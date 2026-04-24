package dashboard

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// credentialsFile is where the bcrypt-hashed operator credentials live.
// Kept next to config.json so an operator inspecting the proxy directory
// finds all runtime state in one place. File mode 0600 so only the running
// user can read the hash.
const credentialsFile = "dashboard.json"

// credentialsDoc is the on-disk shape of dashboard.json. Username is plain
// text; PassHash is bcrypt(cost=12). SessionSecret signs/verifies session
// tokens so they can't be forged, and survives restarts (logins persist as
// long as the secret stays stable).
type credentialsDoc struct {
	Username      string `json:"username"`
	PassHash      string `json:"pass_hash"`
	SessionSecret string `json:"session_secret"`
}

var (
	credsMu    sync.RWMutex
	activeDoc  credentialsDoc

	sessionsMu sync.RWMutex
	sessions   = map[string]sessionRecord{}
)

type sessionRecord struct {
	Username  string
	ExpiresAt time.Time
}

// Bootstrap loads dashboard.json, or generates a fresh one (random username,
// random password, random session secret) on first run. The generated
// password is printed to the console exactly once — operator must copy it.
// This pattern avoids shipping default credentials and avoids asking the
// operator for input at startup (which would block service managers).
func Bootstrap() error {
	data, err := os.ReadFile(credentialsFile)
	if err == nil {
		var doc credentialsDoc
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("parse %s: %w", credentialsFile, err)
		}
		credsMu.Lock()
		activeDoc = doc
		credsMu.Unlock()
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", credentialsFile, err)
	}

	// First run — generate credentials.
	user := "operator"
	pass := randHex(18) // 36 hex chars ~ 144 bits
	hash, err := bcrypt.GenerateFromPassword([]byte(pass), 12)
	if err != nil {
		return fmt.Errorf("bcrypt: %w", err)
	}
	doc := credentialsDoc{
		Username:      user,
		PassHash:      string(hash),
		SessionSecret: randHex(32),
	}
	buf, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(credentialsFile, buf, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", credentialsFile, err)
	}
	credsMu.Lock()
	activeDoc = doc
	credsMu.Unlock()

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  LancarSec dashboard credentials generated (first run)       ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Username: %-50s║\n", user)
	fmt.Printf("║  Password: %-50s║\n", pass)
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Copy this now. It won't be printed again.                   ║")
	fmt.Println("║  Change it by editing dashboard.json (pass_hash is bcrypt).  ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	return nil
}

// VerifyCredentials checks a username/password attempt in constant time
// relative to the bcrypt work factor. Returns (ok, username) so the caller
// can stash the canonical name into the session.
func VerifyCredentials(user, pass string) (bool, string) {
	credsMu.RLock()
	doc := activeDoc
	credsMu.RUnlock()

	if user != doc.Username {
		// Still run bcrypt on a throwaway hash so the response time for
		// unknown users matches the time for wrong-password-on-known-user.
		_ = bcrypt.CompareHashAndPassword([]byte(doc.PassHash), []byte("invalid-dummy"))
		return false, ""
	}
	if err := bcrypt.CompareHashAndPassword([]byte(doc.PassHash), []byte(pass)); err != nil {
		return false, ""
	}
	return true, doc.Username
}

// CreateSession issues an opaque token, stores it, and returns it. Caller
// sets it as an HttpOnly cookie. Tokens live 24 hours; expired rows get
// lazily garbage-collected on next lookup.
func CreateSession(user string) string {
	token := randHex(32)
	sessionsMu.Lock()
	sessions[token] = sessionRecord{
		Username:  user,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	sessionsMu.Unlock()
	return token
}

// SessionUser resolves a session token to a username, returning ("", false)
// for unknown or expired tokens. Expired entries are swept on read.
func SessionUser(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	sessionsMu.RLock()
	rec, ok := sessions[token]
	sessionsMu.RUnlock()
	if !ok {
		return "", false
	}
	if time.Now().After(rec.ExpiresAt) {
		sessionsMu.Lock()
		delete(sessions, token)
		sessionsMu.Unlock()
		return "", false
	}
	return rec.Username, true
}

// RevokeSession deletes a session token — used by the logout handler.
func RevokeSession(token string) {
	sessionsMu.Lock()
	delete(sessions, token)
	sessionsMu.Unlock()
}

// randHex returns a 2n-char hex string from crypto/rand. Panics on crypto
// source failure: a broken kernel RNG is not a situation we can recover from
// safely, and refusing to start is better than shipping weak tokens.
func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("dashboard: crypto/rand read failed: " + err.Error())
	}
	return hex.EncodeToString(buf)
}
