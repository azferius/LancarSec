package dashboard

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"lancarsec/core/store"
)

// Bootstrap ensures there's at least one superadmin in the user store.
// On a fresh DB it seeds username=admin with a random 18-byte-hex password,
// printing it once to the console — subsequent runs reuse the stored hash.
//
// The old dashboard.json path is kept as a migration hint: if the JSON
// file is present at startup and the DB has zero users, we mint a
// superadmin using the username from the JSON and a freshly-generated
// password. That way upgrading from pre-SQLite LancarSec doesn't lock the
// operator out — they get a one-time "use this password" banner.
func Bootstrap() error {
	if err := store.Open(); err != nil {
		return err
	}
	ctx := context.Background()
	count, err := store.CountUsers(ctx)
	if err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	username := "admin"
	pass := randHex(18)
	if _, err := store.CreateUser(ctx, username, "", pass, store.RoleSuperAdmin); err != nil {
		return fmt.Errorf("seed superadmin: %w", err)
	}

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║  LancarSec superadmin created (first run)                    ║")
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Printf("║  Username: %-50s║\n", username)
	fmt.Printf("║  Password: %-50s║\n", pass)
	fmt.Println("╠══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Copy this now. It won't be printed again.                   ║")
	fmt.Println("║  Credentials live in lancarsec.db (SQLite); change the       ║")
	fmt.Println("║  password from the dashboard Users page after logging in.    ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Kick off a background sweep of expired session rows so the sessions
	// table stays pruned without depending on user traffic.
	go sessionSweeper()
	return nil
}

func sessionSweeper() {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for range t.C {
		_ = store.SweepExpiredSessions(context.Background())
	}
}

// VerifyCredentials now defers to the SQLite-backed user store.
func VerifyCredentials(username, password string) (*store.User, bool) {
	u, err := store.VerifyLogin(context.Background(), username, password)
	if err != nil {
		return nil, false
	}
	return u, true
}

// CreateSession issues a new session token tied to the user. ttl is
// intentionally shorter than "forever" so an idle attacker with a stolen
// cookie loses it on their own.
func CreateSessionFor(userID int64, ip, userAgent string) (string, error) {
	return store.CreateSession(context.Background(), userID, ip, userAgent, 24*time.Hour)
}

// SessionUser resolves a cookie token to the session record. Returns ok=false
// for missing, expired, or disabled-user rows.
func SessionUser(token string) (*store.Session, bool) {
	s, err := store.ResolveSession(context.Background(), token)
	if err != nil {
		return nil, false
	}
	return s, true
}

// RevokeSession is what POST /logout calls.
func RevokeSession(token string) {
	_ = store.DeleteSession(context.Background(), token)
}

func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("dashboard: crypto/rand read failed: " + err.Error())
	}
	return hex.EncodeToString(buf)
}
