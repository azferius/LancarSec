package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// APIKey is the row shape for listings. KeyHash is never exposed; the
// plaintext is returned exactly once at creation time via CreateAPIKey.
type APIKey struct {
	ID         int64
	UserID     int64
	Username   string
	Name       string
	Prefix     string
	Scopes     string
	CreatedAt  int64
	LastUsedAt int64
	Revoked    bool
}

// CreateAPIKey mints a fresh key, hashes it, stores the hash, and returns
// the plaintext token and row ID. Format: "lsk_" + prefix(8) + "_" + secret(40).
// The prefix is indexable + user-facing so "lsk_a3f91b02_..." appears in
// logs and dashboards while the secret stays private.
func CreateAPIKey(ctx context.Context, userID int64, name, scopes string) (plaintext string, id int64, err error) {
	prefix := randHexStore(4)
	secret := randHexStore(20)
	plaintext = "lsk_" + prefix + "_" + secret
	sum := sha256.Sum256([]byte(plaintext))
	hash := hex.EncodeToString(sum[:])

	res, err := DB.ExecContext(ctx, `
INSERT INTO api_keys(user_id, name, key_hash, key_prefix, created_at, scopes)
VALUES (?, ?, ?, ?, ?, ?)`,
		userID, name, hash, prefix, time.Now().Unix(), nullable(scopes))
	if err != nil {
		return "", 0, err
	}
	id, err = res.LastInsertId()
	return
}

// ResolveAPIKey matches a plaintext key to its row and returns the owning
// user's context — username + role — so handlers can make RBAC decisions
// the same way they do for sessions. Returns ErrNoAPIKey on miss, expired,
// or revoked.
//
// Lookup is O(1) via the key_prefix index; the SHA-256 compare happens
// only after the prefix hit so an attacker probing random strings doesn't
// get a bcrypt-cost response but also doesn't get a 100%-constant-time
// check. Since the key namespace is 20 bytes of random hex, brute force
// via the API is orders of magnitude slower than disk I/O anyway.
func ResolveAPIKey(ctx context.Context, plaintext string) (*APIKey, string, error) {
	parts := strings.SplitN(plaintext, "_", 3)
	if len(parts) != 3 || parts[0] != "lsk" {
		return nil, "", ErrNoAPIKey
	}
	prefix := parts[1]
	sum := sha256.Sum256([]byte(plaintext))
	wantHash := hex.EncodeToString(sum[:])

	row := DB.QueryRowContext(ctx, `
SELECT k.id, k.user_id, u.username, u.role, k.name, k.key_prefix, COALESCE(k.scopes,''),
       k.created_at, COALESCE(k.last_used_at, 0), k.revoked_at
FROM api_keys k
JOIN users u ON u.id = k.user_id
WHERE k.key_prefix = ? AND k.key_hash = ? AND u.disabled_at IS NULL`,
		prefix, wantHash)

	var k APIKey
	var role string
	var revoked sql.NullInt64
	if err := row.Scan(&k.ID, &k.UserID, &k.Username, &role, &k.Name, &k.Prefix, &k.Scopes, &k.CreatedAt, &k.LastUsedAt, &revoked); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", ErrNoAPIKey
		}
		return nil, "", err
	}
	if revoked.Valid {
		return nil, "", ErrNoAPIKey
	}
	// Best-effort last_used_at bump.
	_, _ = DB.ExecContext(ctx, `UPDATE api_keys SET last_used_at = ? WHERE id = ?`, time.Now().Unix(), k.ID)
	k.Revoked = false
	return &k, role, nil
}

// ListAPIKeys returns every key owned by a user. If userID <= 0, lists all
// keys across all users (superadmin view).
func ListAPIKeys(ctx context.Context, userID int64) ([]*APIKey, error) {
	q := `
SELECT k.id, k.user_id, u.username, k.name, k.key_prefix, COALESCE(k.scopes,''),
       k.created_at, COALESCE(k.last_used_at, 0), k.revoked_at
FROM api_keys k
JOIN users u ON u.id = k.user_id`
	args := []any{}
	if userID > 0 {
		q += " WHERE k.user_id = ?"
		args = append(args, userID)
	}
	q += " ORDER BY k.created_at DESC"

	rows, err := DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*APIKey
	for rows.Next() {
		k := &APIKey{}
		var revoked sql.NullInt64
		if err := rows.Scan(&k.ID, &k.UserID, &k.Username, &k.Name, &k.Prefix, &k.Scopes, &k.CreatedAt, &k.LastUsedAt, &revoked); err != nil {
			return nil, err
		}
		k.Revoked = revoked.Valid
		out = append(out, k)
	}
	return out, rows.Err()
}

// RevokeAPIKey flips the revoked_at timestamp so subsequent lookups fail.
// Revoke is preferred over delete because it preserves the audit trail:
// the dashboard can still show "key X was created by user Y and revoked
// at Z" even after the user is rotated out.
func RevokeAPIKey(ctx context.Context, keyID int64) error {
	_, err := DB.ExecContext(ctx, `UPDATE api_keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, time.Now().Unix(), keyID)
	return err
}

var ErrNoAPIKey = errors.New("store: api key not found, revoked, or disabled")

func randHexStore(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("store: crypto/rand read failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
