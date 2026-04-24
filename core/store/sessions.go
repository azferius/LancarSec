package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// Session is the row returned from session lookups. It carries the denormalized
// user info that handlers need so an authenticated request doesn't require a
// second query.
type Session struct {
	Token     string
	UserID    int64
	Username  string
	Role      string
	ExpiresAt int64
}

// CreateSession issues an opaque token (32 random bytes, hex-encoded) and
// persists it. The caller sets it as an HttpOnly cookie.
func CreateSession(ctx context.Context, userID int64, ip, userAgent string, ttl time.Duration) (string, error) {
	tok, err := newToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	_, err = DB.ExecContext(ctx, `
INSERT INTO sessions(token, user_id, created_at, expires_at, ip, user_agent)
VALUES (?, ?, ?, ?, ?, ?)`,
		tok, userID, now.Unix(), now.Add(ttl).Unix(), nullable(ip), nullable(userAgent))
	if err != nil {
		return "", err
	}
	return tok, nil
}

// ResolveSession returns the session + user role for a token. Expired or
// disabled-user sessions return ErrNoSession so the caller redirects to
// login uniformly. Stale rows are GC'd lazily here to avoid a second
// goroutine loop.
func ResolveSession(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, ErrNoSession
	}
	row := DB.QueryRowContext(ctx, `
SELECT s.token, s.user_id, u.username, u.role, s.expires_at
FROM sessions s
JOIN users u ON u.id = s.user_id
WHERE s.token = ? AND u.disabled_at IS NULL`, token)
	var s Session
	if err := row.Scan(&s.Token, &s.UserID, &s.Username, &s.Role, &s.ExpiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoSession
		}
		return nil, err
	}
	if time.Now().Unix() > s.ExpiresAt {
		// Lazy GC of the expired row so the sessions table stays pruned
		// even if the sweep goroutine is lagging.
		_, _ = DB.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
		return nil, ErrNoSession
	}
	return &s, nil
}

// DeleteSession is the logout side: revoke a single token.
func DeleteSession(ctx context.Context, token string) error {
	_, err := DB.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
	return err
}

// SweepExpiredSessions removes rows past their expires_at. Called on a
// timer from the dashboard server so the table doesn't grow indefinitely.
func SweepExpiredSessions(ctx context.Context) error {
	_, err := DB.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now().Unix())
	return err
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var ErrNoSession = errors.New("store: session not found or expired")
