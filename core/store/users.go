package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Role strings. Kept here so handlers don't sprinkle free-form literals.
const (
	RoleSuperAdmin = "superadmin"
	RoleAdmin      = "admin"
	RoleViewer     = "viewer"
)

// Permission strings for domain_access rows.
const (
	PermView   = "view"
	PermManage = "manage"
)

// User is the row shape returned from user queries. pass_hash is never
// included; callers authenticate via VerifyLogin instead.
type User struct {
	ID          int64
	Username    string
	Email       string
	Role        string
	CreatedAt   int64
	LastLoginAt int64
	Disabled    bool
}

// CreateUser inserts a new user with a bcrypt-hashed password. Returns
// ErrDuplicateUser if the username already exists. Bcrypt cost 12 gives
// ~200 ms hashing — acceptable on an infrequent write path and a useful
// floor on password cracking.
func CreateUser(ctx context.Context, username, email, password, role string) (int64, error) {
	if !validRole(role) {
		return 0, ErrBadRole
	}
	if len(password) < 8 {
		return 0, ErrWeakPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return 0, err
	}
	res, err := DB.ExecContext(ctx, `
INSERT INTO users(username, email, pass_hash, role, created_at)
VALUES (?, ?, ?, ?, ?)`,
		username, nullable(email), string(hash), role, time.Now().Unix())
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrDuplicateUser
		}
		return 0, err
	}
	return res.LastInsertId()
}

// VerifyLogin returns the user on successful password match, or ErrBadCreds
// otherwise. Runs bcrypt.Compare even when the username doesn't exist so
// response time doesn't leak account existence.
func VerifyLogin(ctx context.Context, username, password string) (*User, error) {
	var id int64
	var email sql.NullString
	var hash, role string
	var createdAt int64
	var lastLogin, disabledAt sql.NullInt64
	err := DB.QueryRowContext(ctx, `
SELECT id, email, pass_hash, role, created_at, last_login_at, disabled_at
FROM users WHERE username = ?`, username).
		Scan(&id, &email, &hash, &role, &createdAt, &lastLogin, &disabledAt)
	if errors.Is(err, sql.ErrNoRows) {
		// Throwaway bcrypt compare to flatten timing against the real path.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$dummydummydummydummydummydummydummydummydummy0000"), []byte(password))
		return nil, ErrBadCreds
	}
	if err != nil {
		return nil, err
	}
	if disabledAt.Valid {
		return nil, ErrDisabled
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return nil, ErrBadCreds
	}
	_, _ = DB.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, time.Now().Unix(), id)
	u := &User{
		ID:          id,
		Username:    username,
		Email:       email.String,
		Role:        role,
		CreatedAt:   createdAt,
		LastLoginAt: lastLogin.Int64,
	}
	return u, nil
}

// ListUsers returns all users ordered newest-first. For the user management
// page in the dashboard; the current operator count is small (< 100)
// everywhere this runs, so no pagination needed yet.
func ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := DB.QueryContext(ctx, `
SELECT id, username, email, role, created_at, COALESCE(last_login_at, 0), disabled_at
FROM users ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*User
	for rows.Next() {
		u := &User{}
		var email sql.NullString
		var disabled sql.NullInt64
		if err := rows.Scan(&u.ID, &u.Username, &email, &u.Role, &u.CreatedAt, &u.LastLoginAt, &disabled); err != nil {
			return nil, err
		}
		u.Email = email.String
		u.Disabled = disabled.Valid
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateRole changes a user's role. Refuses to demote the last superadmin
// so the operator can't lock themselves out.
func UpdateRole(ctx context.Context, userID int64, role string) error {
	if !validRole(role) {
		return ErrBadRole
	}
	if role != RoleSuperAdmin {
		var current string
		if err := DB.QueryRowContext(ctx, `SELECT role FROM users WHERE id = ?`, userID).Scan(&current); err != nil {
			return err
		}
		if current == RoleSuperAdmin {
			var superCount int
			if err := DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = ? AND disabled_at IS NULL`, RoleSuperAdmin).Scan(&superCount); err != nil {
				return err
			}
			if superCount <= 1 {
				return ErrLastSuperAdmin
			}
		}
	}
	_, err := DB.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, role, userID)
	return err
}

// SetPassword rehashes and stores a new password. Used by admins resetting
// an operator's password and by the self-service change-password flow.
func SetPassword(ctx context.Context, userID int64, newPassword string) error {
	if len(newPassword) < 8 {
		return ErrWeakPassword
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), 12)
	if err != nil {
		return err
	}
	_, err = DB.ExecContext(ctx, `UPDATE users SET pass_hash = ? WHERE id = ?`, string(hash), userID)
	return err
}

// DisableUser flips disabled_at. Sessions are expired in a separate query
// so the user is kicked out immediately.
func DisableUser(ctx context.Context, userID int64) error {
	var role string
	if err := DB.QueryRowContext(ctx, `SELECT role FROM users WHERE id = ?`, userID).Scan(&role); err != nil {
		return err
	}
	if role == RoleSuperAdmin {
		var superCount int
		if err := DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role = ? AND disabled_at IS NULL`, RoleSuperAdmin).Scan(&superCount); err != nil {
			return err
		}
		if superCount <= 1 {
			return ErrLastSuperAdmin
		}
	}
	if _, err := DB.ExecContext(ctx, `UPDATE users SET disabled_at = ? WHERE id = ?`, time.Now().Unix(), userID); err != nil {
		return err
	}
	_, err := DB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

// EnableUser clears disabled_at.
func EnableUser(ctx context.Context, userID int64) error {
	_, err := DB.ExecContext(ctx, `UPDATE users SET disabled_at = NULL WHERE id = ?`, userID)
	return err
}

// DeleteUser hard-deletes. Foreign keys cascade into sessions, domain_access,
// and api_keys. Audit rows keep username but lose user_id (SET NULL).
func DeleteUser(ctx context.Context, userID int64) error {
	_, err := DB.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, userID)
	return err
}

// CountUsers returns the total user count — used at startup to detect an
// empty DB so the bootstrap can seed the initial superadmin.
func CountUsers(ctx context.Context) (int, error) {
	var n int
	err := DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func validRole(r string) bool {
	return r == RoleSuperAdmin || r == RoleAdmin || r == RoleViewer
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isUniqueViolation(err error) bool {
	return err != nil && (containsFold(err.Error(), "UNIQUE constraint") || containsFold(err.Error(), "unique constraint"))
}

func containsFold(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			sc := s[i+j]
			if sc >= 'A' && sc <= 'Z' {
				sc += 32
			}
			bc := sub[j]
			if bc >= 'A' && bc <= 'Z' {
				bc += 32
			}
			if sc != bc {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// Sentinel errors. Handlers map these to HTTP status codes.
var (
	ErrBadRole        = errors.New("store: invalid role")
	ErrWeakPassword   = errors.New("store: password must be at least 8 characters")
	ErrDuplicateUser  = errors.New("store: username already exists")
	ErrBadCreds       = errors.New("store: invalid credentials")
	ErrDisabled       = errors.New("store: user is disabled")
	ErrLastSuperAdmin = errors.New("store: cannot remove the last superadmin")
)
