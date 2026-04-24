package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// DomainGrant represents one (user, domain) access row.
type DomainGrant struct {
	Domain     string
	Permission string
	GrantedAt  int64
	GrantedBy  int64
}

// GrantDomain creates or overwrites a user's access to a domain. Perm must
// be PermView or PermManage.
func GrantDomain(ctx context.Context, userID int64, domain, permission string, grantedBy int64) error {
	if permission != PermView && permission != PermManage {
		return ErrBadPerm
	}
	_, err := DB.ExecContext(ctx, `
INSERT INTO domain_access(user_id, domain, permission, granted_at, granted_by)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT(user_id, domain) DO UPDATE SET
    permission = excluded.permission,
    granted_at = excluded.granted_at,
    granted_by = excluded.granted_by`,
		userID, domain, permission, time.Now().Unix(), grantedBy)
	return err
}

// RevokeDomain deletes the access row.
func RevokeDomain(ctx context.Context, userID int64, domain string) error {
	_, err := DB.ExecContext(ctx, `DELETE FROM domain_access WHERE user_id = ? AND domain = ?`, userID, domain)
	return err
}

// ListGrants returns every domain a user has access to. Superadmins bypass
// this list — handlers check role first.
func ListGrants(ctx context.Context, userID int64) ([]DomainGrant, error) {
	rows, err := DB.QueryContext(ctx, `
SELECT domain, permission, granted_at, COALESCE(granted_by, 0)
FROM domain_access WHERE user_id = ?
ORDER BY domain`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DomainGrant
	for rows.Next() {
		var g DomainGrant
		if err := rows.Scan(&g.Domain, &g.Permission, &g.GrantedAt, &g.GrantedBy); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// HasAccess reports whether a user can perform the given action on a domain.
// Superadmins always pass. Viewers pass "view"; managers pass both.
// action is "view" or "manage". Missing row = no access.
func HasAccess(ctx context.Context, role string, userID int64, domain, action string) (bool, error) {
	if role == RoleSuperAdmin {
		return true, nil
	}
	var perm string
	err := DB.QueryRowContext(ctx,
		`SELECT permission FROM domain_access WHERE user_id = ? AND domain = ?`,
		userID, domain).Scan(&perm)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	switch action {
	case PermView:
		return perm == PermView || perm == PermManage, nil
	case PermManage:
		return perm == PermManage, nil
	}
	return false, nil
}

// AccessibleDomains returns every domain the user can at least view. Used
// by the dashboard sidebar to filter the domain list. Superadmins get the
// full list (caller passes it in).
func AccessibleDomains(ctx context.Context, role string, userID int64, all []string) ([]string, error) {
	if role == RoleSuperAdmin {
		return all, nil
	}
	rows, err := DB.QueryContext(ctx,
		`SELECT domain FROM domain_access WHERE user_id = ? ORDER BY domain`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	allowed := map[string]struct{}{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		allowed[d] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(allowed))
	for _, d := range all {
		if _, ok := allowed[d]; ok {
			out = append(out, d)
		}
	}
	return out, nil
}

var ErrBadPerm = errors.New("store: permission must be view or manage")
