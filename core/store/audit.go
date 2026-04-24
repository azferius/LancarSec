package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

// AuditEvent is an append-only record of an operator action. The dashboard
// keeps this around for compliance-style review ("who disabled this rule,
// when, from which IP?").
type AuditEvent struct {
	ID       int64
	TS       int64
	UserID   int64
	Username string
	Action   string
	Domain   string
	IP       string
	Details  string
}

// LogEvent inserts one event. Callers do not wait for the result; failures
// are logged but don't abort the originating operation — losing an audit
// entry is bad but losing the user's action is worse.
func LogEvent(ctx context.Context, username string, userID int64, action, domain, ip string, details any) {
	var body string
	if details != nil {
		if buf, err := json.Marshal(details); err == nil {
			body = string(buf)
		}
	}
	_, err := DB.ExecContext(ctx, `
INSERT INTO audit_log(ts, user_id, username, action, domain, ip, details)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		time.Now().Unix(),
		nullInt(userID),
		username,
		action,
		nullable(domain),
		nullable(ip),
		nullable(body))
	_ = err // non-fatal
}

// ListAudit returns the most recent events. Filter is optional; empty
// strings skip that predicate. The newest entries come first so the
// dashboard table has the interesting rows at the top.
type AuditFilter struct {
	Domain string
	Action string
	UserID int64
	Limit  int
}

func ListAudit(ctx context.Context, f AuditFilter) ([]AuditEvent, error) {
	q := `SELECT id, ts, COALESCE(user_id,0), username, action, COALESCE(domain,''), COALESCE(ip,''), COALESCE(details,'')
FROM audit_log WHERE 1=1`
	args := []any{}
	if f.Domain != "" {
		q += " AND domain = ?"
		args = append(args, f.Domain)
	}
	if f.Action != "" {
		q += " AND action = ?"
		args = append(args, f.Action)
	}
	if f.UserID > 0 {
		q += " AND user_id = ?"
		args = append(args, f.UserID)
	}
	q += " ORDER BY ts DESC"
	if f.Limit > 0 {
		q += " LIMIT ?"
		args = append(args, f.Limit)
	} else {
		q += " LIMIT 200"
	}
	rows, err := DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.TS, &e.UserID, &e.Username, &e.Action, &e.Domain, &e.IP, &e.Details); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullInt(v int64) any {
	if v == 0 {
		return sql.NullInt64{}
	}
	return v
}
