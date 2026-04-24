// Package store owns the SQLite-backed runtime state: operator users,
// dashboard sessions, per-user domain ACLs, API keys, and the audit log.
//
// Why not config.json for these?
//   * Users/sessions mutate atomically and need row-level writes.
//   * Sessions must survive restart; we can't stash them in a JSON file.
//   * Audit events are append-only with query patterns (by user, by time,
//     by action) that flat files don't serve well at scale.
//   * ACL lookups happen on every dashboard request — a prepared statement
//     beats scanning a slice.
//
// Why not cgo?
//   * modernc.org/sqlite is a pure-Go reimplementation. Keeps LancarSec a
//     single statically-linked binary, no glibc coupling, cross-compile
//     friendly.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// DB is the package-level handle. Open is called once from main; the rest
// of the codebase uses the typed helpers in this package, not the *sql.DB
// directly, so query strings stay in one file.
var DB *sql.DB

// dbPath is resolved at Open time. Dashboard + config files live next to it.
const dbPath = "lancarsec.db"

// Open initializes the SQLite file (creating it if missing) and runs
// migrations up to the latest schema version. Subsequent calls are a no-op.
func Open() error {
	if DB != nil {
		return nil
	}
	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	// SQLite under WAL handles concurrent readers well, but writes are
	// serialized. We cap the pool small; writers queue in the driver.
	db.SetMaxOpenConns(8)
	db.SetMaxIdleConns(4)
	db.SetConnMaxLifetime(30 * time.Minute)

	if err := db.Ping(); err != nil {
		return fmt.Errorf("ping sqlite: %w", err)
	}
	DB = db
	if err := migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	return nil
}

// Close gracefully flushes. main defers this during shutdown.
func Close() error {
	if DB == nil {
		return nil
	}
	return DB.Close()
}

// migrate advances the schema to the latest version. Each step is
// idempotent on success; a failed step leaves the DB at its prior
// version so startup can retry after the operator fixes the issue.
func migrate(ctx context.Context) error {
	// schema_migrations table tracks applied versions so we don't replay.
	if _, err := DB.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
)`); err != nil {
		return err
	}

	for _, step := range migrations {
		var present int
		if err := DB.QueryRowContext(ctx, "SELECT 1 FROM schema_migrations WHERE version = ?", step.version).Scan(&present); err == nil {
			continue // already applied
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		tx, err := DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, step.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migration %d: %w", step.version, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)", step.version, time.Now().Unix()); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

type migration struct {
	version int
	sql     string
}

// Migrations are append-only — never rewrite an older step because every
// operator's DB has already applied it. Add new numbered steps at the end.
var migrations = []migration{
	{version: 1, sql: `
-- Operators who can log into the dashboard.
CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    email         TEXT,
    pass_hash     TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('superadmin','admin','viewer')),
    created_at    INTEGER NOT NULL,
    last_login_at INTEGER,
    disabled_at   INTEGER
);
CREATE INDEX idx_users_role ON users(role);

-- Dashboard sessions. Survives restart so operators stay signed in.
CREATE TABLE sessions (
    token         TEXT PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    ip            TEXT,
    user_agent    TEXT
);
CREATE INDEX idx_sessions_user   ON sessions(user_id);
CREATE INDEX idx_sessions_expiry ON sessions(expires_at);

-- Per-user / per-domain access grant. Missing row = no access (unless the
-- user is superadmin, which implicitly sees everything).
CREATE TABLE domain_access (
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain      TEXT NOT NULL,
    permission  TEXT NOT NULL CHECK (permission IN ('view','manage')),
    granted_at  INTEGER NOT NULL,
    granted_by  INTEGER REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, domain)
);
CREATE INDEX idx_access_domain ON domain_access(domain);

-- Append-only audit log. Writes are cheap; queries are typically windowed
-- (last N, by user, by domain).
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         INTEGER NOT NULL,
    user_id    INTEGER REFERENCES users(id) ON DELETE SET NULL,
    username   TEXT NOT NULL,
    action     TEXT NOT NULL,
    domain     TEXT,
    ip         TEXT,
    details    TEXT
);
CREATE INDEX idx_audit_ts      ON audit_log(ts DESC);
CREATE INDEX idx_audit_user    ON audit_log(user_id);
CREATE INDEX idx_audit_domain  ON audit_log(domain);
CREATE INDEX idx_audit_action  ON audit_log(action);

-- API keys for programmatic access. Hashed; the plaintext is shown once on
-- creation and can't be retrieved.
CREATE TABLE api_keys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    key_hash      TEXT NOT NULL,
    key_prefix    TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER,
    revoked_at    INTEGER,
    scopes        TEXT
);
CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_pref ON api_keys(key_prefix);
`},
}
