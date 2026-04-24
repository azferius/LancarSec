// Package logstore persists request logs into a separate SQLite database.
//
// The dashboard keeps a short in-memory tail for live SSE rendering, but
// analysis/debugging needs history that survives restarts. log.db is kept
// separate from lancarsec.db so high-volume request writes do not contend
// with auth/session/audit writes.
package logstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lancarsec/core/domains"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

const (
	dbPath    = "log.db"
	queueCap  = 32768
	batchSize = 256
)

var (
	DB      *sql.DB
	openMu  sync.Mutex
	openErr error

	queue  chan RequestLog
	stopCh chan struct{}
	doneCh chan struct{}
	closed atomic.Bool
)

// RequestLog is the durable shape stored in log.db.
type RequestLog struct {
	ID          int64  `json:"id,omitempty"`
	TS          int64  `json:"ts"`
	Domain      string `json:"domain"`
	Time        string `json:"time"`
	IP          string `json:"ip"`
	Country     string `json:"country"`
	Engine      string `json:"engine"`
	Bot         string `json:"bot"`
	Fingerprint string `json:"fingerprint"`
	JA3         string `json:"ja3"`
	JA4         string `json:"ja4"`
	JA4R        string `json:"ja4_r"`
	JA4O        string `json:"ja4_o"`
	JA4H        string `json:"ja4h"`
	UserAgent   string `json:"user_agent"`
	Method      string `json:"method"`
	Path        string `json:"path"`
	Protocol    string `json:"protocol"`
	Status      int    `json:"status"`
	Size        int    `json:"size"`
}

// Filter controls durable request log queries. Domain and Domains are
// mutually exclusive; Domains is used for the global dashboard view after RBAC
// already narrowed the allowed domain list.
type Filter struct {
	Domain  string
	Domains []string
	Search  string
	Limit   int
}

// Open initializes log.db and starts the single writer goroutine.
func Open() error {
	openMu.Lock()
	defer openMu.Unlock()
	if DB != nil {
		return openErr
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		openErr = fmt.Errorf("open log sqlite: %w", err)
		return openErr
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		openErr = fmt.Errorf("ping log sqlite: %w", err)
		return openErr
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		openErr = fmt.Errorf("migrate log sqlite: %w", err)
		return openErr
	}

	DB = db
	queue = make(chan RequestLog, queueCap)
	stopCh = make(chan struct{})
	doneCh = make(chan struct{})
	closed.Store(false)
	go writer()
	return nil
}

func migrate(db *sql.DB) error {
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS request_logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           INTEGER NOT NULL,
    domain       TEXT NOT NULL,
    time_text    TEXT,
    ip           TEXT,
    country      TEXT,
    engine       TEXT,
    bot          TEXT,
    fingerprint  TEXT,
    ja3          TEXT,
    ja4          TEXT,
    ja4_r        TEXT,
    ja4_o        TEXT,
    ja4h         TEXT,
    user_agent   TEXT,
    method       TEXT,
    path         TEXT,
    protocol     TEXT,
    status       INTEGER,
    size         INTEGER
);
CREATE INDEX IF NOT EXISTS idx_request_logs_ts        ON request_logs(ts DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_domain_ts ON request_logs(domain, ts DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_ip_ts     ON request_logs(ip, ts DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_status_ts ON request_logs(status, ts DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_path      ON request_logs(path);
`); err != nil {
		return err
	}
	for _, stmt := range []string{
		"ALTER TABLE request_logs ADD COLUMN ja3 TEXT",
		"ALTER TABLE request_logs ADD COLUMN ja4 TEXT",
		"ALTER TABLE request_logs ADD COLUMN ja4_r TEXT",
		"ALTER TABLE request_logs ADD COLUMN ja4_o TEXT",
		"ALTER TABLE request_logs ADD COLUMN ja4h TEXT",
	} {
		if _, err := db.Exec(stmt); err != nil && !strings.Contains(strings.ToLower(err.Error()), "duplicate column") {
			return err
		}
	}
	return nil
}

// Close drains queued writes and closes log.db.
func Close() error {
	openMu.Lock()
	if DB == nil {
		openMu.Unlock()
		return nil
	}
	if closed.CompareAndSwap(false, true) {
		close(stopCh)
		done := doneCh
		openMu.Unlock()
		<-done
		openMu.Lock()
	}
	err := DB.Close()
	DB = nil
	openMu.Unlock()
	return err
}

// Append persists a request log. It blocks only when the queue is saturated;
// that is intentional backpressure so logs are not silently dropped.
func Append(domain string, entry domains.DomainLog) error {
	if err := Open(); err != nil {
		return err
	}
	if closed.Load() {
		return errors.New("logstore closed")
	}
	rec := RequestLog{
		TS:          time.Now().UnixMilli(),
		Domain:      domain,
		Time:        entry.Time,
		IP:          entry.IP,
		Country:     entry.Country,
		Engine:      entry.BrowserFP,
		Bot:         entry.BotFP,
		Fingerprint: entry.TLSFP,
		JA3:         entry.JA3,
		JA4:         entry.JA4,
		JA4R:        entry.JA4R,
		JA4O:        entry.JA4O,
		JA4H:        entry.JA4H,
		UserAgent:   entry.Useragent,
		Method:      entry.Method,
		Path:        entry.Path,
		Protocol:    entry.Protocol,
		Status:      entry.Status,
		Size:        entry.Size,
	}
	queue <- rec
	return nil
}

func writer() {
	defer close(doneCh)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	batch := make([]RequestLog, 0, batchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		_ = insertBatch(context.Background(), batch)
		batch = batch[:0]
	}

	for {
		select {
		case rec := <-queue:
			batch = append(batch, rec)
			if len(batch) >= batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-stopCh:
			for {
				select {
				case rec := <-queue:
					batch = append(batch, rec)
					if len(batch) >= batchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

func insertBatch(ctx context.Context, rows []RequestLog) error {
	tx, err := DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `
INSERT INTO request_logs(ts, domain, time_text, ip, country, engine, bot, fingerprint, ja3, ja4, ja4_r, ja4_o, ja4h, user_agent, method, path, protocol, status, size)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.ExecContext(ctx,
			r.TS, r.Domain, nullable(r.Time), nullable(r.IP), nullable(r.Country),
			nullable(r.Engine), nullable(r.Bot), nullable(r.Fingerprint),
			nullable(r.JA3), nullable(r.JA4), nullable(r.JA4R), nullable(r.JA4O),
			nullable(r.JA4H), nullable(r.UserAgent), nullable(r.Method), nullable(r.Path),
			nullable(r.Protocol), r.Status, r.Size,
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// List returns newest logs first.
func List(ctx context.Context, f Filter) ([]RequestLog, error) {
	if err := Open(); err != nil {
		return nil, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 5000 {
		limit = 5000
	}

	q := `SELECT id, ts, domain, COALESCE(time_text,''), COALESCE(ip,''), COALESCE(country,''),
COALESCE(engine,''), COALESCE(bot,''), COALESCE(fingerprint,''), COALESCE(ja3,''), COALESCE(ja4,''), COALESCE(ja4_r,''), COALESCE(ja4_o,''), COALESCE(ja4h,''), COALESCE(user_agent,''),
COALESCE(method,''), COALESCE(path,''), COALESCE(protocol,''), COALESCE(status,0), COALESCE(size,0)
FROM request_logs WHERE 1=1`
	args := []any{}
	if f.Domain != "" {
		q += " AND domain = ?"
		args = append(args, f.Domain)
	}
	if len(f.Domains) > 0 {
		placeholders := make([]string, len(f.Domains))
		for i, d := range f.Domains {
			placeholders[i] = "?"
			args = append(args, d)
		}
		q += " AND domain IN (" + strings.Join(placeholders, ",") + ")"
	}
	if s := strings.TrimSpace(f.Search); s != "" {
		like := "%" + s + "%"
		q += ` AND (domain LIKE ? OR ip LIKE ? OR country LIKE ? OR engine LIKE ? OR bot LIKE ? OR fingerprint LIKE ? OR ja3 LIKE ? OR ja4 LIKE ? OR ja4_r LIKE ? OR ja4_o LIKE ? OR ja4h LIKE ? OR user_agent LIKE ? OR method LIKE ? OR path LIKE ? OR protocol LIKE ? OR CAST(status AS TEXT) LIKE ?)`
		for range 16 {
			args = append(args, like)
		}
	}
	q += " ORDER BY ts DESC LIMIT ?"
	args = append(args, limit)

	rows, err := DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []RequestLog{}
	for rows.Next() {
		var r RequestLog
		if err := rows.Scan(&r.ID, &r.TS, &r.Domain, &r.Time, &r.IP, &r.Country, &r.Engine, &r.Bot, &r.Fingerprint, &r.JA3, &r.JA4, &r.JA4R, &r.JA4O, &r.JA4H, &r.UserAgent, &r.Method, &r.Path, &r.Protocol, &r.Status, &r.Size); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func nullable(s string) any {
	if s == "" {
		return sql.NullString{}
	}
	return s
}
