// Package buffer persists collector events in a local SQLite database.
// Events are auto-purged after buffer_retention_hours (default 24h).
// The Store is the primary data source for the MCP server's query tools.
package buffer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/voltagebots/vigilo/internal/collector"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS events (
	id        INTEGER PRIMARY KEY AUTOINCREMENT,
	source    TEXT    NOT NULL,
	timestamp TEXT    NOT NULL,
	pid       INTEGER,
	ppid      INTEGER,
	process   TEXT,
	cmd_line  TEXT,
	user_id   TEXT,
	action    TEXT    NOT NULL,
	resource  TEXT    NOT NULL,
	detail    TEXT,
	severity  TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source    ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_severity  ON events(severity);
`

// Store persists events in SQLite and serves queries from the MCP server.
type Store struct {
	db              *sql.DB
	retentionHours  int
}

func Open(path string, retentionHours int) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	s := &Store{db: db, retentionHours: retentionHours}
	go s.pruneLoop()
	return s, nil
}

func (s *Store) Insert(e collector.Event) error {
	_, err := s.db.Exec(`
		INSERT INTO events (source,timestamp,pid,ppid,process,cmd_line,user_id,action,resource,detail,severity)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		string(e.Source), e.Timestamp.UTC().Format(time.RFC3339Nano),
		e.PID, e.PPID, e.Process, e.CmdLine, e.User,
		e.Action, e.Resource, e.Detail, string(e.Severity),
	)
	return err
}

// QueryOptions controls filtering in List.
type QueryOptions struct {
	Since    time.Time
	Sources  []string
	Severity string // minimum severity: info|medium|high|critical
	Limit    int
}

var severityRank = map[string]int{
	"info": 0, "medium": 1, "high": 2, "critical": 3,
}

func (s *Store) List(opts QueryOptions) ([]collector.Event, error) {
	query := `SELECT id,source,timestamp,pid,ppid,process,cmd_line,user_id,action,resource,detail,severity
	          FROM events WHERE timestamp >= ?`
	args := []any{opts.Since.UTC().Format(time.RFC3339Nano)}

	if len(opts.Sources) > 0 {
		placeholders := ""
		for i, src := range opts.Sources {
			if i > 0 {
				placeholders += ","
			}
			placeholders += "?"
			args = append(args, src)
		}
		query += " AND source IN (" + placeholders + ")"
	}

	if opts.Severity != "" {
		rank := severityRank[opts.Severity]
		query += " AND ("
		first := true
		for sev, r := range severityRank {
			if r >= rank {
				if !first {
					query += " OR "
				}
				query += "severity=?"
				args = append(args, sev)
				first = false
			}
		}
		query += ")"
	}

	query += " ORDER BY timestamp DESC"
	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT %d", opts.Limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []collector.Event
	for rows.Next() {
		var e collector.Event
		var tsStr, source, severity string
		if err := rows.Scan(
			&e.ID, &source, &tsStr,
			&e.PID, &e.PPID, &e.Process, &e.CmdLine, &e.User,
			&e.Action, &e.Resource, &e.Detail, &severity,
		); err != nil {
			return nil, err
		}
		e.Source = collector.EventSource(source)
		e.Severity = collector.Severity(severity)
		e.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
		events = append(events, e)
	}
	return events, rows.Err()
}

func (s *Store) ToJSON(events []collector.Event) (string, error) {
	b, err := json.Marshal(events)
	return string(b), err
}

func (s *Store) pruneLoop() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-time.Duration(s.retentionHours) * time.Hour)
		_, _ = s.db.Exec(
			"DELETE FROM events WHERE timestamp < ?",
			cutoff.UTC().Format(time.RFC3339Nano),
		)
	}
}
