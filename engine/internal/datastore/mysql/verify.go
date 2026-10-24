package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/antifailure/antifailure/engine/internal/secrets"
	"github.com/antifailure/antifailure/engine/internal/verify"
)

// The verification half: the same scanner and the same detectors, reading a
// MySQL. internal/verify carries the dialect, and this supplies the
// connection.

// ScanOptions configure a scan.
type ScanOptions struct {
	// SampleSize is rows per column, and zero uses the scanner's default.
	SampleSize int
	// Unruled names the columns masking copied unchanged because no rule
	// covered them.
	Unruled []string
	// Progress receives a line per table, and may be nil.
	Progress func(string)
	// Now is the time source.
	Now func() time.Time
}

// Scan reads a MySQL database back and reports what still looks real.
//
// Scoped to the database the URL names, for the reason the ClickHouse scan is:
// the server also holds other goldens and other environments' branches, and
// the dialect's own listing covers every database on it.
func Scan(ctx context.Context, url secrets.Value, opts ScanOptions) (verify.Report, error) {
	s, err := parseURL(url)
	if err != nil {
		return verify.Report{}, err
	}
	if s.database == "" {
		return verify.Report{}, fmt.Errorf("datastore.mysql: the address names no database to scan")
	}
	db, err := s.open(sessionPlain)
	if err != nil {
		return verify.Report{}, err
	}
	defer func() { _ = db.Close() }()
	return verify.ScanSource(ctx, source(db), verify.Options{
		SampleSize: opts.SampleSize,
		Unruled:    opts.Unruled,
		Progress:   opts.Progress,
		Now:        opts.Now,
	})
}

// source pairs the scoped dialect with a pool.
func source(db *sql.DB) verify.Source {
	return verify.NewSource(scopedDialect{verify.MySQL},
		func(ctx context.Context, query string, yield func(verify.Row) error) error {
			rows, err := db.QueryContext(ctx, query)
			if err != nil {
				return err
			}
			defer func() { _ = rows.Close() }()
			cols, err := rows.Columns()
			if err != nil {
				return err
			}
			raw := make([]sql.RawBytes, len(cols))
			dest := make([]any, len(cols))
			for i := range raw {
				dest[i] = &raw[i]
			}
			for rows.Next() {
				if err := rows.Scan(dest...); err != nil {
					return err
				}
				// RawBytes is nil for a NULL and the driver's buffer
				// otherwise, which is exactly a Row: valid until yield
				// returns.
				row := make(verify.Row, len(raw))
				for i, v := range raw {
					row[i] = v
				}
				if err := yield(row); err != nil {
					return err
				}
			}
			return rows.Err()
		})
}

// scopedDialect is the MySQL dialect with its column listing limited to the
// session's database. Composed from the dialect's own listing, so which tables
// it reads stays that package's answer.
type scopedDialect struct{ verify.Dialect }

func (scopedDialect) Columns() string {
	return "SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, COLUMN_TYPE FROM (" +
		verify.MySQL.Columns() +
		") AS listed WHERE TABLE_SCHEMA = DATABASE() ORDER BY TABLE_NAME, COLUMN_NAME"
}
