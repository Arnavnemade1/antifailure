package mysql

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	driver "github.com/go-sql-driver/mysql"

	"github.com/antifailure/antifailure/engine/internal/secrets"
)

// How this package reaches a server.
//
// A store's address is a URL, mysql://user:password@host:port/database, because
// that is what every other address in a manifest is and what the runtime knows
// how to point at a container on an environment's network. The driver wants a
// DSN of its own shape, so the URL is parsed here and never handed to it as
// text: a password holding an @ or a / is percent encoded in a URL and would
// end the user part early in a DSN.

// defaultPort is MySQL's own.
const defaultPort = "3306"

// server is one MySQL address, with or without a database.
type server struct {
	user     string
	password string
	addr     string
	database string
	// tls is the driver's tls setting: "preferred" unless the URL says
	// otherwise. See parseURL.
	tls string
}

// parseURL reads a mysql:// address.
//
// tls is taken from the query and nothing else is. Preferred is the default,
// which uses TLS whenever the server offers it and does not verify the
// certificate: a production MySQL is usually reached over a network somebody
// else runs, a server with no certificate must still be readable, and
// tls=true is there for whoever wants verification and has a certificate a
// verifier would accept.
func parseURL(v secrets.Value) (*server, error) {
	raw := strings.TrimSpace(v.Reveal())
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "mysql" || u.Host == "" {
		// The value is a credential, so it is not quoted back.
		return nil, fmt.Errorf(
			"datastore.mysql: the address is not a mysql://user:password@host:port/database URL")
	}
	s := &server{tls: "preferred"}
	if u.User != nil {
		s.user = u.User.Username()
		s.password, _ = u.User.Password()
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host, port = u.Host, defaultPort
	}
	s.addr = net.JoinHostPort(host, port)
	s.database = strings.TrimPrefix(u.Path, "/")
	if strings.Contains(s.database, "/") {
		return nil, fmt.Errorf(
			"datastore.mysql: the address names %q as its database, and a MySQL database name "+
				"has no slash in it", s.database)
	}
	switch mode := u.Query().Get("tls"); mode {
	case "":
	case "true", "false", "skip-verify", "preferred":
		s.tls = mode
	default:
		return nil, fmt.Errorf(
			"datastore.mysql: tls=%s is not one of true, false, skip-verify or preferred", mode)
	}
	return s, nil
}

// DatabaseOf returns the database a mysql:// address names, and empty when it
// names none or is not such an address. It is what masking calls the schema.
func DatabaseOf(v secrets.Value) string {
	s, err := parseURL(v)
	if err != nil {
		return ""
	}
	return s.database
}

// in returns the same server with a different database.
func (s *server) in(database string) *server {
	c := *s
	c.database = database
	return &c
}

// url renders the address back as a URL, for a caller that is handed a branch.
func (s *server) url() secrets.Value {
	u := url.URL{
		Scheme: "mysql",
		User:   url.UserPassword(s.user, s.password),
		Host:   s.addr,
		Path:   "/" + s.database,
	}
	if s.tls != "preferred" {
		u.RawQuery = "tls=" + s.tls
	}
	return secrets.New(u.String())
}

// session is what a connection is opened for, and it decides the settings
// every connection in the pool is given.
type session int

const (
	// sessionPlain reads catalogs, scans and pings. Nothing about it differs
	// from the server's defaults except the time zone.
	sessionPlain session = iota
	// sessionCopy moves rows between servers and between databases, byte for
	// byte. See copySettings.
	sessionCopy
	// sessionMask rewrites rows in place. See maskSettings.
	sessionMask
	// sessionDDL creates tables from their definitions, in name order, so a
	// child may be created before its parent. utf8mb4, because a definition is
	// text, and no foreign key checks.
	sessionDDL
)

// open returns a pool for this server and session.
//
// Every connection is given the session's settings by the driver as it is
// made, rather than by a statement after it, because a pool hands out whichever
// connection is free and a setting applied to one connection is a setting the
// next statement may not see.
func (s *server) open(kind session) (*sql.DB, error) {
	cfg := driver.NewConfig()
	cfg.User = s.user
	cfg.Passwd = s.password
	cfg.Net = "tcp"
	cfg.Addr = s.addr
	cfg.DBName = s.database
	cfg.TLSConfig = s.tls
	cfg.Timeout = 10 * time.Second
	cfg.MultiStatements = false
	// The driver logs a dropped connection to stderr on its own, and a
	// server that is still starting drops every one. Those lines reached the
	// terminal of whoever ran af up, ahead of this package's own sentence
	// about the same wait; every failure the driver logs is also returned,
	// and is reported from there.
	cfg.Logger = &driver.NopLogger{}
	cfg.Params = map[string]string{
		// Every session reads and writes instants in UTC. A TIMESTAMP is
		// stored as an instant and rendered through the session's zone, so a
		// copy whose read and write sessions sat in different zones moved
		// every timestamp in the store by the difference.
		"time_zone": "'+00:00'",
	}
	switch kind {
	case sessionCopy:
		if err := copySettings(cfg); err != nil {
			return nil, fmt.Errorf("datastore.mysql: %w", err)
		}
	case sessionMask, sessionDDL:
		maskSettings(cfg)
	}
	connector, err := driver.NewConnector(cfg)
	if err != nil {
		return nil, fmt.Errorf("datastore.mysql: %w", err)
	}
	db := sql.OpenDB(connector)
	db.SetMaxOpenConns(4)
	db.SetConnMaxIdleTime(time.Minute)
	return db, nil
}

// copySettings make a session that moves rows exactly as they are stored.
//
//   - The binary character set, so that every string column is read as the
//     bytes it holds and written back as those bytes into a column of the same
//     definition. A utf8mb4 session would convert a latin1 column on the way
//     out and back on the way in, which is lossless only for what latin1 can
//     spell, and would reject a binary string that is not valid UTF-8.
//   - A permissive sql_mode. A source made under an older or a looser mode can
//     hold a zero date, and the copy's job is to hold what production holds.
//     NO_AUTO_VALUE_ON_ZERO, because a row whose AUTO_INCREMENT key is 0 would
//     otherwise be given a new key on insert.
//   - No foreign key checks. Tables are created and filled in name order, and a
//     child arriving before its parent is a copy, not a violation.
func copySettings(cfg *driver.Config) error {
	cfg.Params["sql_mode"] = "'NO_ENGINE_SUBSTITUTION,NO_AUTO_VALUE_ON_ZERO'"
	cfg.Params["foreign_key_checks"] = "0"
	// SET NAMES binary, with no collation: binary has exactly one.
	return cfg.Apply(driver.Charset("binary", ""))
}

// maskSettings make a session that rewrites rows in place.
//
// The server's own sql_mode is kept, strict where it is strict, so a masked
// value too long for its column is an error rather than a truncation. Foreign
// key checks are off because a parent and its child are rewritten one row at a
// time by the same deterministic transform, and between those two statements
// the reference is briefly wrong in exactly the way the second one fixes.
func maskSettings(cfg *driver.Config) {
	cfg.Params["foreign_key_checks"] = "0"
}

// quoteIdent quotes an identifier with backticks, doubling any inside it.
func quoteIdent(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

// shortHash names a database this provider makes. Twelve hex characters, so a
// prefixed name stays far inside MySQL's sixty four.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:6])
}

// ping reports whether a server answers.
func ping(ctx context.Context, db *sql.DB) error {
	var one int
	return db.QueryRowContext(ctx, "SELECT 1").Scan(&one)
}
