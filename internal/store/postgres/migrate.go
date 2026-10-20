// Package postgres is the PostgreSQL implementation of the SERK Construction
// financial kernel store.
package postgres

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Migration is one versioned SQL file.
type Migration struct {
	Version  int
	Name     string
	SQL      string
	Checksum string
}

// LoadMigrations reads the embedded migrations in version order.
func LoadMigrations() ([]Migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var out []Migration
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		var v int
		if _, err := fmt.Sscanf(name, "%04d_", &v); err != nil || v == 0 {
			return nil, fmt.Errorf("migration %q must be named NNNN_name.sql", name)
		}
		b, err := migrationFS.ReadFile("migrations/" + name)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(b)
		out = append(out, Migration{Version: v, Name: name, SQL: string(b), Checksum: hex.EncodeToString(sum[:])})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	for i := 1; i < len(out); i++ {
		if out[i].Version == out[i-1].Version {
			return nil, fmt.Errorf("duplicate migration version %d", out[i].Version)
		}
	}
	return out, nil
}

// Migrate applies pending migrations using an admin (schema-owner) connection.
// Each migration runs in its own transaction and is recorded with its checksum;
// a changed checksum for an applied version is refused (migrations are
// immutable history, like journals).
func Migrate(ctx context.Context, conn *pgx.Conn) (applied []string, err error) {
	// Serialise concurrent migrators before touching the catalog (even
	// CREATE TABLE IF NOT EXISTS races in PostgreSQL).
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock(727001)`); err != nil {
		return nil, err
	}
	defer func() { _, _ = conn.Exec(ctx, `SELECT pg_advisory_unlock(727001)`) }()
	if _, err = conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version integer PRIMARY KEY, name text NOT NULL, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}

	ms, err := LoadMigrations()
	if err != nil {
		return nil, err
	}
	for _, m := range ms {
		var existing string
		row := conn.QueryRow(ctx, `SELECT checksum FROM schema_migrations WHERE version=$1`, m.Version)
		switch err := row.Scan(&existing); {
		case err == nil:
			if existing != m.Checksum {
				return applied, fmt.Errorf("migration %s already applied with a different checksum; refusing", m.Name)
			}
			continue
		case err != pgx.ErrNoRows:
			return applied, err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return applied, err
		}
		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			_ = tx.Rollback(ctx)
			return applied, fmt.Errorf("migration %s failed: %w", m.Name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version,name,checksum) VALUES ($1,$2,$3)`, m.Version, m.Name, m.Checksum); err != nil {
			_ = tx.Rollback(ctx)
			return applied, err
		}
		if err := tx.Commit(ctx); err != nil {
			return applied, err
		}
		applied = append(applied, m.Name)
	}
	return applied, nil
}
