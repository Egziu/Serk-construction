package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// NOT VALID constraints (GATEA-13). Migrations add some constraints NOT
// VALID so that pre-existing (legacy) rows are never rewritten: new rows are
// checked, old rows are reported. ValidateConstraints lists every such
// constraint, counts the rows that violate it, records each violating row in
// the append-only migration_exceptions ledger (for human resolution by
// reversal or re-entry, never by editing history) and, when apply is set,
// VALIDATEs only the constraints with no violators. It runs as the schema
// owner (serk-migrate).

// ConstraintReport is one NOT VALID constraint and its violators.
type ConstraintReport struct {
	Table, Name, Kind, Definition string
	Violators                     int64
	Validated                     bool
}

// ValidateConstraints reports (and with apply, validates) NOT VALID
// constraints in the public schema.
func ValidateConstraints(ctx context.Context, conn *pgx.Conn, apply bool) ([]ConstraintReport, error) {
	rows, err := conn.Query(ctx, `
		SELECT c.conrelid::regclass::text, c.conname, c.contype::text || CASE WHEN c.contype = 'f' THEN c.confmatchtype::text ELSE '' END, pg_get_constraintdef(c.oid),
		       (SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY k.ord) FROM unnest(c.conkey) WITH ORDINALITY k(attnum, ord)
		          JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum),
		       COALESCE(c.confrelid::regclass::text, ''),
		       (SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY k.ord) FROM unnest(c.confkey) WITH ORDINALITY k(attnum, ord)
		          JOIN pg_attribute a ON a.attrelid = c.confrelid AND a.attnum = k.attnum),
		       (SELECT string_agg(quote_ident(a.attname), ', ' ORDER BY a.attnum) FROM pg_index i JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY (i.indkey)
		          WHERE i.indrelid = c.conrelid AND i.indisprimary)
		  FROM pg_constraint c JOIN pg_namespace n ON n.oid = c.connamespace
		 WHERE n.nspname = 'public' AND NOT c.convalidated AND c.contype IN ('c', 'f')
		 ORDER BY 1, 2`)
	if err != nil {
		return nil, err
	}
	type cons struct {
		table, name, kind, def, cols, refTable, refCols, pk string
	}
	var list []cons
	for rows.Next() {
		var x cons
		var refCols, pk *string
		if err := rows.Scan(&x.table, &x.name, &x.kind, &x.def, &x.cols, &x.refTable, &refCols, &pk); err != nil {
			rows.Close()
			return nil, err
		}
		if refCols != nil {
			x.refCols = *refCols
		}
		if pk != nil {
			x.pk = *pk
		}
		list = append(list, x)
	}
	rows.Close()
	var out []ConstraintReport
	for _, x := range list {
		var where string
		switch x.kind {
		case "c":
			// "CHECK (<expr>) NOT VALID" -> NOT (<expr>)
			expr := strings.TrimSuffix(strings.TrimPrefix(x.def, "CHECK "), " NOT VALID")
			where = "NOT " + expr
		case "fs", "fp", "ff":
			cols, ref := strings.Split(x.cols, ", "), strings.Split(x.refCols, ", ")
			var conds []string
			for i := range cols {
				conds = append(conds, fmt.Sprintf("r.%s = t.%s", ref[i], cols[i]))
			}
			// A composite FK with any NULL column is not checked (MATCH SIMPLE).
			var notNull []string
			for _, c := range cols {
				notNull = append(notNull, "t."+c+" IS NOT NULL")
			}
			where = strings.Join(notNull, " AND ") + " AND NOT EXISTS (SELECT 1 FROM " + x.refTable + " r WHERE " + strings.Join(conds, " AND ") + ")"
			if x.kind == "ff" && len(cols) > 1 {
				// MATCH FULL (R10-F9): a key that is partly NULL is itself a
				// violation; only an all-NULL key is exempt.
				var someNull []string
				for _, c := range cols {
					someNull = append(someNull, "t."+c+" IS NULL")
				}
				where = "(" + where + ") OR ((" + strings.Join(someNull, " OR ") + ") AND NOT (" + strings.Join(someNull, " AND ") + "))"
			}
		}
		rowRef := "t.ctid::text"
		if x.pk != "" {
			var parts []string
			for _, c := range strings.Split(x.pk, ", ") {
				parts = append(parts, "t."+c+"::text")
			}
			rowRef = "concat_ws('#', " + strings.Join(parts, ", ") + ")"
		}
		r := ConstraintReport{Table: x.table, Name: x.name, Kind: map[string]string{"c": "CHECK", "fs": "FOREIGN KEY", "fp": "FOREIGN KEY", "ff": "FOREIGN KEY (MATCH FULL)"}[x.kind], Definition: x.def}
		if r.Kind == "" {
			return out, fmt.Errorf("%s: unsupported constraint kind %q", x.name, x.kind)
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return out, err
		}
		// Record violators not yet in the ledger for this rule.
		rule := "GATEA-13 " + x.name
		tag, err := tx.Exec(ctx, fmt.Sprintf(`INSERT INTO migration_exceptions(migration, rule, table_name, row_ref, detail)
			SELECT 'validate-constraints', $1, $2, %s, 'violates %s'
			  FROM %s t WHERE %s
			   AND NOT EXISTS (SELECT 1 FROM migration_exceptions e WHERE e.rule = $1 AND e.table_name = $2 AND e.row_ref = %s)`,
			rowRef, strings.ReplaceAll(x.def, "'", "''"), x.table, where, rowRef), rule, x.table)
		if err != nil {
			tx.Rollback(ctx)
			return out, fmt.Errorf("%s: %w", x.name, err)
		}
		_ = tag
		if err := tx.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s t WHERE %s`, x.table, where)).Scan(&r.Violators); err != nil {
			tx.Rollback(ctx)
			return out, fmt.Errorf("%s: %w", x.name, err)
		}
		if apply && r.Violators == 0 {
			// The database is the final judge: a refusal here means the
			// report missed a violator; keep the ledger entries recorded so
			// far and report the constraint as not validated.
			if _, err := tx.Exec(ctx, `SAVEPOINT validate_one`); err != nil {
				tx.Rollback(ctx)
				return out, err
			}
			if _, err := tx.Exec(ctx, fmt.Sprintf(`ALTER TABLE %s VALIDATE CONSTRAINT %s`, x.table, pgx.Identifier{x.name}.Sanitize())); err != nil {
				if _, rerr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT validate_one`); rerr != nil {
					tx.Rollback(ctx)
					return out, rerr
				}
				r.Violators = -1 // unknown: the database refused validation
				r.Definition += " [VALIDATE refused: " + err.Error() + "]"
			} else {
				r.Validated = true
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return out, err
		}
		out = append(out, r)
	}
	return out, nil
}
