package kernel

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
)

// GATEA-13: NOT VALID constraints are validated only when no legacy row
// violates them; violating rows are recorded in the append-only exception
// ledger, never rewritten by the tool.
func TestLegacy_NotValidConstraintsAreValidatedOrReported(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	// A bank statement with one line, imported through the kernel.
	st, err := f.svc.ImportBankStatement(f.ctx, c.bankOfficer, stmt(w.bank, "CBE-LEGACY-1", today(), "0", "1000", [3]string{"1000", "LEGACY LINE", "SOMEONE"}))
	must(t, "statement", err)
	var lines []string
	must(t, "lines", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		r, err := tx.Query(ctx, `SELECT id::text FROM bank_statement_lines WHERE statement_id = $1::uuid ORDER BY line_no`, st)
		if err != nil {
			return err
		}
		lines, err = pgx.CollectRows(r, pgx.RowTo[string])
		return err
	}))
	if len(lines) != 1 {
		t.Fatalf("statement lines: %d", len(lines))
	}
	// Plant legacy dirt as only a migration could: drop the NOT VALID
	// check, write a MATCHED line without a reconciler, re-add it NOT VALID.
	must(t, "plant", f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		for _, q := range []string{
			`ALTER TABLE bank_statement_lines DISABLE TRIGGER USER`,
			`ALTER TABLE bank_statement_lines DROP CONSTRAINT bank_statement_lines_matched_by`,
			`UPDATE bank_statement_lines SET status = 'MATCHED', matched_by = NULL WHERE id = '` + lines[0] + `'::uuid`,
			`ALTER TABLE bank_statement_lines ADD CONSTRAINT bank_statement_lines_matched_by CHECK (status <> 'MATCHED' OR (matched_by IS NOT NULL AND btrim(matched_by) <> '')) NOT VALID`,
			`ALTER TABLE bank_statement_lines ENABLE TRIGGER USER`,
		} {
			if _, err := tx.Exec(ctx, q); err != nil {
				return err
			}
		}
		return nil
	}))
	reps, err := postgres.ValidateConstraints(f.ctx, f.admin, true)
	must(t, "validate", err)
	byName := map[string]postgres.ConstraintReport{}
	for _, r := range reps {
		byName[r.Name] = r
		t.Logf("%s.%s %s violators=%d validated=%v", r.Table, r.Name, r.Kind, r.Violators, r.Validated)
	}
	dirty := byName["bank_statement_lines_matched_by"]
	if dirty.Violators != 1 || dirty.Validated {
		t.Errorf("the dirty constraint: violators %d validated %v (want 1, false)", dirty.Violators, dirty.Validated)
	}
	for _, r := range reps {
		if r.Name != "bank_statement_lines_matched_by" && (r.Violators != 0 || !r.Validated) {
			t.Errorf("%s: violators %d validated %v (want 0, true)", r.Name, r.Violators, r.Validated)
		}
	}
	var ledger string
	must(t, "ledger", f.admin.QueryRow(f.ctx, `SELECT string_agg(rule || ' ' || table_name || ' ' || row_ref, '; ') FROM migration_exceptions WHERE migration = 'validate-constraints'`).Scan(&ledger))
	if !strings.Contains(ledger, "GATEA-13 bank_statement_lines_matched_by bank_statement_lines "+lines[0]) {
		t.Errorf("violator not in the exception ledger: %q", ledger)
	}
	// The tool never edits the row; a human resolves it (here: the
	// reconciler is recorded), and a re-run validates the constraint. The
	// ledger entry stays (append-only).
	must(t, "resolve", f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `ALTER TABLE bank_statement_lines DISABLE TRIGGER USER`)
		if err != nil {
			return err
		}
		defer tx.Exec(ctx, `ALTER TABLE bank_statement_lines ENABLE TRIGGER USER`)
		_, err = tx.Exec(ctx, `UPDATE bank_statement_lines SET matched_by = 'u-legacy-reconciler' WHERE id = $1::uuid`, lines[0])
		return err
	}))
	reps, err = postgres.ValidateConstraints(f.ctx, f.admin, true)
	must(t, "validate 2", err)
	for _, r := range reps {
		if r.Violators != 0 || !r.Validated {
			t.Errorf("after resolution %s: violators %d validated %v", r.Name, r.Violators, r.Validated)
		}
	}
	var remaining int
	must(t, "remaining", f.admin.QueryRow(f.ctx, `SELECT count(*) FROM pg_constraint WHERE NOT convalidated AND contype IN ('c','f') AND connamespace = 'public'::regnamespace`).Scan(&remaining))
	if remaining != 0 {
		t.Errorf("%d NOT VALID constraints remain", remaining)
	}
	var kept int
	// Counted for this test's row only: other tests record their own
	// violators in the same (shared) ledger, in any order under -shuffle.
	must(t, "kept", f.admin.QueryRow(f.ctx, `SELECT count(*) FROM migration_exceptions WHERE migration = 'validate-constraints' AND row_ref = $1`, lines[0]).Scan(&kept))
	if kept != 1 {
		t.Errorf("ledger entries %d, want 1 kept (append-only)", kept)
	}
}
