package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/pkg/datakey"
)

// EncryptBankAccounts converts pre-0032 plaintext account numbers of every
// tenant into ciphertext, keyed digest and display suffix, and clears the
// plaintext. Run by serk-migrate as the schema owner (RLS is forced, so the
// tenant GUC is set per row's tenant). Returns the number of rows converted.
func EncryptBankAccounts(ctx context.Context, conn *pgx.Conn, ring datakey.Ring) (int, error) {
	total := 0
	for _, table := range []string{"supplier_bank_accounts", "company_bank_accounts"} {
		tx, err := conn.Begin(ctx)
		if err != nil {
			return total, err
		}
		if _, err := tx.Exec(ctx, `SET LOCAL app.tenant_id = ''`); err != nil {
			tx.Rollback(ctx)
			return total, err
		}
		// The status guard forbids any column change while the status is
		// unchanged; this one-time owner conversion changes only the storage
		// form (the 0032 trigger still checks it), so the guard is disabled
		// for this transaction only. The keyed digest, and so every stored
		// bank snapshot, is unchanged.
		if _, err := tx.Exec(ctx, fmt.Sprintf(`ALTER TABLE %s DISABLE TRIGGER %s_guard`, table, table)); err != nil {
			tx.Rollback(ctx)
			return total, err
		}
		// The owner sees every tenant only with RLS not forced for it; the
		// policies are forced, so iterate tenants explicitly.
		rows, err := tx.Query(ctx, `SELECT id::text FROM tenants`)
		if err != nil {
			tx.Rollback(ctx)
			return total, err
		}
		tenants, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			tx.Rollback(ctx)
			return total, err
		}
		for _, tenant := range tenants {
			if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
				tx.Rollback(ctx)
				return total, err
			}
			// Filtered by tenant explicitly: a superuser owner bypasses RLS.
			r, err := tx.Query(ctx, fmt.Sprintf(`SELECT id::text, account_number FROM %s WHERE tenant_id = $1::uuid AND account_number IS NOT NULL FOR UPDATE`, table), tenant)
			if err != nil {
				tx.Rollback(ctx)
				return total, err
			}
			type row struct{ id, number string }
			var todo []row
			for r.Next() {
				var x row
				if err := r.Scan(&x.id, &x.number); err != nil {
					r.Close()
					tx.Rollback(ctx)
					return total, err
				}
				todo = append(todo, x)
			}
			r.Close()
			for _, x := range todo {
				enc, err := ring.Encrypt(tenant, datakey.AAD(table, x.id, tenant), []byte(x.number))
				if err != nil {
					tx.Rollback(ctx)
					return total, err
				}
				var digest string
				if err := tx.QueryRow(ctx, `SELECT p2p_account_digest_for($1::uuid, $2)`, tenant, x.number).Scan(&digest); err != nil {
					tx.Rollback(ctx)
					return total, err
				}
				k := len(x.number) / 3
				if k > 4 {
					k = 4
				}
				if _, err := tx.Exec(ctx, fmt.Sprintf(`UPDATE %s SET account_number_enc = $2, account_digest = $3, account_last4 = $4, account_number = NULL WHERE id = $1::uuid`, table),
					x.id, enc, digest, x.number[len(x.number)-k:]); err != nil {
					tx.Rollback(ctx)
					return total, err
				}
				total++
			}
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(`ALTER TABLE %s ENABLE TRIGGER %s_guard`, table, table)); err != nil {
			tx.Rollback(ctx)
			return total, err
		}
		if err := tx.Commit(ctx); err != nil {
			return total, err
		}
	}
	return total, nil
}
