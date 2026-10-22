package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/pkg/datakey"
)

// EncryptBankAccounts converts pre-0032 plaintext account numbers of every
// tenant into ciphertext, keyed digest and display suffix, and clears the
// plaintext. It also re-digests rows encrypted between 0032 and 0035, whose
// digest the database computed ("hmac:"), with the API's digest key
// ("hkey:", R10-F4), so duplicate detection compares like with like. Run by
// serk-migrate as the schema owner (RLS is forced, so the tenant GUC is set
// per row's tenant). Returns the number of rows converted or re-digested.
//
// Approval subjects and payment snapshots bind the digest: an approval or
// payment prepared before the conversion is refused afterwards (fail closed)
// and must be prepared again. Run it before go-live, or with no bank
// approval or payment in flight.
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
		// for this transaction only. The 0035 trigger admits only the
		// storage-form change and an hmac:->hkey: digest change, and only in
		// a maintenance session.
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
				if len(ring.DigestKey) == 0 {
					tx.Rollback(ctx)
					return total, fmt.Errorf("postgres: the bank digest key is required")
				}
				digest, err := datakey.Digest(ring.DigestKey, tenant, x.number)
				if err != nil {
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
			// Encrypted rows with a database-computed digest (0032-0034).
			r, err = tx.Query(ctx, fmt.Sprintf(`SELECT id::text, account_number_enc FROM %s WHERE tenant_id = $1::uuid AND account_number IS NULL
				AND account_number_enc IS NOT NULL AND account_digest LIKE 'hmac:%%' FOR UPDATE`, table), tenant)
			if err != nil {
				tx.Rollback(ctx)
				return total, err
			}
			type encRow struct {
				id  string
				enc []byte
			}
			var legacy []encRow
			for r.Next() {
				var x encRow
				if err := r.Scan(&x.id, &x.enc); err != nil {
					r.Close()
					tx.Rollback(ctx)
					return total, err
				}
				legacy = append(legacy, x)
			}
			r.Close()
			for _, x := range legacy {
				if len(ring.DigestKey) == 0 {
					tx.Rollback(ctx)
					return total, fmt.Errorf("postgres: the bank digest key is required")
				}
				pt, err := ring.Decrypt(tenant, datakey.AAD(table, x.id, tenant), x.enc)
				if err != nil {
					tx.Rollback(ctx)
					return total, fmt.Errorf("postgres: %s %s: %w", table, x.id, err)
				}
				digest, err := datakey.Digest(ring.DigestKey, tenant, string(pt))
				if err != nil {
					tx.Rollback(ctx)
					return total, err
				}
				if _, err := tx.Exec(ctx, fmt.Sprintf(`UPDATE %s SET account_digest = $2 WHERE id = $1::uuid`, table), x.id, digest); err != nil {
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
