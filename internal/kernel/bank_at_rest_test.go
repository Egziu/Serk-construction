package kernel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/internal/testdb"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/datakey"
)

func fresh(p auth.Principal) auth.Principal {
	p.MFA, p.AuthTime = true, time.Now()
	return p
}

// R-BANK-AT-REST (0032): account numbers reach the database only as
// ciphertext bound to their row; a tenant credential, an export or a backup
// yields the keyed digest and the display suffix, nothing more.

func TestBankAtRest_CiphertextOnlyInTheDatabase(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	const number = "1000987654321"
	id, err := f.svc.AddSupplierBankAccount(f.ctx, c.buyer, w.sup[0], "Awash Bank", "ABC Steel PLC", "1000 9876 54321", "ETB")
	must(t, "add", err)
	var plain *string
	var enc []byte
	var digest, last4 string
	must(t, "raw read", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT account_number, account_number_enc, account_digest, account_last4 FROM supplier_bank_accounts WHERE id = $1::uuid`, id).Scan(&plain, &enc, &digest, &last4)
	}))
	if plain != nil {
		t.Errorf("OPEN: plaintext account number stored: %q", *plain)
	}
	if len(enc) < 30 || strings.Contains(string(enc), number) || strings.Contains(string(enc), "987654") {
		t.Errorf("OPEN: ciphertext carries the number: %x", enc)
	}
	if !strings.HasPrefix(digest, "hmac:") || len(digest) != 69 {
		t.Errorf("digest form: %q", digest)
	}
	if last4 != "4321" {
		t.Errorf("display suffix %q, want 4321", last4)
	}
	// The whole tenant-readable row: no field contains the number.
	var row string
	must(t, "row", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT to_jsonb(b)::text FROM supplier_bank_accounts b WHERE id = $1::uuid`, id).Scan(&row)
	}))
	if strings.Contains(row, number) || strings.Contains(row, "987654") {
		t.Errorf("OPEN: the tenant-readable row carries the number: %s", row)
	}
	// Readers see the mask; the reveal (MFA, audited) decrypts.
	d, err := f.svc.GetP2PDoc(f.ctx, c.buyer, "supplier_bank_account", id)
	must(t, "detail", err)
	if !strings.Contains(string(d.Detail), `"account_number_masked":"****4321"`) || strings.Contains(string(d.Detail), "987654") || strings.Contains(string(d.Detail), "account_number_enc") {
		t.Errorf("detail projection: %s", d.Detail)
	}
	must(t, "approve", f.svc.ApproveSupplierBankAccount(f.ctx, fresh(c.finMgr), id))
	rev, err := f.svc.RevealBankAccount(f.ctx, fresh(c.finMgr), "supplier_bank_account", id, "Verifying the payee before the first payment run")
	must(t, "reveal", err)
	if rev.AccountNumber != number {
		t.Errorf("reveal returned %q, want %q", rev.AccountNumber, number)
	}
	// Without the data key the kernel neither records nor reveals.
	noKey := New(f.db.Router, auth.NewAuthorizer(nil, true)).UseApprovalSigner(f.svc.signer)
	if _, err := noKey.AddSupplierBankAccount(f.ctx, c.buyer, w.sup[0], "Awash Bank", "ABC Steel PLC", "1000111122223", "ETB"); err == nil || !strings.Contains(err.Error(), "data key") {
		t.Errorf("add without a data key: %v", err)
	}
	if _, err := noKey.RevealBankAccount(f.ctx, fresh(c.finMgr), "supplier_bank_account", id, "Verifying the payee before the first payment run"); err == nil {
		t.Errorf("reveal without a data key succeeded")
	}
	// A different key (another deployment, or a stolen export decrypted
	// elsewhere) cannot open it.
	other := New(f.db.Router, auth.NewAuthorizer(nil, true)).UseApprovalSigner(f.svc.signer).
		UseBankDataKeys(datakey.Ring{Current: datakey.Key{ID: "test-k1", Master: []byte("another-key-of-at-least-32-bytes-0123456789")}})
	if _, err := other.RevealBankAccount(f.ctx, fresh(c.finMgr), "supplier_bank_account", id, "Verifying the payee before the first payment run"); err == nil {
		t.Errorf("another key revealed the number")
	}
	// Raw writes: plaintext refused; ciphertext immutable; another row's
	// ciphertext does not transplant (row binding).
	for what, stmt := range map[string]string{
		"plaintext insert": `INSERT INTO supplier_bank_accounts(supplier_id, bank_name, account_name, account_number, currency, created_by) VALUES ($1::uuid, 'X', 'Y', 'PLAIN00001', 'ETB', 'u-buyer')`,
		"ciphertext swap":  `UPDATE supplier_bank_accounts SET account_number_enc = '\x01'::bytea WHERE id = $2::uuid`,
	} {
		err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, stmt, w.sup[0], id)
			return err
		})
		if err == nil {
			t.Errorf("OPEN: %s accepted", what)
		}
	}
	// Duplicate company accounts are still detected, through the digest.
	acct := w.acct
	_, err = f.svc.RegisterCompanyBankAccount(f.ctx, c.treasury, f.entity, "Operating account 2", "CBE1000555666", "ETB", acct["1000"], acct["1050"])
	must(t, "company account", err)
	if _, err := f.svc.RegisterCompanyBankAccount(f.ctx, c.treasury, f.entity, "Operating account 3", "CBE 1000 555 666", "ETB", acct["1000"], acct["1050"]); err == nil || !strings.Contains(err.Error(), "cannot be registered") {
		t.Errorf("duplicate company account by digest: %v", err)
	}
}

// Pre-0032 rows: the posture check reports them, serk-migrate converts them,
// and the converted row reveals correctly.
func TestBankAtRest_LegacyPlaintextConversionAndPosture(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	// Simulate a pre-0032 row (the trigger refuses plaintext, so bypass it as
	// the owner, which only a migration could do).
	var legacy string
	must(t, "legacy row", f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `ALTER TABLE supplier_bank_accounts DISABLE TRIGGER USER`); err != nil {
			return err
		}
		defer tx.Exec(ctx, `ALTER TABLE supplier_bank_accounts ENABLE TRIGGER USER`)
		return tx.QueryRow(ctx, `INSERT INTO supplier_bank_accounts(tenant_id, supplier_id, bank_name, account_name, account_number, currency, created_by, status, approved_by)
			VALUES ($2::uuid, $1::uuid, 'Legacy Bank', 'ABC Steel PLC', 'LEGACY0004455', 'ETB', 'u-buyer', 'APPROVED', 'u-finance-manager') RETURNING id::text`, w.sup[0], f.tenant).Scan(&legacy)
	}))
	issues, err := f.app.Posture(f.ctx)
	must(t, "posture", err)
	found := false
	for _, s := range issues {
		if strings.Contains(s, "stored in plaintext: ") {
			found = true
		}
	}
	if !found {
		t.Errorf("posture does not report the plaintext row: %q", issues)
	}
	// The mask and the reveal still work on the unconverted row.
	if rev, err := f.svc.RevealBankAccount(f.ctx, fresh(c.finMgr), "supplier_bank_account", legacy, "Verifying the payee before the first payment run"); err != nil || rev.AccountNumber != "LEGACY0004455" {
		t.Errorf("reveal of the legacy row: %v %v", rev.AccountNumber, err)
	}
	n, err := postgres.EncryptBankAccounts(f.ctx, f.admin, testdb.BankDataKeys)
	must(t, "convert", err)
	if n < 1 {
		t.Errorf("converted %d rows, want at least the legacy row", n)
	}
	issues, err = f.app.Posture(f.ctx)
	must(t, "posture after", err)
	for _, s := range issues {
		if strings.Contains(s, "plaintext") {
			t.Errorf("posture still reports plaintext after conversion: %q", s)
		}
	}
	var plain *string
	var last4 string
	must(t, "raw", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT account_number, account_last4 FROM supplier_bank_accounts WHERE id = $1::uuid`, legacy).Scan(&plain, &last4)
	}))
	if plain != nil || last4 != "4455" {
		t.Errorf("after conversion: plain %v last4 %q", plain, last4)
	}
	if rev, err := f.svc.RevealBankAccount(f.ctx, fresh(c.finMgr), "supplier_bank_account", legacy, "Verifying the payee before the first payment run"); err != nil || rev.AccountNumber != "LEGACY0004455" {
		t.Errorf("reveal of the converted row: %v %v", rev.AccountNumber, err)
	}
	// Parameter logging: the posture item clears when the server setting is 0.
	var withZero int
	must(t, "setting", f.admin.QueryRow(f.ctx, `SELECT count(*) FROM (SELECT set_config('log_parameter_max_length', '0', true)) s, serk_database_posture() p WHERE p.issue LIKE 'log_parameter%'`).Scan(&withZero))
	if withZero != 0 {
		t.Errorf("posture reports log_parameter_max_length with the setting at 0")
	}
}
