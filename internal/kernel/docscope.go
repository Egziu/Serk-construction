package kernel

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// Document visibility (IA-040-01, ADR 0010). ONE policy decides whether a
// principal may see a P2P document, and it is used by every path that
// returns or acts on one: list, detail, mutation and bank-detail reveal.
//
//   - project documents (BOQ, requisition, RFQ, quote, PO, GRN, invoice):
//     the principal's effective scope must include the document's project;
//   - supplier and customer master (code, name, tax id): any p2p.read
//     holder, because every project role must recognise its counterparties;
//   - supplier bank accounts: tenant-wide scope, or supplier.manage (the
//     procurement officers who enter them); always masked;
//   - entity-level finance documents (payment instructions, P2P and contract
//     policies, company bank accounts, customer receipts, money-in statement
//     lines) and anything not listed: tenant-wide scope only.
//
// "Tenant-wide" is auth.ScopeOf: the scope.tenant_wide entitlement AND no
// project restriction on the principal (SC-05). Out-of-scope documents are
// reported exactly like nonexistent ones.

func (s *Service) canSee(p auth.Principal, docType, project string) bool {
	sc := s.authz.ScopeOf(p)
	if project != "" {
		return sc.Allows(project)
	}
	if sc.TenantWide {
		return true
	}
	switch docType {
	case "supplier", "customer":
		return true
	case "supplier_bank_account":
		return s.authz.Has(p, auth.PermSupplierManage)
	}
	return false
}

// listScope is canSee expressed as the filter applied inside the list query.
func (s *Service) listScope(p auth.Principal, docType string) postgres.ListScope {
	sc := s.authz.ScopeOf(p)
	ls := postgres.ListScope{TenantWide: sc.TenantWide, Projects: sc.Projects, EntityLevel: s.canSee(p, docType, "")}
	if ls.Projects == nil {
		ls.Projects = []string{}
	}
	return ls
}

// tenantWide is the tenant-wide test of the visibility policy: the
// scope.tenant_wide entitlement AND no project restriction (auth.ScopeOf).
// Every entity-level operation uses it; Has(scope.tenant_wide) alone is
// never sufficient (review 5, F1).
var docTypes = postgres.DocTypes()

func (s *Service) tenantWide(p auth.Principal) bool { return s.authz.ScopeOf(p).TenantWide }

// visibleDoc loads a document only if the principal may see it. Visibility
// is decided BEFORE any row lock is taken, so an out-of-scope caller can
// never wait on (and so detect) a locked document (review 5, F2).
func (s *Service) visibleDoc(ctx context.Context, tx pgx.Tx, p auth.Principal, docType, id string, lock bool) (postgres.Doc, error) {
	if _, ok := docTypes[docType]; !ok {
		return postgres.Doc{}, postgres.ErrUnknownDocType
	}
	proj, err := docProject(ctx, tx, docType, id)
	if err != nil {
		return postgres.Doc{}, ErrNotFound
	}
	if !s.canSee(p, docType, proj) {
		return postgres.Doc{}, ErrNotFound // indistinguishable from absence
	}
	return postgres.GetDoc(ctx, tx, docType, id, lock)
}

// auditRefusal records a refused sensitive operation in its own transaction
// (the refused one rolls back). Best effort: a failure to audit is logged by
// the caller's error path, never turned into success.
func (s *Service) auditRefusal(ctx context.Context, p auth.Principal, action, docType, id string, payload map[string]any) {
	_ = s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if id == "" {
			id = "-"
		}
		return postgres.Audit(ctx, tx, postgres.AuditEntry{TenantID: p.TenantID, ActorID: p.UserID, Action: action,
			AggregateType: docType, AggregateID: id, RequestID: requestID(ctx), Payload: payload})
	})
}

// ---------------------------------------------------------------------------
// Response projections: explicit allowlists for documents that carry bank
// details. Account numbers leave the kernel only masked ("****6789").
// ---------------------------------------------------------------------------

var bankAccountFields = map[string][]string{
	"supplier_bank_account": {"id", "supplier_id", "bank_name", "account_name", "currency", "status", "created_by", "created_at", "approved_by", "approved_at"},
	"company_bank_account": {"id", "legal_entity_id", "name", "currency", "gl_account_id", "clearing_account_id", "status", "created_by", "created_at",
		"approved_by", "approved_at"},
}

var paymentFields = []string{"id", "number", "legal_entity_id", "supplier_id", "supplier_bank_id", "company_bank_id", "currency", "amount", "value_date",
	"policy_id", "status", "created_by", "created_at", "submitted_at", "approved_by", "approved_at", "second_approved_by", "second_approved_at",
	"released_by", "released_at", "settled_at", "cancel_reason"}

// MaskAccount shows at most the last four characters and never more than a
// third of the number, behind a fixed-width prefix that hides the length.
func MaskAccount(n string) string {
	n = strings.ReplaceAll(n, " ", "")
	k := len(n) / 3
	if k > 4 {
		k = 4
	}
	return "****" + n[len(n)-k:]
}

func pick(src map[string]any, fields []string) map[string]any {
	out := make(map[string]any, len(fields)+1)
	for _, f := range fields {
		if v, ok := src[f]; ok {
			out[f] = v
		}
	}
	return out
}

// scrub masks any account number that might appear anywhere else (defence
// in depth for document types without an explicit projection).
func scrub(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			switch k {
			case "account_number":
				if n, ok := val.(string); ok {
					out["account_number_masked"] = MaskAccount(n)
				}
			case "bank_snapshot":
				// fingerprint of payee details; not needed by readers
			default:
				out[k] = scrub(val)
			}
		}
		return out
	case []any:
		for i := range x {
			x[i] = scrub(x[i])
		}
		return x
	}
	return v
}

// maskedAccountOf returns the masked number of the bank account a document
// carries (the subject text holds only a keyed digest since 0017).
func maskedAccountOf(ctx context.Context, tx pgx.Tx, docType, id string) (string, error) {
	var q string
	switch docType {
	case "supplier_bank_account":
		q = `SELECT account_number FROM supplier_bank_accounts WHERE id = $1::uuid`
	case "company_bank_account":
		q = `SELECT account_number FROM company_bank_accounts WHERE id = $1::uuid`
	case "payment_instruction":
		q = `SELECT b.account_number FROM payment_instructions p JOIN supplier_bank_accounts b ON b.id = p.supplier_bank_id WHERE p.id = $1::uuid`
	default:
		return "", nil
	}
	var n string
	if err := tx.QueryRow(ctx, q, id).Scan(&n); err != nil {
		return "", err
	}
	return MaskAccount(n), nil
}

// projectDoc returns the reader-safe detail of a document; masked is the
// masked account number for documents that carry one.
func projectDoc(docType string, raw json.RawMessage, masked string) (json.RawMessage, error) {
	if len(raw) == 0 {
		return raw, nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	m, _ := v.(map[string]any)
	switch {
	case bankAccountFields[docType] != nil && m != nil:
		out := pick(m, bankAccountFields[docType])
		out["account_number_masked"] = masked
		v = out
	case docType == "payment_instruction" && m != nil:
		h, _ := m["h"].(map[string]any)
		payee, _ := m["payee"].(map[string]any)
		out := map[string]any{"h": pick(h, paymentFields), "alloc": m["alloc"]}
		if payee != nil {
			pe := pick(payee, bankAccountFields["supplier_bank_account"])
			pe["account_number_masked"] = masked
			out["payee"] = pe
		}
		v = out
	default:
		v = scrub(v)
	}
	return json.Marshal(v)
}

// ---------------------------------------------------------------------------
// Privileged reveal of a full bank account number.
// ---------------------------------------------------------------------------

// BankAccountReveal is the full detail returned by RevealBankAccount.
type BankAccountReveal struct {
	ID            string `json:"id"`
	BankName      string `json:"bank_name,omitempty"`
	AccountName   string `json:"account_name,omitempty"`
	AccountNumber string `json:"account_number"`
	Currency      string `json:"currency"`
}

// RevealBankAccount returns a full account number to a principal holding
// bank.details.reveal and p2p.read, tenant-wide scope, fresh MFA and a
// stated purpose, under the same visibility policy as every other read. Each reveal is audited (without the
// number itself).
func (s *Service) RevealBankAccount(ctx context.Context, p auth.Principal, docType, id, purpose string) (BankAccountReveal, error) {
	var out BankAccountReveal
	if docType != "supplier_bank_account" && docType != "company_bank_account" {
		return out, ErrNotFound
	}
	refused := func(err error) (BankAccountReveal, error) {
		s.auditRefusal(ctx, p, "bank.details.reveal_refused", docType, id, map[string]any{"reason": err.Error()})
		return BankAccountReveal{}, err
	}
	if err := s.authz.Require(p, auth.PermBankDetailsReveal, p.TenantID); err != nil {
		return refused(err)
	}
	if err := s.authz.Require(p, auth.PermP2PRead, p.TenantID); err != nil {
		return refused(err)
	}
	if !s.tenantWide(p) {
		// Supplier bank accounts are visible (masked) to project-restricted
		// supplier.manage holders; the full number is not (review 5, F6).
		return refused(ErrNotFound)
	}
	if err := s.authz.RequireStepUp(p); err != nil {
		return refused(err)
	}
	purpose = strings.TrimSpace(purpose)
	if n := utf8.RuneCountInString(purpose); n < 20 || n > 500 {
		return refused(fmt.Errorf("%w: state the purpose of the reveal (20 to 500 characters)", ErrInvalidInput))
	}
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := checkSessionTx(ctx, tx, p); err != nil {
			return err
		}
		if _, err := s.visibleDoc(ctx, tx, p, docType, id, false); err != nil {
			return err
		}
		q := `SELECT id::text, bank_name, account_name, account_number, currency FROM supplier_bank_accounts WHERE id = $1::uuid`
		if docType == "company_bank_account" {
			q = `SELECT id::text, '', name, account_number, currency FROM company_bank_accounts WHERE id = $1::uuid`
		}
		if err := tx.QueryRow(ctx, q, id).Scan(&out.ID, &out.BankName, &out.AccountName, &out.AccountNumber, &out.Currency); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "bank.details.reveal", docType, id, "bank.details.revealed",
			map[string]any{"document_type": docType, "account": MaskAccount(out.AccountNumber), "purpose": purpose, "mfa_auth_time": p.AuthTime.UTC()})
	})
	if err != nil {
		return refused(err)
	}
	return out, nil
}
