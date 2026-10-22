package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// IA-040-01 (independent assessment of v0.4.0): the single-document read
// applied project scope only to project documents, so any p2p.read holder
// could fetch entity-level payment instructions, P2P policies and bank
// accounts by id, and detail responses carried full bank account numbers.
//
// Required behaviour: one visibility policy for list, detail and mutation;
// entity-level finance documents need tenant-wide scope; bank account numbers
// are masked in every ordinary response; the full number is available only
// through an explicit, permissioned, MFA-fresh, audited reveal.

const (
	iaSupplierAcct = "1000123456789" // the approved supplier account in newP2PWorld
	iaCompanyAcct  = "1000999888777"
)

type iaWorld struct {
	*p2pWorld
	payment string
	other   string // a second project of the same tenant
}

func newIAWorld(t *testing.T) *iaWorld {
	t.Helper()
	w := &iaWorld{p2pWorld: newP2PWorld(t)}
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	_, _, po := w.awardedPO(t, "20", "500")
	_, _, inv, _ := w.r3invoice(t, po, "1", "IA-1")
	var err error
	w.payment, err = f.svc.PreparePayment(f.ctx, c.treasury, f.entity, w.sup[0], w.supBank, w.bank, today(), []Allocation{{inv, dec("97175")}})
	must(t, "payment", err)
	err = f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		w.other, err = postgres.CreateProject(ctx, tx, f.tenant, f.entity, "P-002", "Adigrat Water Supply", "ETB")
		return err
	})
	must(t, "second project", err)
	return w
}

// Principals that hold p2p.read but no tenant-wide scope.
func (w *iaWorld) restricted() map[string]auth.Principal {
	c := w.cast
	now := time.Now()
	other := auth.Principal{UserID: "u-other-pm", TenantID: w.f.tenant, Roles: []string{"project_manager"}, ProjectIDs: []string{w.other},
		IssuedAt: now.Add(-time.Minute), Kind: auth.KindHuman}
	analyst := auth.Principal{UserID: "u-analyst", TenantID: w.f.tenant, Roles: []string{"auditor"}, ProjectIDs: []string{w.f.project},
		IssuedAt: now.Add(-time.Minute), Kind: auth.KindHuman} // tenant-wide role, but restricted by a project list (SC-05)
	return map[string]auth.Principal{"project manager": c.pm, "site engineer": c.siteEng, "storekeeper": c.store,
		"other-project manager": other, "project-restricted analyst": analyst}
}

func TestIA04001_EntityLevelDocumentsNeedTenantWideScope(t *testing.T) {
	w := newIAWorld(t)
	f := w.f
	docs := map[string]string{"payment_instruction": w.payment, "p2p_policy": w.policy, "company_bank_account": w.bank}
	for who, p := range w.restricted() {
		for typ, id := range docs {
			d, err := f.svc.GetP2PDoc(f.ctx, p, typ, id)
			if err == nil {
				t.Errorf("EXPOSED: %s read %s %s by id (%d bytes of detail)", who, typ, id[:8], len(d.Detail))
				continue
			}
			if !errors.Is(err, ErrNotFound) {
				t.Errorf("%s reading %s: refused with %v, want not-found (no existence disclosure)", who, typ, err)
				continue
			}
			t.Logf("refused %-27s %-21s not found", who, typ)
		}
		// List/detail parity: what cannot be read is not listed either.
		for typ := range docs {
			items, err := f.svc.ListP2PDocs(f.ctx, p, typ, "", 200)
			if err != nil || len(items) != 0 {
				t.Errorf("%s lists %d %s (err %v)", who, len(items), typ, err)
			}
		}
	}
	// A nonexistent id and an out-of-scope id are indistinguishable.
	_, e1 := f.svc.GetP2PDoc(f.ctx, w.cast.pm, "payment_instruction", "00000000-0000-4000-8000-000000000000")
	_, e2 := f.svc.GetP2PDoc(f.ctx, w.cast.pm, "payment_instruction", w.payment)
	if e1 == nil || e2 == nil || e1.Error() != e2.Error() {
		t.Errorf("existence disclosure: unknown id -> %v, out-of-scope id -> %v", e1, e2)
	}
	// Mutations use the same policy: a project-restricted finance role cannot act on entity-level documents.
	scopedFin := w.cast.finMgr
	scopedFin.ProjectIDs = []string{f.project}
	if _, err := f.svc.ApprovePayment(f.ctx, scopedFin, w.payment); !errors.Is(err, ErrNotFound) {
		t.Errorf("project-restricted finance manager acting on a payment: %v, want not-found", err)
	}
	// Tenant-wide finance roles still read them.
	for _, p := range []auth.Principal{w.cast.finMgr, w.cast.treasury, w.cast.controller} {
		for typ, id := range docs {
			if _, err := f.svc.GetP2PDoc(f.ctx, p, typ, id); err != nil {
				t.Errorf("%s cannot read %s: %v", p.UserID, typ, err)
			}
		}
	}
}

func TestIA04001_BankAccountNumbersMaskedEverywhere(t *testing.T) {
	w := newIAWorld(t)
	f, c := w.f, w.cast
	check := func(who string, p auth.Principal, typ, id string) {
		t.Helper()
		d, err := f.svc.GetP2PDoc(f.ctx, p, typ, id)
		if err != nil {
			t.Errorf("%s reading %s: %v", who, typ, err)
			return
		}
		raw, _ := json.Marshal(d)
		for _, full := range []string{iaSupplierAcct, iaCompanyAcct} {
			if strings.Contains(string(raw), full) {
				t.Errorf("EXPOSED: %s's %s response contains the full account number %s", who, typ, full)
			}
		}
		if !strings.Contains(string(raw), "6789") && !strings.Contains(string(raw), "8777") {
			t.Errorf("%s's %s response lost the last-4 digits needed to recognise the account: %s", who, typ, raw)
		}
	}
	// Supplier bank accounts: the procurement officers who enter them (project
	// scoped, supplier.manage) see them masked; other project roles do not.
	check("procurement officer", c.buyer, "supplier_bank_account", w.supBank)
	if _, err := f.svc.GetP2PDoc(f.ctx, c.siteEng, "supplier_bank_account", w.supBank); !errors.Is(err, ErrNotFound) {
		t.Errorf("site engineer reads supplier bank details: %v", err)
	}
	if items, _ := f.svc.ListP2PDocs(f.ctx, c.siteEng, "supplier_bank_account", "", 200); len(items) != 0 {
		t.Errorf("site engineer lists %d supplier bank accounts", len(items))
	}
	// The supplier master itself (code, name, tax id) stays visible to project roles.
	if _, err := f.svc.GetP2PDoc(f.ctx, c.siteEng, "supplier", w.sup[0]); err != nil {
		t.Errorf("site engineer cannot read the supplier master: %v", err)
	}
	// Finance sees masked numbers by default too.
	check("finance manager", c.finMgr, "supplier_bank_account", w.supBank)
	check("finance manager", c.finMgr, "company_bank_account", w.bank)
	check("treasury", c.treasury, "payment_instruction", w.payment)
	// Lists carry only the last four digits.
	for _, typ := range []string{"supplier_bank_account", "company_bank_account"} {
		items, _ := f.svc.ListP2PDocs(f.ctx, c.finMgr, typ, "", 200)
		raw, _ := json.Marshal(items)
		if strings.Contains(string(raw), iaSupplierAcct) || strings.Contains(string(raw), iaCompanyAcct) {
			t.Errorf("EXPOSED: %s list contains a full account number", typ)
		}
	}
}
