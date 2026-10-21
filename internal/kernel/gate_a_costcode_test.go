package kernel

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
	"github.com/serk-group/serk-construction/pkg/money"
)

func ptrTime(t time.Time) *time.Time { return &t }

// SC-10: cost codes come from an approved, versioned WBS of the same project,
// must be active and in date; accounts can require them.
func TestSC10_CostCodesAreValidatedAgainstApprovedWBS(t *testing.T) {
	f := newFixture(t)
	pm := auth.Principal{UserID: "u-pm", TenantID: f.tenant, Roles: []string{"project_manager"}, ProjectIDs: []string{f.project}}
	nodes := []postgres.WBSNode{{Code: "01", Name: "Substructure"}, {Code: "01.01", Name: "Excavation", ParentCode: "01"}}
	codes := []postgres.CostCode{
		{NodeCode: "01.01", Code: "01.01-MAT", Name: "Excavation materials", CostType: "MATERIAL", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
		{NodeCode: "01.01", Code: "01.01-LAB", Name: "Excavation labour", CostType: "LABOUR", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), ValidTo: ptrTime(time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC))},
		{NodeCode: "01.01", Code: "01.01-PLT", Name: "Excavation plant", CostType: "PLANT", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	v1, ids, err := f.svc.ProposeWBSVersion(f.ctx, pm, f.project, "Initial tender WBS", nodes, codes)
	if err != nil {
		t.Fatal(err)
	}
	mat, lab, plt := ids["01.01/01.01-MAT"], ids["01.01/01.01-LAB"], ids["01.01/01.01-PLT"]
	coded := func(k, cc string) ledger.Journal {
		j := f.balanced(k)
		j.Lines[0].CostCodeID = cc
		return j
	}
	// Not yet approved.
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, coded(key("draftwbs"), mat)); !errors.Is(err, postgres.ErrLineRejected) {
		t.Fatalf("code of a DRAFT WBS accepted: %v", err)
	}
	// Maker/checker on the WBS.
	if err := f.svc.DecideWBSVersion(f.ctx, pm, v1.ID, true, "approve own"); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("PM approved own WBS: %v", err)
	}
	both := auth.Principal{UserID: "u-pm", TenantID: f.tenant, Roles: []string{"project_manager", "finance_manager"}}
	if err := f.svc.DecideWBSVersion(f.ctx, both, v1.ID, true, "approve own"); !errors.Is(err, auth.ErrSoD) {
		t.Fatalf("maker approved own WBS: %v", err)
	}
	if err := f.svc.DecideWBSVersion(f.ctx, f.appr, v1.ID, true, "tender baseline"); err != nil {
		t.Fatal(err)
	}
	f.lifecycle(t, coded(key("ok"), mat))

	// A second project with its own approved WBS.
	var p2 string
	_ = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		p2, err = postgres.CreateProject(ctx, tx, f.tenant, f.entity, "P-002", "Adigrat Road", "ETB")
		return err
	})
	pm2 := auth.Principal{UserID: "u-pm2", TenantID: f.tenant, Roles: []string{"project_manager"}, ProjectIDs: []string{p2}}
	v2p, ids2, err := f.svc.ProposeWBSVersion(f.ctx, pm2, p2, "Adigrat WBS", nodes[:1], []postgres.CostCode{{NodeCode: "01", Code: "01-MAT", Name: "m", CostType: "MATERIAL", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	_ = f.svc.DecideWBSVersion(f.ctx, f.appr, v2p.ID, true, "baseline p2")
	// PM limited to P-001 cannot propose a WBS for P-002.
	if _, _, err := f.svc.ProposeWBSVersion(f.ctx, pm, p2, "out of scope", nodes, nil); !errors.Is(err, auth.ErrForbidden) {
		t.Fatalf("PM proposed WBS outside scope: %v", err)
	}

	for name, cc := range map[string]string{
		"unknown code":            uuid.NewString(),
		"other project's code":    ids2["01/01-MAT"],
		"expired code (to 06-30)": lab,
	} {
		if _, err := f.svc.CreateJournal(f.ctx, f.prep, coded(key("bad"), cc)); !errors.Is(err, postgres.ErrLineRejected) {
			t.Errorf("SC-10 %s accepted: %v", name, err)
		}
	}
	// Closing a code stops further use.
	if err := f.rawExec(`UPDATE cost_codes SET status='CLOSED' WHERE id=$1::uuid`, plt); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, coded(key("closed"), plt)); !errors.Is(err, postgres.ErrLineRejected) {
		t.Fatalf("closed code accepted: %v", err)
	}
	// Structure of an approved version is frozen.
	if err := f.rawExec(`UPDATE cost_codes SET name='renamed' WHERE id=$1::uuid`, mat); err == nil {
		t.Fatal("approved cost code renamed")
	}
	if err := f.rawExec(`UPDATE cost_codes SET status='ACTIVE' WHERE id=$1::uuid`, plt); err == nil {
		t.Fatal("closed cost code reopened")
	}
	// Superseding: v2 replaces v1; v1 codes become unusable.
	v2, ids3, err := f.svc.ProposeWBSVersion(f.ctx, pm, f.project, "Re-baselined after variation VO-3", nodes,
		[]postgres.CostCode{{NodeCode: "01.01", Code: "01.01-MAT", Name: "Excavation materials", CostType: "MATERIAL", ValidFrom: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DecideWBSVersion(f.ctx, f.appr, v2.ID, true, "variation VO-3 approved"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, coded(key("superseded"), mat)); !errors.Is(err, postgres.ErrLineRejected) {
		t.Fatalf("superseded code accepted: %v", err)
	}
	f.lifecycle(t, coded(key("v2"), ids3["01.01/01.01-MAT"]))

	// Database backstop: raw insert of a superseded code as the tenant role.
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var jid string
		if err := tx.QueryRow(ctx, `INSERT INTO journals(tenant_id,legal_entity_id,project_id,functional_currency,business_event_at,description,source_type,idempotency_key,command_hash,created_by)
			VALUES ($1::uuid,$2::uuid,$3::uuid,'ETB','2026-10-15','raw','MANUAL',$4,'h','a') RETURNING id::text`, f.tenant, f.entity, f.project, key("rawcc")).Scan(&jid); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO journal_lines(journal_id,tenant_id,legal_entity_id,line_no,account_id,side,amount,currency,cost_code_id)
			VALUES ($1::uuid,$2::uuid,$3::uuid,1,$4::uuid,'DEBIT',1,'ETB',$5::uuid)`, jid, f.tenant, f.entity, f.accounts["5000"], mat)
		return err
	})
	if !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("database accepted a superseded cost code: %v", err)
	}

	// Account policy: materials expense requires a cost code on project journals.
	if err := f.svc.SetAccountCostCoding(f.ctx, f.ctrl, f.accounts["5000"], "REQUIRED_ON_PROJECT"); err != nil {
		t.Fatal(err)
	}
	uncoded := f.journal(key("uncoded"),
		ledger.Line{AccountID: f.accounts["5000"], Side: ledger.Debit, Amount: money.MustNew("5.00", "ETB")},
		ledger.Line{AccountID: f.accounts["1000"], Side: ledger.Credit, Amount: money.MustNew("5.00", "ETB")})
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, uncoded); !errors.Is(err, postgres.ErrInvariant) {
		t.Fatalf("uncoded line on a REQUIRED account accepted: %v", err)
	}
	tenantWide := f.journal(key("tw"),
		ledger.Line{AccountID: f.accounts["5000"], Side: ledger.Debit, Amount: money.MustNew("5.00", "ETB")},
		ledger.Line{AccountID: f.accounts["1000"], Side: ledger.Credit, Amount: money.MustNew("5.00", "ETB")})
	tenantWide.ProjectID = ""
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, tenantWide); err != nil {
		t.Fatalf("unassigned journal needlessly refused: %v", err)
	}
	// A cost code on a journal without a project is refused in Go.
	tenantWide.IdempotencyKey = key("tw2")
	tenantWide.Lines[0].CostCodeID = ids3["01.01/01.01-MAT"]
	if _, err := f.svc.CreateJournal(f.ctx, f.prep, tenantWide); !errors.Is(err, ledger.ErrBadLine) {
		t.Fatalf("cost code without project accepted: %v", err)
	}
}
