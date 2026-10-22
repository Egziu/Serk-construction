package auth

import (
	"errors"
	"testing"
	"time"
)

func TestDefaultRolesSeparateDuties(t *testing.T) {
	a := NewAuthorizer(nil, true)
	conflicts := [][]Permission{
		{PermJournalCreate, PermJournalApprove, PermJournalPost},
		{PermFXManage, PermFXApprove},
		{PermFXManage, PermFXPolicyApprove},
		{PermWorkflowDefine, PermWorkflowPublish},
		{PermPeriodClose, PermPeriodReopen},
		{PermWBSManage, PermWBSApprove},
		{PermSupplierManage, PermSupplierApprove}, {PermSupplierManage, PermSupplierBankApprove},
		{PermBankAcctManage, PermBankAcctApprove}, {PermBOQManage, PermBOQApprove}, {PermPRCreate, PermPRApprove},
		{PermRFQManage, PermRFQAward}, {PermRFQManage, PermRFQEvaluate}, {PermPOManage, PermPOApprove},
		{PermGRNCreate, PermGRNConfirm}, {PermAPEnter, PermAPApprove}, {PermAPEnter, PermAPApproveException},
		{PermPaymentPrepare, PermPaymentApprove}, {PermPaymentApprove, PermPaymentRelease}, {PermPaymentRelease, PermBankReconcile},
		{PermP2PPolicyManage, PermP2PPolicyApprove}, {PermBankImport, PermBankReconcile},
		{PermBankImport, PermPaymentPrepare}, {PermBankImport, PermPaymentApprove}, {PermBankImport, PermPaymentRelease},
		{PermCustomerManage, PermCustomerApprove}, {PermContractPolicyManage, PermContractPolicyApprove}, {PermContractManage, PermContractApprove},
		{PermMeasureCreate, PermMeasureVerify}, {PermIPCPrepare, PermIPCCertify}, {PermARInvoiceCreate, PermARInvoiceApprove},
		{PermARReceiptCreate, PermARReceiptConfirm}, {PermARCreditCreate, PermARCreditApprove}, {PermBankImport, PermARReceiptConfirm}, {PermBankImport, PermARReceiptCreate},
		{PermStockItemManage, PermStockItemApprove}, {PermStockIssue, PermStockIssueApprove}, {PermStockCount, PermStockAdjustApprove},
		{PermGRNCreate, PermStockIssueApprove},
	}
	for name := range DefaultRoles {
		p := Principal{UserID: "u", TenantID: "t", Roles: []string{name}}
		for _, set := range conflicts {
			n := 0
			for _, perm := range set {
				if a.Has(p, perm) {
					n++
				}
			}
			if n > 1 {
				t.Fatalf("role %s holds %d of %v", name, n, set)
			}
		}
	}
}

func TestRequire(t *testing.T) {
	a := NewAuthorizer(nil, true)
	acc := Principal{UserID: "u1", TenantID: "t1", Roles: []string{"accountant"}}
	if err := a.Require(acc, PermJournalCreate, "t1"); err != nil {
		t.Fatal(err)
	}
	if err := a.Require(acc, PermJournalPost, "t1"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("want forbidden got %v", err)
	}
	if err := a.Require(acc, PermJournalCreate, "t2"); !errors.Is(err, ErrTenantMismatch) {
		t.Fatalf("want tenant mismatch got %v", err)
	}
	if err := a.Require(Principal{}, PermJournalRead, ""); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("want unauthenticated got %v", err)
	}
	unknownRole := Principal{UserID: "u", TenantID: "t", Roles: []string{"ghost"}}
	if len(a.Permissions(unknownRole)) != 0 {
		t.Fatal("unknown role granted permissions")
	}
}

// SC-05: tenant-wide access is an explicit entitlement, never implied by an
// empty project list, and a project-limited session never reaches
// unassigned (tenant-wide) records.
func TestScopeSC05(t *testing.T) {
	a := NewAuthorizer(nil, true)
	cases := []struct {
		name    string
		p       Principal
		project string
		allowed bool
	}{
		{"tenant-wide accountant, unassigned", Principal{Roles: []string{"accountant"}}, "", true},
		{"tenant-wide accountant, any project", Principal{Roles: []string{"accountant"}}, "p9", true},
		{"accountant limited to p1, unassigned", Principal{Roles: []string{"accountant"}, ProjectIDs: []string{"p1"}}, "", false},
		{"accountant limited to p1, p1", Principal{Roles: []string{"accountant"}, ProjectIDs: []string{"p1"}}, "p1", true},
		{"accountant limited to p1, p2", Principal{Roles: []string{"accountant"}, ProjectIDs: []string{"p1"}}, "p2", false},
		{"project accountant, no projects, unassigned", Principal{Roles: []string{"project_accountant"}}, "", false},
		{"project accountant, no projects, p1", Principal{Roles: []string{"project_accountant"}}, "p1", false},
		{"project accountant, p1+p2 mixed, p2", Principal{Roles: []string{"project_accountant"}, ProjectIDs: []string{"p1", "p2"}}, "p2", true},
		{"project accountant, p1+p2 mixed, unassigned", Principal{Roles: []string{"project_accountant"}, ProjectIDs: []string{"p1", "p2"}}, "", false},
		{"inherited roles: PM + accountant limited to p1, unassigned", Principal{Roles: []string{"project_manager", "accountant"}, ProjectIDs: []string{"p1"}}, "", false},
	}
	for _, c := range cases {
		c.p.UserID, c.p.TenantID = "u", "t"
		perm := PermJournalCreate
		err := a.RequireProject(c.p, perm, "t", c.project)
		if c.allowed && err != nil {
			t.Errorf("%s: denied: %v", c.name, err)
		}
		if !c.allowed && !errors.Is(err, ErrForbidden) {
			t.Errorf("%s: allowed (err=%v)", c.name, err)
		}
	}
	// Read access follows the same scope rule.
	pm := Principal{UserID: "u", TenantID: "t", Roles: []string{"project_manager"}, ProjectIDs: []string{"p1"}}
	if err := a.RequireProject(pm, PermJournalRead, "t", ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("scoped PM read an unassigned journal: %v", err)
	}
}

func TestStepUp(t *testing.T) {
	a := NewAuthorizer(nil, true)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }
	if err := a.RequireStepUp(Principal{MFA: false, AuthTime: now}); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("no-MFA session passed step-up")
	}
	if err := a.RequireStepUp(Principal{MFA: true, AuthTime: now.Add(-11 * time.Minute)}); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("stale MFA passed step-up")
	}
	if err := a.RequireStepUp(Principal{MFA: true}); !errors.Is(err, ErrStepUpRequired) {
		t.Fatal("MFA without auth_time passed step-up")
	}
	if err := a.RequireStepUp(Principal{MFA: true, AuthTime: now.Add(-2 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
}

func TestSoD(t *testing.T) {
	strict := NewAuthorizer(nil, true)
	prep := Principal{UserID: "prep", TenantID: "t"}
	appr := Principal{UserID: "appr", TenantID: "t"}
	post := Principal{UserID: "post", TenantID: "t"}

	if err := strict.CheckSoDApprove(prep, JournalActors{CreatedBy: "prep"}); !errors.Is(err, ErrSoD) {
		t.Fatal("self-approval allowed")
	}
	if err := strict.CheckSoDApprove(appr, JournalActors{CreatedBy: "prep"}); err != nil {
		t.Fatal(err)
	}
	if err := strict.CheckSoDPost(appr, JournalActors{CreatedBy: "prep", ApprovedBy: "appr"}); !errors.Is(err, ErrSoD) {
		t.Fatal("approver posting allowed under strict mode")
	}
	if err := strict.CheckSoDPost(prep, JournalActors{CreatedBy: "prep", ApprovedBy: "appr"}); !errors.Is(err, ErrSoD) {
		t.Fatal("preparer posting allowed under strict mode")
	}
	if err := strict.CheckSoDPost(post, JournalActors{CreatedBy: "prep", ApprovedBy: "appr"}); err != nil {
		t.Fatal(err)
	}
	if err := strict.CheckSoDPost(post, JournalActors{CreatedBy: "prep"}); !errors.Is(err, ErrSoD) {
		t.Fatal("posting without approver allowed")
	}
	relaxed := NewAuthorizer(nil, false)
	if err := relaxed.CheckSoDPost(appr, JournalActors{CreatedBy: "prep", ApprovedBy: "appr"}); err != nil {
		t.Fatal("two-person rule should permit approver to post")
	}
	if err := CheckMakerChecker(Principal{UserID: "m"}, "m", "rate"); !errors.Is(err, ErrSoD) {
		t.Fatal("maker approved own record")
	}
}

// A tenant-defined role can never grant a platform-derived permission.
func TestReservedPermissionsNotGrantableByRoles(t *testing.T) {
	a := NewAuthorizer(map[string]Role{"bot": {Name: "bot", Permissions: []Permission{"principal.human", PermPaymentApprove}}}, true)
	p := Principal{UserID: "svc-x", TenantID: "t", Roles: []string{"bot"}}
	for _, perm := range a.Permissions(p) {
		if perm == "principal.human" {
			t.Fatal("role granted principal.human")
		}
	}
	if !a.Has(p, PermPaymentApprove) {
		t.Fatal("ordinary permission lost")
	}
}
