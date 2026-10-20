package auth

import (
	"errors"
	"testing"
)

func TestDefaultRolesSeparateDuties(t *testing.T) {
	a := NewAuthorizer(nil, true)
	for name := range DefaultRoles {
		p := Principal{UserID: "u", TenantID: "t", Roles: []string{name}}
		n := 0
		for _, perm := range []Permission{PermJournalCreate, PermJournalApprove, PermJournalPost} {
			if a.Has(p, perm) {
				n++
			}
		}
		if n > 1 {
			t.Fatalf("role %s holds %d of create/approve/post", name, n)
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

func TestProjectABAC(t *testing.T) {
	a := NewAuthorizer(nil, true)
	pm := Principal{UserID: "u", TenantID: "t", Roles: []string{"project_manager"}, ProjectIDs: []string{"p1"}}
	if err := a.RequireProject(pm, PermJournalRead, "t", "p1"); err != nil {
		t.Fatal(err)
	}
	if err := a.RequireProject(pm, PermJournalRead, "t", "p2"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("project restriction bypassed: %v", err)
	}
	all := Principal{UserID: "u", TenantID: "t", Roles: []string{"project_manager"}}
	if err := a.RequireProject(all, PermJournalRead, "t", "p2"); err != nil {
		t.Fatal("unrestricted principal denied")
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
}
