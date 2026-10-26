package automation

import (
	"strings"
	"testing"
)

func TestParseAcceptsEveryCatalogueKind(t *testing.T) {
	for _, body := range []string{
		`{"when":{"kind":"document_stale","subject":"supplier_invoice","status":"SUBMITTED","hours":48},"then":{"notify_role":"ap_supervisor","severity":"warn"}}`,
		`{"when":{"kind":"invoice_due","days":7},"then":{"notify_role":"treasury_officer","severity":"info","title":"Invoices falling due"}}`,
		`{"when":{"kind":"receivable_overdue","days":30},"then":{"notify_role":"ar_supervisor","severity":"warn"}}`,
		`{"when":{"kind":"po_overdue"},"then":{"notify_role":"procurement_manager","severity":"warn"}}`,
		`{"when":{"kind":"budget_threshold","percent":90},"then":{"notify_role":"project_manager","severity":"critical"}}`,
		`{"when":{"kind":"stock_below","item_code":"CEM-OPC50","quantity":"500"},"then":{"notify_role":"storekeeper","severity":"info"}}`,
		`{"when":{"kind":"schedule_risk","ratio":"0.9"},"then":{"notify_role":"planner","severity":"warn"}}`,
		`{"when":{"kind":"cost_risk","ratio":"0.95"},"then":{"notify_user":"u-cfo","severity":"critical"}}`,
		`{"when":{"kind":"export_volume","count":50},"then":{"notify_role":"security_admin","severity":"critical"}}`,
	} {
		if _, err := Parse([]byte(body)); err != nil {
			t.Errorf("%s: %v", body, err)
		}
	}
}

func TestParseRefusesWhatTheCatalogueDoesNotOffer(t *testing.T) {
	for name, body := range map[string]string{
		"unknown kind":        `{"when":{"kind":"approve_everything"},"then":{"notify_role":"cfo","severity":"info"}}`,
		"unknown field":       `{"when":{"kind":"po_overdue"},"then":{"notify_role":"cfo","severity":"info","approve":true}}`,
		"action field":        `{"when":{"kind":"po_overdue"},"then":{"notify_role":"cfo","severity":"info","action":"approve"}}`,
		"no recipient":        `{"when":{"kind":"po_overdue"},"then":{"severity":"info"}}`,
		"bad severity":        `{"when":{"kind":"po_overdue"},"then":{"notify_role":"cfo","severity":"loud"}}`,
		"stale without hours": `{"when":{"kind":"document_stale","subject":"grn","status":"DRAFT"},"then":{"notify_role":"cfo","severity":"info"}}`,
		"percent zero":        `{"when":{"kind":"budget_threshold","percent":0},"then":{"notify_role":"cfo","severity":"info"}}`,
		"negative stock":      `{"when":{"kind":"stock_below","item_code":"X-1","quantity":"-1"},"then":{"notify_role":"cfo","severity":"info"}}`,
		"ratio zero":          `{"when":{"kind":"cost_risk","ratio":"0"},"then":{"notify_role":"cfo","severity":"info"}}`,
		"role injection":      `{"when":{"kind":"po_overdue"},"then":{"notify_role":"cfo; drop","severity":"info"}}`,
		"trailing":            `{"when":{"kind":"po_overdue"},"then":{"notify_role":"cfo","severity":"info"}} {}`,
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDedupeKey(t *testing.T) {
	a := DedupeKey("AP-STALE", Finding{SubjectType: "supplier_invoice", SubjectID: "i1"})
	b := DedupeKey("AP-STALE", Finding{SubjectType: "supplier_invoice", SubjectID: "i1", Key: "2026-10-26"})
	if a == b || !strings.HasPrefix(b, a) {
		t.Fatal(a, b)
	}
	for _, k := range Kinds {
		if Describe(k) == "" {
			t.Errorf("%s has no description", k)
		}
	}
}
