package workflow

import (
	"errors"
	"strings"
	"testing"

	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/money"
)

var testCatalog = Catalog{
	Actions: map[string]Action{
		"journal.approve": {Name: "journal.approve", Subject: "journal", Sensitive: true, Permission: auth.PermJournalApprove},
		"journal.post":    {Name: "journal.post", Subject: "journal", Sensitive: true, Permission: auth.PermJournalPost},
		"journal.cancel":  {Name: "journal.cancel", Subject: "journal", Sensitive: false, Permission: auth.PermJournalApprove},
		"period.close":    {Name: "period.close", Subject: "fiscal_period", Sensitive: true, Permission: auth.PermPeriodClose},
	},
	Permissions: map[auth.Permission]bool{auth.PermJournalCreate: true, auth.PermJournalApprove: true, auth.PermJournalPost: true,
		auth.PermPeriodClose: true, "approval.high_value": true, auth.PermWorkflowAdmin: true},
	Subjects: map[string]bool{"journal": true, "fiscal_period": true},
}

const posting = `{
  "key": "journal.posting", "title": "Journal posting", "subject": "journal", "mandatory": true,
  "start_permission": "journal.create",
  "steps": [
    {"id": "review", "title": "Finance review", "permission": "journal.approve",
     "distinct_from": ["initiator", "subject.creator"], "sla": "24h", "escalate_to": "approval.high_value",
     "expire_after": "168h", "effect": "journal.approve"},
    {"id": "executive", "title": "Executive sign-off", "permission": "approval.high_value", "approvals": 2,
     "require_mfa": true, "when": [{"amount_gte": "1000000.00", "currency": "ETB"}, {"amount_gte": "20000.00", "currency": "USD"}],
     "distinct_from": ["initiator", "subject.creator", "step:review"]},
    {"id": "post", "title": "Controller posts", "permission": "journal.post",
     "distinct_from": ["initiator", "subject.creator", "step:review"], "effect": "journal.post"}
  ],
  "on_reject": "journal.cancel"
}`

func TestValidDefinitionAndRouting(t *testing.T) {
	d, err := Parse([]byte(posting), testCatalog)
	if err != nil {
		t.Fatal(err)
	}
	small := money.MustNew("250000.00", "ETB")
	big := money.MustNew("1000000.00", "ETB")
	r, _ := d.Route(Facts{Amount: &small})
	if len(r) != 2 || r[0].ID != "review" || r[1].ID != "post" {
		t.Fatalf("small route %+v", r)
	}
	r, _ = d.Route(Facts{Amount: &big})
	if len(r) != 3 || r[1].ID != "executive" || r[1].Approvals != 2 || r[0].Approvals != 1 {
		t.Fatalf("big route %+v", r)
	}
	sim, _ := d.Simulate(Facts{Amount: &big})
	if !strings.Contains(sim[1].Reason, "≥ threshold 1000000.00 ETB") || !sim[1].RequireMFA {
		t.Fatalf("simulation %+v", sim[1])
	}
	usd := money.MustNew("20000.00", "USD")
	if r, err := d.Route(Facts{Amount: &usd}); err != nil || len(r) != 3 {
		t.Fatalf("USD threshold: %+v %v", r, err)
	}
	eur := money.MustNew("5000000.00", "EUR")
	if _, err := d.Route(Facts{Amount: &eur}); !errors.Is(err, ErrConditionCurrency) {
		t.Fatalf("threshold silently compared across currencies: %v", err)
	}
}

// The validator is the guarantee that a workflow cannot weaken controls.
// Each case must fail for its own reason (asserted by message), so a case
// cannot pass merely because some other rule happens to fire.
func TestValidatorRefusesUnsafeDefinitions(t *testing.T) {
	type tc struct {
		mutate func(string) string
		want   string
	}
	rep := func(old, new string) func(string) string {
		return func(s string) string {
			if !strings.Contains(s, old) {
				t.Fatalf("fixture drift: %q not found", old)
			}
			return strings.Replace(s, old, new, 1)
		}
	}
	cases := map[string]tc{
		"sensitive effect decided by people without that permission": {rep(`"permission": "journal.post",`, `"permission": "journal.approve",`), `requires the step permission to be "journal.post"`},
		"sensitive effect on a threshold step": {rep(`"permission": "approval.high_value", "approvals": 2,`,
			`"permission": "journal.post", "effect": "journal.post", "approvals": 2,`), "cannot sit on a conditional step"},
		"sensitive on_reject":                   {rep(`"on_reject": "journal.cancel"`, `"on_reject": "journal.post"`), "rejection may only run non-sensitive"},
		"effect for another subject":            {rep(`"effect": "journal.approve"`, `"effect": "period.close"`), "applies to fiscal_period, not journal"},
		"unknown effect":                        {rep(`"effect": "journal.post"`, `"effect": "payment.release"`), `unknown effect "payment.release"`},
		"SoD on a later step":                   {rep(`"step:review"]},`, `"step:post"]},`), "must be initiator, subject.creator or an EARLIER step"},
		"unknown permission":                    {rep(`"approval.high_value", "approvals"`, `"god.mode", "approvals"`), `unknown permission "god.mode"`},
		"quorum of 9":                           {rep(`"approvals": 2`, `"approvals": 9`), "approvals must be between 1 and 5"},
		"expiry shorter than SLA":               {rep(`"expire_after": "168h"`, `"expire_after": "1h"`), "expire_after must be longer than sla"},
		"SLA without escalation":                {rep(`, "escalate_to": "approval.high_value"`, ``), "an SLA needs a known escalate_to"},
		"unknown field (strict)":                {rep(`"mandatory": true,`, `"mandatory": true, "skip_controls": true,`), "unknown field"},
		"negative threshold":                    {rep(`"1000000.00"`, `"-1"`), "plain non-negative amount"},
		"huge exponent threshold (DoS)":         {rep(`"1000000.00"`, `"1e40000000"`), "plain non-negative amount"},
		"sub-minor threshold":                   {rep(`"1000000.00"`, `"1000000.001"`), "plain non-negative amount"},
		"duplicate threshold currency":          {rep(`{"amount_gte": "20000.00", "currency": "USD"}`, `{"amount_gte": "20000.00", "currency": "ETB"}`), "two thresholds for ETB"},
		"approve quorum may include the maker":  {rep(`"distinct_from": ["initiator", "subject.creator"], "sla"`, `"distinct_from": ["initiator"], "sla"`), `must list "subject.creator"`},
		"post quorum may include the approver":  {rep(`"step:review"], "effect": "journal.post"`, `"subject.creator"], "effect": "journal.post"`), `must list "step:review"`},
		"fractional duration":                   {rep(`"sla": "24h"`, `"sla": "1.5h"`), "duration like 90m"},
		"threshold on a subject without amount": {rep(`"subject": "journal"`, `"subject": "fiscal_period"`), "apply only to subjects with an amount"},
		"mandatory missing journal.post":        {rep(`, "effect": "journal.post"`, ``), "missing [journal.post]"},
		"duplicated effect": {rep(`"permission": "journal.post",
     "distinct_from": ["initiator", "subject.creator", "step:review"], "effect": "journal.post"}`, `"permission": "journal.approve",
     "distinct_from": ["initiator", "subject.creator", "step:review"], "effect": "journal.approve"}`), "already runs at an earlier step"},
	}
	for name, c := range cases {
		_, err := Parse([]byte(c.mutate(posting)), testCatalog)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("unsafe definition accepted: %s", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: refused for the wrong reason: %v", name, err)
		}
	}
}
