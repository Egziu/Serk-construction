package httpapi

import (
	"testing"
)

const apiPostingDef = `{
  "key": "journal.posting", "title": "Journal approval and posting", "subject": "journal", "mandatory": true,
  "start_permission": "journal.create",
  "steps": [
    {"id": "review", "title": "Finance review", "permission": "journal.approve", "distinct_from": ["initiator", "subject.creator"],
     "sla": "24h", "escalate_to": "approval.high_value", "effect": "journal.approve"},
    {"id": "post", "title": "Controller posts", "permission": "journal.post", "distinct_from": ["initiator", "subject.creator", "step:review"],
     "effect": "journal.post"}
  ],
  "on_reject": "journal.cancel"
}`

func TestAPIWorkflowConsole(t *testing.T) {
	e := newEnv(t)
	owner, prep, fm, ctrl := e.token("owner", "process_owner"), e.token("prep", "accountant"), e.token("fm", "finance_manager"), e.token("ctrl", "controller")
	code := func(out map[string]any) any { return out["error"].(map[string]any)["code"] }

	if st, out := e.do("POST", "/v1/workflow/definitions", owner, `{"key":"x.y","title":"t","subject":"journal","mandatory":false,"start_permission":"journal.create","steps":[{"id":"a","title":"a","permission":"god.mode"}]}`); st != 422 || code(out) != "validation" {
		t.Fatalf("unsafe definition: %d %v", st, out)
	}
	st, out := e.do("POST", "/v1/workflow/definitions", owner, apiPostingDef)
	if st != 201 {
		t.Fatalf("propose: %d %v", st, out)
	}
	def := out["id"].(string)
	if st, out := e.do("POST", "/v1/workflow/definitions/"+def+"/publish", e.token("cfo", "cfo"), nil); st != 401 {
		t.Fatalf("publish without MFA: %d %v", st, out)
	}
	if st, out := e.do("POST", "/v1/workflow/definitions/"+def+"/publish", e.mfaToken("cfo", "cfo"), nil); st != 200 {
		t.Fatalf("publish: %d %v", st, out)
	}
	st, out = e.do("POST", "/v1/journals", prep, e.journalBody("wf-api-1", "250.00"))
	if st != 201 {
		t.Fatalf("create: %d %v", st, out)
	}
	jid := out["id"].(string)
	if st, out := e.do("POST", "/v1/journals/"+jid+"/approve", fm, nil); st != 409 || code(out) != "workflow_required" {
		t.Fatalf("direct approve: %d %v", st, out)
	}
	if st, out := e.do("POST", "/v1/workflow/definitions/"+def+"/simulate", fm, map[string]any{"subject_id": jid}); st != 200 || out["dry_run"] != true || len(out["steps"].([]any)) != 2 {
		t.Fatalf("simulate: %d %v", st, out)
	}
	st, out = e.do("POST", "/v1/workflow/instances", prep, map[string]any{"definition_key": "journal.posting", "subject_id": jid})
	if st != 201 {
		t.Fatalf("start: %d %v", st, out)
	}
	inst := out["id"].(string)
	st, out = e.do("GET", "/v1/workflow/tasks", fm, nil)
	if st != 200 || len(out["tasks"].([]any)) != 1 {
		t.Fatalf("tasks: %d %v", st, out)
	}
	if st, out := e.do("POST", "/v1/workflow/instances/"+inst+"/approve", prep, nil); st != 403 {
		t.Fatalf("preparer decided: %d %v", st, out)
	}
	if st, out := e.do("POST", "/v1/workflow/instances/"+inst+"/approve", fm, nil); st != 200 || out["effect_executed"] != "journal.approve" {
		t.Fatalf("review: %d %v", st, out)
	}
	if st, out := e.do("POST", "/v1/workflow/instances/"+inst+"/approve", ctrl, nil); st != 200 || out["effect_executed"] != "journal.post" {
		t.Fatalf("post step: %d %v", st, out)
	}
	if st, out := e.do("GET", "/v1/journals/"+jid, prep, nil); st != 200 || out["status"] != "POSTED" {
		t.Fatalf("journal: %d %v", st, out)
	}
	if st, out := e.do("POST", "/v1/workflow/instances/"+inst+"/approve", ctrl, nil); st != 409 || code(out) != "invalid_state" {
		t.Fatalf("decide completed: %d %v", st, out)
	}
	// Rejection needs a reason and cancels the journal (on_reject).
	_, out = e.do("POST", "/v1/journals", prep, e.journalBody("wf-api-2", "250.00"))
	j2 := out["id"].(string)
	_, out = e.do("POST", "/v1/workflow/instances", prep, map[string]any{"definition_key": "journal.posting", "subject_id": j2})
	i2 := out["id"].(string)
	if st, out := e.do("POST", "/v1/workflow/instances/"+i2+"/reject", fm, nil); st != 422 {
		t.Fatalf("reject without reason: %d %v", st, out)
	}
	if st, out := e.do("POST", "/v1/workflow/instances/"+i2+"/reject", fm, map[string]any{"reason": "no supporting invoice"}); st != 200 || out["effect_executed"] != "journal.cancel" {
		t.Fatalf("reject: %d %v", st, out)
	}
	st, out = e.do("GET", "/v1/workflow/instances/"+inst, fm, nil)
	if st != 200 || len(out["history"].([]any)) != 8 {
		t.Fatalf("instance detail: %d %v", st, out)
	}
	st, out = e.do("GET", "/v1/workflow/metrics", e.token("aud", "auditor"), nil)
	m, _ := out["metrics"].(map[string]any)
	if st != 200 || m["completed"] != float64(1) || m["rejected"] != float64(1) {
		t.Fatalf("metrics: %d %v", st, out)
	}
	if st, _ := e.do("GET", "/v1/workflow/instances?status=ACTIVE", fm, nil); st != 200 {
		t.Fatalf("list: %d", st)
	}
}
