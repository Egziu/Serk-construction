package httpapi

import (
	"testing"

	"github.com/shopspring/decimal"
)

// TestAPISchedule_BaselineProgressEVM: the kernel test's textbook network
// (docs/testing/E2E_PLANNING.md) through the HTTP API.
func TestAPISchedule_BaselineProgressEVM(t *testing.T) {
	a := newP2PAPI(t)
	P := []string{a.project}
	estimator, commercial := a.tok("u-estimator", P, false, "estimator"), a.tok("u-commercial", P, false, "commercial_manager")
	planner, pm := a.tok("u-planner", P, false, "planner"), a.tok("u-pm", P, false, "project_manager")
	otherPlanner := a.tok("u-planner-2", []string{"8c1d4c2e-0000-4000-8000-000000000001"}, false, "planner")
	boq := a.id("POST", "/v1/boqs", estimator, map[string]any{"project_id": a.project, "description": "Tender BOQ rev A", "items": []map[string]any{
		{"item_no": "3.1", "description": "Reinforcement steel", "unit": "t", "quantity": "120", "rate": "85000", "cost_code_id": a.costCode}}})
	a.call(200, "POST", "/v1/boqs/"+boq+"/submit", estimator, nil)
	a.call(200, "POST", "/v1/boqs/"+boq+"/approve", commercial, map[string]any{"reason": "priced to tender"})

	act := func(code, name string, dur int, budget string) map[string]any {
		m := map[string]any{"code": code, "name": name, "duration": dur, "budget": budget}
		if budget != "0" {
			m["cost_code_id"] = a.costCode
		}
		return m
	}
	body := map[string]any{"description": "Tender programme rev A", "start_date": "2026-10-05", "working_weekdays": []int{1, 2, 3, 4, 5, 6},
		"activities": []map[string]any{act("A", "Mobilisation", 3, "1000000"), act("B", "Excavation", 4, "2000000"), act("C", "Drainage", 2, "500000"),
			act("D", "Foundations", 5, "3000000"), act("E", "Handover", 1, "0")},
		"links": []map[string]any{{"pred": "A", "succ": "B", "type": "FS"}, {"pred": "A", "succ": "C", "type": "FS"}, {"pred": "B", "succ": "D", "type": "FS"},
			{"pred": "C", "succ": "E", "type": "FS"}, {"pred": "D", "succ": "E", "type": "FS"}}}
	if st, _ := a.do("POST", "/v1/projects/"+a.project+"/schedules", otherPlanner, body); st != 403 {
		t.Errorf("another project's planner creates a schedule: %d", st)
	}
	cyc := map[string]any{}
	for k, v := range body {
		cyc[k] = v
	}
	cyc["links"] = append(body["links"].([]map[string]any), map[string]any{"pred": "E", "succ": "A", "type": "FS"})
	if st, _ := a.do("POST", "/v1/projects/"+a.project+"/schedules", planner, cyc); st != 422 {
		t.Errorf("a cyclic network: %d, want 422", st)
	}
	v := a.id("POST", "/v1/projects/"+a.project+"/schedules", planner, body)
	d := a.call(200, "GET", "/v1/p2p/schedule_version/"+v, pm, nil)["detail"].(map[string]any)
	if h := d["h"].(map[string]any); h["finish_date"] != "2026-10-19" {
		t.Errorf("finish date %v, want 2026-10-19", h["finish_date"])
	}
	a.call(200, "POST", "/v1/schedules/"+v+"/submit", planner, nil)
	if st, _ := a.do("POST", "/v1/schedules/"+v+"/approve", planner, nil); st != 403 {
		t.Errorf("baseline approved by the planner: %d", st)
	}
	a.call(200, "POST", "/v1/schedules/"+v+"/approve", pm, nil)

	pr := a.id("POST", "/v1/projects/"+a.project+"/progress", planner, map[string]any{"status_date": "2026-10-14", "lines": []map[string]any{
		{"activity_code": "A", "percent_complete": "100", "actual_start": "2026-10-05", "actual_finish": "2026-10-07"},
		{"activity_code": "B", "percent_complete": "100", "actual_start": "2026-10-08", "actual_finish": "2026-10-13"},
		{"activity_code": "C", "percent_complete": "50", "actual_start": "2026-10-08"},
		{"activity_code": "D", "percent_complete": "20", "actual_start": "2026-10-14"}}})
	a.call(200, "POST", "/v1/progress/"+pr+"/approve", pm, nil)
	ev := a.call(200, "GET", "/v1/projects/"+a.project+"/evm?status_date=2026-10-14", pm, nil)
	for k, want := range map[string]string{"bac": "6500000", "pv": "4700000", "ev": "3850000", "sv": "-850000", "spi": "0.8191"} {
		if got := decOf(t, ev[k]); !got.Equal(decimal.RequireFromString(want)) {
			t.Errorf("EVM %s: %s, want %s", k, got, want)
		}
	}
	if st, _ := a.do("GET", "/v1/projects/"+a.project+"/evm?status_date=14-10-2026", pm, nil); st != 422 {
		t.Errorf("malformed status date: %d, want 422", st)
	}
	if st, _ := a.do("GET", "/v1/projects/"+a.project+"/evm?status_date=9999-12-31", pm, nil); st != 422 {
		t.Errorf("status date beyond the schedule horizon (R9-F3): %d, want 422", st)
	}
	if st, _ := a.do("GET", "/v1/projects/"+a.project+"/evm", otherPlanner, nil); st != 403 {
		t.Errorf("another project's planner reads the EVM: %d", st)
	}
}
