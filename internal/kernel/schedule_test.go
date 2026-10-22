package kernel

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/pkg/auth"
)

func d(s string) time.Time { t, _ := time.Parse("2006-01-02", s); return t }

// scheduleInput is the textbook network on a Monday-Saturday calendar
// starting Monday 2026-10-05 (all on the project's 01-MAT cost code, whose
// approved BOQ budget is 12,100,000):
//
//	A(3) 1,000,000 -> B(4) 2,000,000 -> D(5) 3,000,000 -> E(1) 0;  A -> C(2) 500,000 -> E
//	A 0-3, B 3-7, C 3-5 (float 7), D 7-12, E 12-13; finish day 12 = Mon 2026-10-19.
func (w *p2pWorld) scheduleInput() ScheduleInput {
	act := func(code, name string, dur int, budget string) ScheduleActivity {
		a := ScheduleActivity{Code: code, Name: name, Duration: dur, Budget: dec(budget)}
		if budget != "0" {
			a.CostCodeID = w.costCode
		}
		return a
	}
	return ScheduleInput{ProjectID: w.f.project, Description: "Tender programme rev A", StartDate: d("2026-10-05"), Weekdays: []int{1, 2, 3, 4, 5, 6},
		Activities: []ScheduleActivity{act("A", "Mobilisation and setting out", 3, "1000000"), act("B", "Excavation", 4, "2000000"),
			act("C", "Drainage", 2, "500000"), act("D", "Foundations", 5, "3000000"), act("E", "Handover", 1, "0")},
		Links: []ScheduleLink{{"A", "B", "FS", 0}, {"A", "C", "FS", 0}, {"B", "D", "FS", 0}, {"C", "E", "FS", 0}, {"D", "E", "FS", 0}}}
}

func TestScheduleBaselineProgressEVM(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	now := time.Now()
	planner := auth.Principal{Kind: auth.KindHuman, UserID: "u-planner", TenantID: f.tenant, Roles: []string{"planner"}, ProjectIDs: []string{f.project}, IssuedAt: now.Add(-time.Minute)}

	// Input controls.
	cyc := w.scheduleInput()
	cyc.Links = append(cyc.Links, ScheduleLink{"E", "A", "FS", 0})
	_, err := f.svc.CreateSchedule(f.ctx, planner, cyc)
	arDenied(t, "a network with a cycle", err, "cycle")
	sun := w.scheduleInput()
	sun.StartDate = d("2026-10-04")
	_, err = f.svc.CreateSchedule(f.ctx, planner, sun)
	arDenied(t, "a schedule starting on a non-working day", err, "non-working")
	_, err = f.svc.CreateSchedule(f.ctx, c.store, w.scheduleInput())
	arDenied(t, "a schedule by someone without schedule.manage", err, "forbidden")
	over := w.scheduleInput()
	over.Activities[3].Budget = dec("12000000")
	big, err := f.svc.CreateSchedule(f.ctx, planner, over)
	must(t, "over-budget draft", err)
	arDenied(t, "activity budgets beyond the BOQ", f.svc.SubmitSchedule(f.ctx, planner, big), "exceed its approved BOQ budget")

	v1, err := f.svc.CreateSchedule(f.ctx, planner, w.scheduleInput())
	must(t, "schedule", err)
	var finish time.Time
	var critical, floatC int
	must(t, "computed", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT finish_date FROM schedule_versions WHERE id = $1::uuid`, v1).Scan(&finish); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FILTER (WHERE critical), max(total_float) FILTER (WHERE code = 'C') FROM schedule_activities WHERE version_id = $1::uuid`, v1).
			Scan(&critical, &floatC)
	}))
	if finish.Format("2006-01-02") != "2026-10-19" || critical != 4 || floatC != 7 {
		t.Errorf("computed schedule: finish %s, %d critical, C float %d; want 2026-10-19, 4, 7", finish.Format("2006-01-02"), critical, floatC)
	}

	// The database re-verifies the critical path: a tampered date is refused at submission.
	tampered, err := f.svc.CreateSchedule(f.ctx, planner, w.scheduleInput())
	must(t, "second draft", err)
	must(t, "tamper", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE schedule_activities SET es = 2, ef = 6, total_float = 1 WHERE version_id = $1::uuid AND code = 'B'`, tampered)
		return err
	}))
	arDenied(t, "submitting a schedule whose dates were altered", f.svc.SubmitSchedule(f.ctx, planner, tampered), "critical path equations")

	// A required finish the network cannot meet shows as negative float; the
	// database verifies the late dates against it too.
	req := w.scheduleInput()
	rf := d("2026-10-14")
	req.RequiredFinish = &rf
	tight, err := f.svc.CreateSchedule(f.ctx, planner, req)
	must(t, "required-finish draft", err)
	var minFloat int
	must(t, "negative float", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT min(total_float) FROM schedule_activities WHERE version_id = $1::uuid`, tight).Scan(&minFloat)
	}))
	if minFloat != -4 {
		t.Errorf("float against a required finish of day 8: %d, want -4", minFloat)
	}
	must(t, "required-finish submit (database verifies)", f.svc.SubmitSchedule(f.ctx, planner, tight))
	must(t, "reject the tight programme", f.svc.DecideSchedule(f.ctx, c.pm, tight, false, "Finish date not achievable"))

	must(t, "submit", f.svc.SubmitSchedule(f.ctx, planner, v1))
	both := planner
	both.Roles = append([]string{"project_manager"}, both.Roles...)
	arDenied(t, "self-approval of a schedule", f.svc.DecideSchedule(f.ctx, both, v1, true, ""), "segregation of duties")
	ai := c.pm
	ai.UserID, ai.Kind = "u-pm-assistant", auth.KindAI
	arDenied(t, "baseline approval by an AI principal", f.svc.DecideSchedule(f.ctx, ai, v1, true, ""), "reserved to human principals")
	arDenied(t, "baseline approval by the planner", f.svc.DecideSchedule(f.ctx, planner, v1, true, ""), "forbidden")
	must(t, "baseline", f.svc.DecideSchedule(f.ctx, c.pm, v1, true, ""))

	// Progress at Wed 2026-10-14 (working day 8): A and B done, C 50%, D 20%.
	pct := func(code, p, start, fin string) ProgressLine {
		l := ProgressLine{ActivityCode: code, PercentComplete: dec(p)}
		if start != "" {
			s := d(start)
			l.ActualStart = &s
		}
		if fin != "" {
			x := d(fin)
			l.ActualFinish = &x
		}
		return l
	}
	_, err = f.svc.RecordProgress(f.ctx, planner, f.project, d("2026-10-14"), []ProgressLine{pct("C", "100", "2026-10-08", "")})
	arDenied(t, "100 percent without an actual finish", err, "schedule_progress_finished")
	pr, err := f.svc.RecordProgress(f.ctx, planner, f.project, d("2026-10-14"), []ProgressLine{
		pct("A", "100", "2026-10-05", "2026-10-07"), pct("B", "100", "2026-10-08", "2026-10-13"), pct("C", "50", "2026-10-08", ""), pct("D", "20", "2026-10-14", "")})
	must(t, "progress", err)
	arDenied(t, "progress approved by the planner", f.svc.DecideProgress(f.ctx, planner, pr, true, ""), "forbidden")
	must(t, "progress approve", f.svc.DecideProgress(f.ctx, c.pm, pr, true, ""))

	ev, err := f.svc.ScheduleEVM(f.ctx, c.pm, f.project, d("2026-10-14"))
	must(t, "evm", err)
	// PV: A 1,000,000 + B 2,000,000 + C 500,000 + D 3,000,000 x 2/5 = 4,700,000.
	// EV: 1,000,000 + 2,000,000 + 250,000 + 600,000 = 3,850,000; SPI 0.8191.
	if !ev.BAC.Equal(dec("6500000")) || !ev.PV.Equal(dec("4700000")) || !ev.EV.Equal(dec("3850000")) || !ev.SV.Equal(dec("-850000")) ||
		ev.SPI == nil || !ev.SPI.Equal(dec("0.8191")) || ev.CPI != nil {
		t.Errorf("EVM at 2026-10-14: %+v (SPI %v)", ev, ev.SPI)
	}
	t.Logf("EVM at 2026-10-14: BAC %s PV %s EV %s SV %s SPI %s AC %s", ev.BAC, ev.PV, ev.EV, ev.SV, ev.SPI, ev.AC)

	// Progress never goes backwards, and is reported forward in time.
	back, err := f.svc.RecordProgress(f.ctx, planner, f.project, d("2026-10-16"), []ProgressLine{pct("D", "10", "2026-10-14", "")})
	must(t, "backwards draft", err)
	arDenied(t, "percent complete going backwards", f.svc.DecideProgress(f.ctx, c.pm, back, true, ""), "goes back")
	must(t, "reject backwards", f.svc.DecideProgress(f.ctx, c.pm, back, false, "Percent complete cannot fall"))
	_, err = f.svc.RecordProgress(f.ctx, planner, f.project, d("2026-10-12"), []ProgressLine{pct("D", "30", "2026-10-12", "")})
	arDenied(t, "a status date before the last approved one", err, "reported forward")
	_, err = f.svc.RecordProgress(f.ctx, planner, f.project, time.Now().AddDate(0, 0, 3), []ProgressLine{pct("D", "30", "2026-10-14", "")})
	arDenied(t, "a future status date", err, "between the schedule start and today")

	// A new baseline supersedes the first; progress then refers to it.
	rev := w.scheduleInput()
	rev.Description = "Programme rev B (foundations re-sequenced)"
	rev.Activities[3].Duration = 7
	v2, err := f.svc.CreateSchedule(f.ctx, planner, rev)
	must(t, "rev B", err)
	must(t, "rev B submit", f.svc.SubmitSchedule(f.ctx, planner, v2))
	must(t, "rev B baseline", f.svc.DecideSchedule(f.ctx, c.pm, v2, true, ""))
	var st1, st2 string
	must(t, "statuses", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT (SELECT status FROM schedule_versions WHERE id = $1::uuid), (SELECT status FROM schedule_versions WHERE id = $2::uuid)`, v1, v2).Scan(&st1, &st2)
	}))
	if st1 != "SUPERSEDED" || st2 != "BASELINE" {
		t.Errorf("after rev B: v1 %s, v2 %s", st1, st2)
	}
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE schedule_versions SET status = 'SUPERSEDED' WHERE id = $1::uuid`, v2)
		return err
	})
	arDenied(t, "superseding a baseline directly", err, "only by the approval of the next one")
}
