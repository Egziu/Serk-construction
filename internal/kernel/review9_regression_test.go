package kernel

// Independent review 9 probes (migrations 0026-0029 at 11dcff3).
// "OPEN:" (t.Errorf) = a defect observed; "held:" (t.Logf) = the control worked;
// "info:" = an observation that is not a defect by itself.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

func r9open(t *testing.T, format string, a ...any) { t.Helper(); t.Errorf("OPEN: "+format, a...) }
func r9held(t *testing.T, format string, a ...any) { t.Helper(); t.Logf("held: "+format, a...) }
func r9info(t *testing.T, format string, a ...any) { t.Helper(); t.Logf("info: "+format, a...) }

func r9refused(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		r9open(t, "%s was accepted", what)
		return
	}
	r9held(t, "%s refused: %v", what, err)
}

func r9raw(f *fixture, fn func(ctx context.Context, tx pgx.Tx) error) error {
	return f.app.WithTenant(f.ctx, f.tenant, fn)
}

func r9exec(f *fixture, sql string, args ...any) error {
	return r9raw(f, func(ctx context.Context, tx pgx.Tx) error { _, err := tx.Exec(ctx, sql, args...); return err })
}

func r9dec(t *testing.T, f *fixture, sql string, args ...any) decimal.Decimal {
	t.Helper()
	var v decimal.Decimal
	must(t, "value", r9raw(f, func(ctx context.Context, tx pgx.Tx) error { return tx.QueryRow(ctx, sql, args...).Scan(&v) }))
	return v
}

func r9vo(lines ...VariationLine) VariationInput {
	return VariationInput{Title: "Review 9 variation", Reason: "Client instruction for review probes", ClientInstructionRef: "ERA-VO-R9", ClientInstructionSHA256: voSHA, Lines: lines}
}

// ---------------------------------------------------------------------------
// 0026 variations: races between a reduction and verification, two
// reductions, two NEW lines with the same number.
// ---------------------------------------------------------------------------
func TestR9_VariationRaces(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	inv := func(ctr string) (eff, ver decimal.Decimal) {
		must(t, "qty", r9raw(f, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT contract_line_qty($1::uuid, 3), contract_verified_qty($1::uuid, 3, NULL)`, ctr).Scan(&eff, &ver)
		}))
		return
	}
	for round := 0; round < 3; round++ {
		ctr := w.activeContract(t)
		w.measure(t, 10, "0", "0", "20")
		vo, err := f.svc.CreateVariation(f.ctx, c.commercial, ctr, r9vo(VariationLine{LineNo: 3, Kind: "CHANGE", QtyDelta: dec("-90")}))
		must(t, "vo", err)
		must(t, "vo submit", f.svc.SubmitVariation(f.ctx, c.commercial, vo))
		m, err := f.svc.CreateMeasurement(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), []MeasurementLine{{3, dec("15"), "Bridge"}})
		must(t, "m", err)
		must(t, "m submit", f.svc.SubmitMeasurement(f.ctx, w.ar.qs, m))
		var errV, errM error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); errV = f.svc.DecideVariation(f.ctx, w.mfa(c.cfo), vo, true, "") }()
		go func() { defer wg.Done(); errM = f.svc.DecideMeasurement(f.ctx, c.siteEng, m, true, "") }()
		wg.Wait()
		eff, ver := inv(ctr)
		t.Logf("round %d: reduction -90 (120 -> 30) vs verification of +15 (20 -> 35): variation err=%v; measurement err=%v; effective %s verified %s", round, errV, errM, eff, ver)
		if (errV == nil) == (errM == nil) || ver.GreaterThan(eff) {
			r9open(t, "round %d: both or neither succeeded, or verified %s > effective %s", round, ver, eff)
		} else {
			r9held(t, "round %d: exactly one of the reduction and the verification succeeded; verified %s <= effective %s", round, ver, eff)
		}
	}
	// Two reductions that each fit but not together.
	ctr := w.activeContract(t)
	w.measure(t, 10, "0", "0", "20")
	a, err := f.svc.CreateVariation(f.ctx, c.commercial, ctr, r9vo(VariationLine{LineNo: 3, Kind: "CHANGE", QtyDelta: dec("-60")}))
	must(t, "a", err)
	b, err := f.svc.CreateVariation(f.ctx, c.commercial, ctr, r9vo(VariationLine{LineNo: 3, Kind: "CHANGE", QtyDelta: dec("-60")}))
	must(t, "b", err)
	must(t, "a submit", f.svc.SubmitVariation(f.ctx, c.commercial, a))
	must(t, "b submit", f.svc.SubmitVariation(f.ctx, c.commercial, b))
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = f.svc.DecideVariation(f.ctx, w.mfa(c.cfo), a, true, "") }()
	go func() { defer wg.Done(); errs[1] = f.svc.DecideVariation(f.ctx, w.mfa(c.cfo), b, true, "") }()
	wg.Wait()
	eff, ver := inv(ctr)
	t.Logf("two reductions of -60 on 120 with 20 verified, approved concurrently: %v / %v; effective %s verified %s", errs[0], errs[1], eff, ver)
	if ver.GreaterThan(eff) || (errs[0] == nil && errs[1] == nil) {
		r9open(t, "both reductions approved: effective %s below verified %s", eff, ver)
	} else {
		r9held(t, "one reduction refused; effective %s >= verified %s", eff, ver)
	}
	// Two drafts with the same NEW line number, created concurrently.
	ctr = w.activeContract(t)
	ids := make([]string, 2)
	wg.Add(2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			defer wg.Done()
			ids[i], errs[i] = f.svc.CreateVariation(f.ctx, c.commercial, ctr, r9vo(VariationLine{LineNo: 7, Kind: "NEW", Description: fmt.Sprintf("Lighting %d", i), Unit: "no", QtyDelta: dec("10"), Rate: dec(fmt.Sprint(15000 + i))}))
		}(i)
	}
	wg.Wait()
	t.Logf("two concurrent drafts with NEW line 7: %v / %v", errs[0], errs[1])
	if errs[0] == nil && errs[1] == nil {
		r9info(t, "both drafts with NEW line 7 exist (the uniqueness check at line insert does not serialise)")
		must(t, "s0", f.svc.SubmitVariation(f.ctx, c.commercial, ids[0]))
		must(t, "s1", f.svc.SubmitVariation(f.ctx, c.commercial, ids[1]))
		must(t, "approve first", f.svc.DecideVariation(f.ctx, w.mfa(c.cfo), ids[0], true, ""))
		r9refused(t, "approval of the second variation with the same NEW line number", f.svc.DecideVariation(f.ctx, w.mfa(c.cfo), ids[1], true, ""))
	}
}

// ---------------------------------------------------------------------------
// 0026: raw SQL as the tenant role, scope, human decisions, value math.
// ---------------------------------------------------------------------------
func TestR9_VariationRawSQLAndScope(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	// A variation on a DRAFT contract.
	draft, err := f.svc.CreateContract(f.ctx, c.commercial, w.contractInput())
	must(t, "draft contract", err)
	_, err = f.svc.CreateVariation(f.ctx, c.commercial, draft, r9vo(VariationLine{LineNo: 1, Kind: "CHANGE", QtyDelta: dec("5")}))
	r9refused(t, "a variation on a DRAFT contract", err)

	ctr := w.activeContract(t)
	w.measure(t, 10, "4000", "300", "20")
	vo, err := f.svc.CreateVariation(f.ctx, c.commercial, ctr, r9vo(VariationLine{LineNo: 2, Kind: "CHANGE", QtyDelta: dec("100")}))
	must(t, "vo", err)

	// Column/table privileges and forged prices.
	r9refused(t, "raw UPDATE of value_change", r9exec(f, `UPDATE contract_variations SET value_change = 1 WHERE id = $1::uuid`, vo))
	r9refused(t, "raw UPDATE of a variation line rate", r9exec(f, `UPDATE variation_lines SET rate = 1 WHERE variation_id = $1::uuid`, vo))
	r9refused(t, "raw DELETE of a variation line", r9exec(f, `DELETE FROM variation_lines WHERE variation_id = $1::uuid`, vo))
	r9refused(t, "raw INSERT of a variation (no creation attestation)", r9exec(f, `INSERT INTO contract_variations(contract_id, number, title, reason, client_instruction_ref, client_instruction_sha256, created_by)
		VALUES ($1::uuid, 'VO-RAW', 'Raw variation', 'Raw variation reason', 'RAW-1', $2, 'u-commercial')`, ctr, voSHA))
	errChg := r9exec(f, `INSERT INTO variation_lines(variation_id, line_no, kind, description, unit, qty_delta, rate) VALUES ($1::uuid, 1, 'CHANGE', 'forged', 'zz', 10, 1)`, vo)
	rate := r9dec(t, f, `SELECT COALESCE((SELECT rate FROM variation_lines WHERE variation_id = $1::uuid AND line_no = 1), -1)`, vo)
	if errChg == nil && rate.Equal(dec("350")) {
		r9held(t, "a raw CHANGE line with forged rate 1 was re-priced at the contract rate 350")
	} else if errChg != nil {
		r9held(t, "raw CHANGE line refused: %v", errChg)
	} else {
		r9open(t, "raw CHANGE line kept forged rate %s", rate)
	}
	errNew := r9exec(f, `INSERT INTO variation_lines(variation_id, line_no, kind, description, unit, qty_delta, rate) VALUES ($1::uuid, 8, 'NEW', 'Injected line', 'no', 1, 9999999)`, vo)
	if errNew == nil {
		r9info(t, "the tenant role added a NEW line (rate 9,999,999) to commercial manager's DRAFT variation %s; lines are not bound to the variation's creator until submission", vo[:8])
	} else {
		r9held(t, "raw NEW line into another person's draft refused: %v", errNew)
	}
	r9refused(t, "raw submission", r9exec(f, `UPDATE contract_variations SET status = 'SUBMITTED' WHERE id = $1::uuid`, vo))
	must(t, "submit", f.svc.SubmitVariation(f.ctx, c.commercial, vo))
	value := r9dec(t, f, `SELECT value_change FROM contract_variations WHERE id = $1::uuid`, vo)
	t.Logf("submitted variation value_change %s (100 m3 x 6,500 + injected/CHANGE lines as stored)", value)
	r9refused(t, "raw approval", r9exec(f, `UPDATE contract_variations SET status = 'APPROVED', approved_by = 'u-cfo' WHERE id = $1::uuid`, vo))
	r9refused(t, "raw CANCELLED -> by update of decision_reason only", r9exec(f, `UPDATE contract_variations SET decision_reason = 'changed my mind' WHERE id = $1::uuid`, vo))

	// Scope and human decisions.
	other := w.mfa(r8principal(f, "u-cfo-other", []string{uuid.NewString()}, "cfo"))
	_, errD := f.svc.GetP2PDoc(f.ctx, other, "contract_variation", vo)
	l, _ := f.svc.ListP2PDocs(f.ctx, other, "contract_variation", "", 50)
	if errD == nil || len(l) > 0 {
		r9open(t, "another project's CFO sees the variation: %v, %d rows", errD, len(l))
	} else {
		r9held(t, "another project's CFO: detail %v, list %d rows", errD, len(l))
	}
	r9refused(t, "approval by another project's CFO", f.svc.DecideVariation(f.ctx, other, vo, true, ""))
	svc := w.mfa(c.cfo)
	svc.Kind, svc.UserID = auth.KindService, "svc-cfo"
	r9refused(t, "approval by a service principal", f.svc.DecideVariation(f.ctx, svc, vo, true, ""))
	cm := w.mfa(c.commercial)
	cm.UserID = "u-commercial-2"
	r9refused(t, "approval by a second commercial manager (no contract.approve)", f.svc.DecideVariation(f.ctx, cm, vo, true, ""))
	cm2 := r8principal(f, "u-commercial-3", []string{f.project}, "commercial_manager")
	if err := f.svc.CancelVariation(f.ctx, cm2, vo, "Withdrawn by a colleague"); err == nil {
		r9info(t, "a commercial manager who did not prepare the SUBMITTED variation cancelled it")
	} else {
		r9held(t, "cancel by a non-preparer refused: %v", err)
	}

	// Value math: many small quantity changes vs the effective quantity x rate.
	for i := 0; i < 4; i++ {
		v, err := f.svc.CreateVariation(f.ctx, c.commercial, ctr, r9vo(VariationLine{LineNo: 1, Kind: "CHANGE", QtyDelta: dec("0.0001")}))
		must(t, "small vo", err)
		must(t, "small submit", f.svc.SubmitVariation(f.ctx, c.commercial, v))
		must(t, "small approve", f.svc.DecideVariation(f.ctx, w.mfa(c.cfo), v, true, ""))
	}
	pos, err := f.svc.ContractPosition(f.ctx, c.commercial, ctr)
	must(t, "position", err)
	byQty := r9dec(t, f, `SELECT sum(p2p_round(contract_line_qty($1::uuid, l.line_no) * l.rate, 'ETB')) FROM contract_lines l WHERE l.contract_id = $1::uuid`, ctr)
	t.Logf("info: 4 variations of +0.0001 m3 @ 350: variations approved %s; revised contract value %s; sum(effective qty x rate) %s", pos.VariationsApproved, pos.RevisedContractValue, byQty)

	// 0028 AR date trigger UPDATE paths: only status columns are updatable.
	var cdate, rdate bool
	must(t, "privs", r9raw(f, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT has_column_privilege('customer_credit_notes', 'credit_date', 'UPDATE'), has_column_privilege('retention_releases', 'release_date', 'UPDATE')`).Scan(&cdate, &rdate)
	}))
	if cdate || rdate {
		r9open(t, "the tenant role may UPDATE credit_date=%v release_date=%v", cdate, rdate)
	} else {
		r9held(t, "the tenant role cannot UPDATE credit_date or release_date (the date trigger's UPDATE path is reached only by status changes)")
	}
}

// ---------------------------------------------------------------------------
// 0027 planning: EVM against a hand computation (holiday, SS and FF links,
// non-working status dates), partial progress reports, out-of-order
// approval, forged computed columns, cycles, concurrency, scope, DoS.
// ---------------------------------------------------------------------------
func TestR9_ScheduleEVMHand(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	planner := r8principal(f, "u-planner", []string{f.project}, "planner")
	// Mon-Fri, start Mon 2026-10-05, holiday Wed 2026-10-07.
	// P(4) 400,000; Q(3) 300,000 with P->Q SS+2; R(2) 200,000 with Q->R FF+1.
	// Hand: P [0,4) Q [2,5) R [4,6); finish 6; day 0 Mon 05, 1 Tue 06, 2 Thu 08, 3 Fri 09, 4 Mon 12, 5 Tue 13.
	in := ScheduleInput{ProjectID: f.project, Description: "Hand-checked network", StartDate: d("2026-10-05"), Weekdays: []int{1, 2, 3, 4, 5},
		Holidays: []time.Time{d("2026-10-07")},
		Activities: []ScheduleActivity{{Code: "P", Name: "Piling", Duration: 4, CostCodeID: w.costCode, Budget: dec("400000")},
			{Code: "Q", Name: "Pile caps", Duration: 3, CostCodeID: w.costCode, Budget: dec("300000")},
			{Code: "R", Name: "Ground beams", Duration: 2, CostCodeID: w.costCode, Budget: dec("200000")}},
		Links: []ScheduleLink{{"P", "Q", "SS", 2}, {"Q", "R", "FF", 1}}}
	v, err := f.svc.CreateSchedule(f.ctx, planner, in)
	must(t, "schedule", err)
	rows := map[string][4]int{}
	must(t, "computed", r9raw(f, func(ctx context.Context, tx pgx.Tx) error {
		r, err := tx.Query(ctx, `SELECT code, es, ef, ls, lf FROM schedule_activities WHERE version_id = $1::uuid`, v)
		if err != nil {
			return err
		}
		for r.Next() {
			var code string
			var a [4]int
			if err := r.Scan(&code, &a[0], &a[1], &a[2], &a[3]); err != nil {
				return err
			}
			rows[code] = a
		}
		return r.Err()
	}))
	want := map[string][4]int{"P": {0, 4, 0, 4}, "Q": {2, 5, 2, 5}, "R": {4, 6, 4, 6}}
	for k, a := range want {
		if rows[k] != a {
			r9open(t, "activity %s ES/EF/LS/LF %v, hand %v", k, rows[k], a)
		}
	}
	t.Logf("computed ES/EF/LS/LF %v (hand %v)", rows, want)
	must(t, "submit", f.svc.SubmitSchedule(f.ctx, planner, v))
	must(t, "baseline", f.svc.DecideSchedule(f.ctx, c.pm, v, true, ""))
	// PV by hand = sum budget x min(1, max(0, (elapsed working days - ES) / D)),
	// elapsed = working days from the start up to and including the status date.
	for _, x := range []struct{ date, pv, note string }{
		{"2026-10-06", "200000", "Tue, 2 working days elapsed"},
		{"2026-10-07", "200000", "Wed holiday, still 2 working days elapsed"},
		{"2026-10-09", "600000", "Fri, 4 elapsed: P 1, Q 2/3"},
		{"2026-10-10", "600000", "Sat, still 4 elapsed"},
		{"2026-10-11", "600000", "Sun, still 4 elapsed"},
		{"2026-10-12", "800000", "Mon, 5 elapsed: P 1, Q 1, R 1/2"},
	} {
		ev, err := f.svc.ScheduleEVM(f.ctx, c.pm, f.project, d(x.date))
		must(t, "evm", err)
		if !ev.PV.Equal(dec(x.pv)) {
			r9open(t, "PV at %s (%s) is %s, hand computation %s", x.date, x.note, ev.PV, x.pv)
		} else {
			r9held(t, "PV at %s (%s) = %s", x.date, x.note, ev.PV)
		}
	}
}

func TestR9_ScheduleProgressAndRaw(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	planner := r8principal(f, "u-planner", []string{f.project}, "planner")
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

	// Forged computed columns that the database does not verify.
	forged, err := f.svc.CreateSchedule(f.ctx, planner, w.scheduleInput())
	must(t, "schedule", err)
	var before string
	must(t, "before", r9raw(f, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT format('critical=%s free_float=%s late_start=%s late_finish=%s', critical, free_float, late_start, late_finish) FROM schedule_activities WHERE version_id=$1::uuid AND code='C'`, forged).Scan(&before)
	}))
	errF := r9exec(f, `UPDATE schedule_activities SET critical = true, free_float = 0, late_start = '2026-10-08', late_finish = '2026-10-09' WHERE version_id = $1::uuid AND code = 'C'`, forged)
	errF2 := r9exec(f, `UPDATE schedule_activities SET critical = false, free_float = 30, late_start = '2027-03-01', late_finish = '2027-03-31' WHERE version_id = $1::uuid AND code = 'D'`, forged)
	t.Logf("activity C as computed: %s; raw updates: %v / %v", before, errF, errF2)
	if errF == nil && errF2 == nil {
		if err := f.svc.SubmitSchedule(f.ctx, planner, forged); err != nil {
			r9held(t, "submission with forged critical/free float/late dates refused: %v", err)
		} else {
			r9open(t, "a schedule with forged critical flag, free float and late dates was accepted for submission")
		}
	}
	// A genuine baseline for the tampering probes below (R9-F7 left the
	// forged version DRAFT).
	forged, err = f.svc.CreateSchedule(f.ctx, planner, w.scheduleInput())
	must(t, "genuine schedule", err)
	must(t, "submit genuine", f.svc.SubmitSchedule(f.ctx, planner, forged))
	must(t, "baseline genuine", f.svc.DecideSchedule(f.ctx, c.pm, forged, true, ""))

	// Raw tampering with a BASELINE.
	r9refused(t, "raw UPDATE of a BASELINE activity's computed column", r9exec(f, `UPDATE schedule_activities SET critical = false WHERE version_id = $1::uuid`, forged))
	r9refused(t, "raw INSERT of a link into a BASELINE", r9exec(f, `INSERT INTO schedule_links(version_id, pred_code, succ_code, link_type, lag) VALUES ($1::uuid, 'C', 'D', 'FS', 0)`, forged))
	r9refused(t, "raw UPDATE of a BASELINE's holidays", r9exec(f, `UPDATE schedule_versions SET holidays = '{2026-10-06}' WHERE id = $1::uuid`, forged))
	r9refused(t, "raw UPDATE of a BASELINE's finish", r9exec(f, `UPDATE schedule_versions SET finish_offset = 99 WHERE id = $1::uuid`, forged))
	r9refused(t, "raw DELETE of a BASELINE activity", r9exec(f, `DELETE FROM schedule_activities WHERE version_id = $1::uuid AND code = 'E'`, forged))
	r9refused(t, "raw INSERT of a version as BASELINE", r9exec(f, `INSERT INTO schedule_versions(legal_entity_id, project_id, version, description, start_date, working_weekdays, status, created_by)
		VALUES ($1::uuid, $2::uuid, 1, 'raw baseline', '2026-10-05', '{1,2,3,4,5}', 'BASELINE', 'u-planner')`, f.entity, f.project))

	// A cycle added by raw SQL to a DRAFT, then submitted through the kernel.
	cyc, err := f.svc.CreateSchedule(f.ctx, planner, w.scheduleInput())
	must(t, "cyclic draft", err)
	errL := r9exec(f, `INSERT INTO schedule_links(version_id, pred_code, succ_code, link_type, lag) VALUES ($1::uuid, 'E', 'A', 'FS', 0)`, cyc)
	t.Logf("raw link E->A into a DRAFT: %v", errL)
	r9refused(t, "submission of a DRAFT with a raw cycle", f.svc.SubmitSchedule(f.ctx, planner, cyc))

	// Cost of the cycle check: a 300-activity chain with a 2-cycle at its end.
	big := ScheduleInput{ProjectID: f.project, Description: "Long chain", StartDate: d("2026-10-05"), Weekdays: []int{1, 2, 3, 4, 5}}
	for i := 0; i < 300; i++ {
		big.Activities = append(big.Activities, ScheduleActivity{Code: fmt.Sprintf("Z%03d", i), Name: "Chain step", Duration: 1})
		if i > 0 {
			big.Links = append(big.Links, ScheduleLink{fmt.Sprintf("Z%03d", i-1), fmt.Sprintf("Z%03d", i), "FS", 0})
		}
	}
	bv, err := f.svc.CreateSchedule(f.ctx, planner, big)
	must(t, "long chain", err)
	must(t, "2-cycle", r9exec(f, `INSERT INTO schedule_links(version_id, pred_code, succ_code, link_type, lag) VALUES ($1::uuid, 'Z299', 'Z298', 'FS', 0)`, bv))
	t0 := time.Now()
	errB := f.svc.SubmitSchedule(f.ctx, planner, bv)
	t.Logf("info: cycle check on 300 activities with a 2-cycle at the end took %s: %v", time.Since(t0).Round(time.Millisecond), errB)

	// Concurrent baseline approvals.
	v1, err := f.svc.CreateSchedule(f.ctx, planner, w.scheduleInput())
	must(t, "v1", err)
	v2, err := f.svc.CreateSchedule(f.ctx, planner, w.scheduleInput())
	must(t, "v2", err)
	must(t, "s1", f.svc.SubmitSchedule(f.ctx, planner, v1))
	must(t, "s2", f.svc.SubmitSchedule(f.ctx, planner, v2))
	errs := make([]error, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = f.svc.DecideSchedule(f.ctx, c.pm, v1, true, "") }()
	go func() { defer wg.Done(); errs[1] = f.svc.DecideSchedule(f.ctx, c.pm, v2, true, "") }()
	wg.Wait()
	n := r9dec(t, f, `SELECT count(*)::numeric FROM schedule_versions WHERE project_id = $1::uuid AND status = 'BASELINE'`, f.project)
	t.Logf("concurrent approvals of two versions: %v / %v; BASELINE rows %s", errs[0], errs[1], n)
	if !n.Equal(dec("1")) {
		r9open(t, "%s baselines after concurrent approvals", n)
	} else {
		r9held(t, "one BASELINE after concurrent approvals")
	}
	base := v1
	if errs[0] != nil {
		base = v2
	}
	_ = base

	// Scope: another project's PM and planner.
	otherProj := uuid.NewString()
	pm2 := r8principal(f, "u-pm-other", []string{otherProj}, "project_manager")
	pl2 := r8principal(f, "u-planner-other", []string{otherProj}, "planner")
	_, errD := f.svc.GetP2PDoc(f.ctx, pm2, "schedule_version", v1)
	lst, _ := f.svc.ListP2PDocs(f.ctx, pm2, "schedule_version", "", 50)
	_, errE := f.svc.ScheduleEVM(f.ctx, pm2, f.project, d("2026-10-14"))
	_, errP := f.svc.RecordProgress(f.ctx, pl2, f.project, d("2026-10-14"), []ProgressLine{pct("A", "10", "2026-10-05", "")})
	if errD == nil || len(lst) > 0 || errE == nil || errP == nil {
		r9open(t, "another project's PM/planner: detail %v, list %d, evm %v, progress %v", errD, len(lst), errE, errP)
	} else {
		r9held(t, "another project's PM/planner: detail %v; list %d; evm %v; progress %v", errD, len(lst), errE, errP)
	}

	// Progress: EV from the latest report only.
	p1, err := f.svc.RecordProgress(f.ctx, planner, f.project, d("2026-10-14"), []ProgressLine{
		pct("A", "100", "2026-10-05", "2026-10-07"), pct("B", "100", "2026-10-08", "2026-10-13"), pct("C", "50", "2026-10-08", ""), pct("D", "20", "2026-10-14", "")})
	must(t, "p1", err)
	must(t, "p1 approve", f.svc.DecideProgress(f.ctx, c.pm, p1, true, ""))
	e1, err := f.svc.ScheduleEVM(f.ctx, c.pm, f.project, d("2026-10-14"))
	must(t, "evm 14", err)
	p2, err := f.svc.RecordProgress(f.ctx, planner, f.project, d("2026-10-15"), []ProgressLine{pct("D", "40", "2026-10-14", "")})
	must(t, "p2 (D only)", err)
	must(t, "p2 approve", f.svc.DecideProgress(f.ctx, c.pm, p2, true, ""))
	e2, err := f.svc.ScheduleEVM(f.ctx, c.pm, f.project, d("2026-10-15"))
	must(t, "evm 15", err)
	// Hand: A 1,000,000 + B 2,000,000 + C 50% of 500,000 + D 40% of 3,000,000 = 4,450,000.
	t.Logf("EV at 10-14 (full report) %s; EV at 10-15 after a report listing only D at 40%%: %s (hand, latest known percent per activity: 4450000)", e1.EV, e2.EV)
	if !e2.EV.Equal(dec("4450000")) {
		r9open(t, "a later progress report that lists only D drops EV from %s to %s: A, B (100%%) and C (50%%) count as 0; SPI %v -> %v", e1.EV, e2.EV, e1.SPI, e2.SPI)
	}
	// Out-of-order approval of two drafts.
	late, err := f.svc.RecordProgress(f.ctx, planner, f.project, d("2026-10-17"), []ProgressLine{pct("D", "50", "2026-10-14", "")})
	must(t, "10-17", err)
	early, err := f.svc.RecordProgress(f.ctx, planner, f.project, d("2026-10-16"), []ProgressLine{pct("D", "60", "2026-10-14", "")})
	must(t, "10-16", err)
	must(t, "approve 10-17", f.svc.DecideProgress(f.ctx, c.pm, late, true, ""))
	if err := f.svc.DecideProgress(f.ctx, c.pm, early, true, ""); err == nil {
		r9info(t, "a 10-16 report (D 60%%) was approved after the 10-17 report (D 50%%): approved history now runs backwards in time; 'reported forward' is checked only at recording")
	} else {
		r9held(t, "out-of-order approval refused: %v", err)
	}
	// Actual start before the schedule start.
	pre, err := f.svc.RecordProgress(f.ctx, planner, f.project, d("2026-10-18"), []ProgressLine{pct("E", "0", "", ""), pct("D", "60", "2026-09-01", "")})
	if err == nil {
		r9info(t, "progress %s with D actual start 2026-09-01 (schedule starts 2026-10-05) recorded", pre[:8])
	} else {
		r9held(t, "actual start before the schedule start refused: %v", err)
	}
}

func TestR9_ScheduleEVMCost(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	planner := r8principal(f, "u-planner", []string{f.project}, "planner")
	in := w.scheduleInput()
	for i := 0; i < 3000; i++ {
		in.Holidays = append(in.Holidays, d("2027-01-01").AddDate(0, 0, i))
	}
	_, err := f.svc.CreateSchedule(f.ctx, planner, in)
	r9refused(t, "a schedule with 3000 holidays (R9-F3: at most 400)", err)
	in = w.scheduleInput()
	for i := 0; i < 400; i++ {
		in.Holidays = append(in.Holidays, d("2027-01-01").AddDate(0, 0, i*3))
	}
	v, err := f.svc.CreateSchedule(f.ctx, planner, in)
	must(t, "schedule with 400 holidays", err)
	must(t, "submit", f.svc.SubmitSchedule(f.ctx, planner, v))
	must(t, "baseline", f.svc.DecideSchedule(f.ctx, c.pm, v, true, ""))
	reader := r8principal(f, "u-site-reader", []string{f.project}, "site_engineer")
	for _, sd := range []string{"2026-10-14", "2036-01-01", "2100-01-01", "9999-12-31"} {
		ctx, cancel := context.WithTimeout(f.ctx, 30*time.Second)
		t0 := time.Now()
		_, err := f.svc.ScheduleEVM(ctx, reader, f.project, d(sd))
		cancel()
		el := time.Since(t0)
		t.Logf("EVM at status date %s with 400 holidays (one GET by a project reader): %s, err %v", sd, el.Round(time.Millisecond), err)
		if el > 6*time.Second {
			r9open(t, "EVM at %s took %s (bound: 5 s statement timeout)", sd, el)
		}
		if (sd == "2100-01-01" || sd == "9999-12-31") && err == nil {
			r9open(t, "EVM at %s beyond the schedule horizon was computed", sd)
		}
	}
}

// ---------------------------------------------------------------------------
// 0028: the designation path.
// ---------------------------------------------------------------------------
func TestR9_Designation(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	other, err := f.svc.CreateStockItem(f.ctx, c.buyer, StockItemInput{LegalEntityID: f.entity, Code: "CU-WIRE-16", Name: "Copper wire 16mm2", Unit: "t",
		ValuationMethod: "FIFO", InventoryAccountID: w.acct["1200"]})
	must(t, "item", err)
	must(t, "approve item", f.svc.ApproveStockItem(f.ctx, c.finMgr, other))

	// An item of another legal entity of the same tenant.
	var e2, inv2 string
	must(t, "entity 2", f.db.AdminStore.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		if e2, err = postgres.CreateLegalEntity(ctx, tx, f.tenant, "SERK TRADING PLC", "ET", "ETB", ""); err != nil {
			return err
		}
		inv2, err = postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: f.tenant, LegalEntityID: e2, Code: "1200", Name: "Inventory E2", Type: "ASSET", Active: true})
		return err
	}))
	foreign, err := f.svc.CreateStockItem(f.ctx, c.buyer, StockItemInput{LegalEntityID: e2, Code: "STEEL-E2", Name: "Steel of entity 2", Unit: "t", ValuationMethod: "FIFO", InventoryAccountID: inv2})
	must(t, "item e2", err)
	must(t, "approve item e2", f.svc.ApproveStockItem(f.ctx, c.finMgr, foreign))

	po := w.inventoryPOUndesignated(t)
	r9refused(t, "designation with an item of another legal entity", f.svc.DesignatePOLineItem(f.ctx, c.buyer, po, 1, foreign))
	buyer2 := r8principal(f, "u-buyer-other", []string{uuid.NewString()}, "procurement_officer")
	r9refused(t, "designation by another project's buyer", f.svc.DesignatePOLineItem(f.ctx, buyer2, po, 1, w.itemSteel))
	r9refused(t, "designation of a line that does not exist", f.svc.DesignatePOLineItem(f.ctx, c.buyer, po, 9, w.itemSteel))

	// One person, no checker: the steel line designated as copper wire.
	if err := f.svc.DesignatePOLineItem(f.ctx, c.buyer, po, 1, other); err == nil {
		r9info(t, "the buyer alone designated PO line 1 'Reinforcement steel Grade 60' as CU-WIRE-16 (same unit and account); no second person")
	} else {
		r9held(t, "%v", err)
	}
	rows, err := f.admin.Query(f.ctx, `SELECT action, subject_type, left(subject_id, 8), COALESCE(ctx, '-'), actor FROM approval_attestations WHERE action = 'po.line.designate' AND tenant_id = $1::uuid`, f.tenant)
	must(t, "attestations", err)
	for rows.Next() {
		var a, st, sid, cx, actor string
		must(t, "scan", rows.Scan(&a, &st, &sid, &cx, &actor))
		r9info(t, "designation attestation: action %s subject %s/%s ctx %s actor %s (no line number or item in the attested decision)", a, st, sid, cx, actor)
	}
	rows.Close()

	// Designation on a DRAFT PO.
	pr, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "Draft PO designation probe", nil, []PRLine{
		{LineNo: 1, CostCodeID: w.costCode, Description: "Reinforcement steel Grade 60", Unit: "t", Quantity: dec("2"), EstUnitPrice: dec("86000")}})
	must(t, "pr", err)
	must(t, "pr submit", f.svc.SubmitPR(f.ctx, c.siteEng, pr))
	must(t, "pr approve", f.svc.DecidePR(f.ctx, c.pm, pr, true, ""))
	rfq, err := f.svc.CreateRFQ(f.ctx, c.buyer, pr, time.Now().Add(72*time.Hour), 3, "", w.sup[:])
	must(t, "rfq", err)
	must(t, "rfq issue", f.svc.IssueRFQ(f.ctx, c.buyer, rfq))
	q := make([]string, 3)
	for i := range q {
		q[i], err = f.svc.RecordQuote(f.ctx, c.buyer, rfq, w.sup[i], time.Now().AddDate(0, 1, 0), "SQ-"+key("d"), []QuoteLine{{1, dec("84500").Add(decimal.NewFromInt(int64(i * 1000)))}})
		must(t, "quote", err)
		must(t, "eval", f.svc.EvaluateQuote(f.ctx, c.siteEng, q[i], true, "Mill certificates provided"))
	}
	must(t, "award", f.svc.AwardRFQ(f.ctx, c.procMgr, rfq, q[0], ""))
	dpo, err := f.svc.CreatePOFromAward(f.ctx, c.buyer, rfq, map[int]string{1: w.acct["1200"]})
	must(t, "draft po", err)
	st := r9dec(t, f, `SELECT (CASE status WHEN 'DRAFT' THEN 0 ELSE 1 END)::numeric FROM purchase_orders WHERE id = $1::uuid`, dpo)
	if err := f.svc.DesignatePOLineItem(f.ctx, c.buyer, dpo, 1, w.itemSteel); err == nil {
		r9info(t, "designation accepted on a PO in status %s (0 = DRAFT); the kernel and trigger do not check the PO status", st)
		if err := f.svc.ApprovePO(f.ctx, c.procMgr, dpo, ""); err != nil {
			t.Logf("info: approval after designation on the draft: %v", err)
		}
	} else {
		r9held(t, "designation on a DRAFT PO refused: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 0028: p2p_cost_position semantics. Budget gate after put-away; count
// shortages.
// ---------------------------------------------------------------------------
func (w *stockWorld) r9PR(t *testing.T, steelQty string) (string, error) {
	t.Helper()
	f, c := w.f, w.cast
	pr, err := f.svc.CreatePR(f.ctx, c.siteEng, f.project, "Stock replenishment (review 9)", nil, []PRLine{
		{LineNo: 1, CostCodeID: w.costCode, Description: "Reinforcement steel Grade 60", Unit: "t", Quantity: dec(steelQty), EstUnitPrice: dec("86000")},
		{LineNo: 2, CostCodeID: w.costCode, Description: "OPC cement 50kg", Unit: "bag", Quantity: dec("1"), EstUnitPrice: dec("960")}})
	must(t, "pr", err)
	must(t, "pr submit", f.svc.SubmitPR(f.ctx, c.siteEng, pr))
	return pr, f.svc.DecidePR(f.ctx, c.pm, pr, true, "")
}

func (w *stockWorld) r9POFromPR(t *testing.T, pr string) string {
	t.Helper()
	f, c := w.f, w.cast
	rfq, err := f.svc.CreateRFQ(f.ctx, c.buyer, pr, time.Now().Add(72*time.Hour), 3, "", w.sup[:])
	must(t, "rfq", err)
	must(t, "rfq issue", f.svc.IssueRFQ(f.ctx, c.buyer, rfq))
	q := make([]string, 3)
	var err2 error
	for i := range q {
		bump := decimal.NewFromInt(int64(i))
		q[i], err2 = f.svc.RecordQuote(f.ctx, c.buyer, rfq, w.sup[i], time.Now().AddDate(0, 1, 0), "SQ-"+key("b"), []QuoteLine{{1, dec("84500").Add(bump.Mul(dec("1000")))}, {2, dec("940").Add(bump.Mul(dec("10")))}})
		must(t, "quote", err2)
		must(t, "eval", f.svc.EvaluateQuote(f.ctx, c.siteEng, q[i], true, "Mill certificates provided"))
	}
	must(t, "award", f.svc.AwardRFQ(f.ctx, c.procMgr, rfq, q[0], ""))
	po, err := f.svc.CreatePOFromAwardItems(f.ctx, c.buyer, rfq, map[int]string{1: w.acct["1200"], 2: w.acct["1200"]}, map[int]string{1: w.itemSteel, 2: w.itemCement})
	must(t, "po", err)
	must(t, "po approve", f.svc.ApprovePO(f.ctx, c.procMgr, po, ""))
	return po
}

func TestR9_BudgetAfterPutAway(t *testing.T) {
	w := newStockWorld(t)
	f, c := w.f, w.cast
	pos := func() (budget, committed, actual, available decimal.Decimal) {
		must(t, "position", r9raw(f, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT budget, committed, actual_other, available FROM p2p_cost_position($1::uuid, NULL, NULL)`, w.costCode).Scan(&budget, &committed, &actual, &available)
		}))
		return
	}
	b0, _, _, av0 := pos()
	t.Logf("01-MAT budget %s available %s", b0, av0)
	purchased := decimal.Zero
	receive := func(po string) {
		grn, j := w.receipt(t, po, GRNLine{POLineNo: 1, QtyReceived: dec("55")}, GRNLine{POLineNo: 2, QtyReceived: dec("1")})
		w.financePost(t, j)
		w.putAway(t, grn, 1, w.itemSteel, "55")
		w.putAway(t, grn, 2, w.itemCement, "1")
	}
	// Control: two 55 t POs open (nothing put away), a third PR does not fit.
	var open []string
	for i := 0; i < 2; i++ {
		pr, err := w.r9PR(t, "55")
		must(t, "pr", err)
		po := w.r9POFromPR(t, pr)
		open = append(open, po)
		purchased = purchased.Add(r9dec(t, f, `SELECT sum(amount) FROM po_lines WHERE po_id = $1::uuid`, po))
	}
	_, cm, _, av := pos()
	_, errCtl := w.r9PR(t, "55")
	if errCtl != nil {
		r9held(t, "with two POs open and nothing put away (committed %s, available %s) a third 4,730,960 PR is refused: %v", cm, av, errCtl)
	} else {
		t.Logf("control: third PR accepted with committed %s available %s", cm, av)
	}
	for _, po := range open {
		receive(po)
	}
	_, cm2, act2, av2 := pos()
	t.Logf("after receiving and putting away both POs (%s): committed %s actual %s available %s", purchased, cm2, act2, av2)
	for cycle := 3; cycle <= 4; cycle++ {
		pr, err := w.r9PR(t, "55")
		if err != nil {
			r9held(t, "cycle %d PR refused by the budget gate after put-away (R9-F2): %v", cycle, err)
			break
		}
		po := w.r9POFromPR(t, pr)
		purchased = purchased.Add(r9dec(t, f, `SELECT sum(amount) FROM po_lines WHERE po_id = $1::uuid`, po))
		receive(po)
		_, cm3, act3, av3 := pos()
		t.Logf("PR/PO %d approved by the budget gate; after put-away: committed %s actual %s available %s; purchased so far %s on a %s budget", cycle, cm3, act3, av3, purchased, b0)
	}
	_, _, _, avEnd := pos()
	if purchased.GreaterThan(b0) && avEnd.GreaterThan(decimal.Zero) {
		r9open(t, "%s of stock bought on 01-MAT (budget %s) through three budget-checked PRs; available is still %s: put-away releases the commitment, so the PR/PO gate no longer bounds purchasing on the code", purchased, b0, avEnd)
	}

	// A count shortage: stock written off with no cost code.
	_, _, _, avA := pos()
	ct, err := f.svc.CreateStockCount(f.ctx, c.store, StockCountInput{WarehouseID: w.store, StockItemID: w.itemSteel, CountedQty: dec("208"),
		VarianceAccountID: w.acct["5200"], CountDate: today()})
	must(t, "shortage count", err)
	jc, err := f.svc.ApproveStockCount(f.ctx, w.invCtl, ct)
	must(t, "approve count", err)
	w.financePost(t, jc)
	amt := r9dec(t, f, `SELECT amount FROM stock_counts WHERE id = $1::uuid`, ct)
	var lines string
	must(t, "journal lines", r9raw(f, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT string_agg(format('%s %s %s project=%s cost_code=%s', a.code, jl.side, jl.amount, COALESCE(left(jl.project_id::text,8),'-'), COALESCE(left(jl.cost_code_id::text,8),'-')), '; ' ORDER BY a.code)
			FROM journal_lines jl JOIN accounts a ON a.id = jl.account_id WHERE jl.journal_id = $1::uuid`, jc).Scan(&lines)
	}))
	_, _, _, avB := pos()
	t.Logf("12 t shortage (%s) approved and posted: journal %s; 01-MAT available %s -> %s", amt, lines, avA, avB)
	// Since 0030 (R9-F5): the lost stock is still inside the ordering code's
	// commitment (put-away releases nothing and it was never issued), so the
	// code stays charged for it and the count adds no second charge.
	if !avA.Equal(avB) {
		r9open(t, "a count shortage of %s moved 01-MAT available %s -> %s; the lost stock is already charged through the commitment", amt, avA, avB)
	} else {
		r9held(t, "the %s shortage stays charged to 01-MAT through its commitment (available %s unchanged)", amt, avB)
	}
}

// ---------------------------------------------------------------------------
// 0028 posture check: false negatives.
// ---------------------------------------------------------------------------
func TestR9_PostureFalseNegative(t *testing.T) {
	w := newStockWorld(t)
	f := w.f
	var role string
	must(t, "role", r9raw(f, func(ctx context.Context, tx pgx.Tx) error { return tx.QueryRow(ctx, `SELECT current_user`).Scan(&role) }))
	base, err := f.app.Posture(f.ctx)
	must(t, "posture", err)
	t.Logf("posture on the test database: %q", base)
	fn := `pg_catalog.pg_try_advisory_xact_lock(bigint)`
	defer f.super.Exec(f.ctx, fmt.Sprintf(`REVOKE EXECUTE ON FUNCTION %s FROM %q`, fn, role))
	if _, err := f.super.Exec(f.ctx, fmt.Sprintf(`GRANT EXECUTE ON FUNCTION %s TO %q`, fn, role)); err != nil {
		t.Skipf("grant: %v", err)
	}
	after, err := f.app.Posture(f.ctx)
	must(t, "posture 2", err)
	var got bool
	errLock := r9raw(f, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(727002)`).Scan(&got)
	})
	t.Logf("with %s granted directly to tenant login %s: posture %q; lock 727002 taken: %v %v", fn, role, after, got, errLock)
	if got && errLock == nil && len(after) == len(base) {
		r9open(t, "(conditional) EXECUTE on %s granted directly to the tenant login lets it take the relay lock 727002; the posture check (has_function_privilege('serk_app', ...)) reports nothing", fn)
	}
}

// ---------------------------------------------------------------------------
// 0029 abuse counters at the SQL boundary.
// ---------------------------------------------------------------------------
func TestR9_AbuseSQL(t *testing.T) {
	f := newFixture(t)
	dsn := f.db.LoginRole(t, "serk_abuse")
	pool, err := pgxpool.New(f.ctx, dsn)
	must(t, "abuse pool", err)
	defer pool.Close()
	var login string
	must(t, "login", pool.QueryRow(f.ctx, `SELECT current_user`).Scan(&login))

	// What else can the login do?
	var tables, funcs []string
	rows, err := f.admin.Query(f.ctx, `SELECT n.nspname || '.' || c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','v','m','p','S')
		  AND (has_table_privilege($1, c.oid, 'SELECT') OR has_table_privilege($1, c.oid, 'INSERT') OR has_table_privilege($1, c.oid, 'UPDATE') OR has_table_privilege($1, c.oid, 'DELETE'))`, login)
	must(t, "tables", err)
	tables, err = pgx.CollectRows(rows, pgx.RowTo[string])
	must(t, "tables rows", err)
	rows, err = f.admin.Query(f.ctx, `SELECT p.oid::regprocedure::text || CASE WHEN p.prosecdef THEN ' [SECURITY DEFINER]' ELSE '' END FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public' AND has_function_privilege($1, p.oid, 'EXECUTE') ORDER BY 1`, login)
	must(t, "funcs", err)
	funcs, err = pgx.CollectRows(rows, pgx.RowTo[string])
	must(t, "funcs rows", err)
	t.Logf("abuse login %s: tables/views/sequences with any DML/SELECT privilege: %v", login, tables)
	t.Logf("abuse login: public functions executable (%d): %v", len(funcs), funcs)
	var definers []string
	for _, fn := range funcs {
		if strings.Contains(fn, "SECURITY DEFINER") && !strings.HasPrefix(fn, "abuse_") {
			definers = append(definers, fn)
		}
	}
	if len(tables) > 0 {
		r9open(t, "the abuse login has table privileges: %v", tables)
	}
	if len(definers) > 0 {
		r9info(t, "SECURITY DEFINER functions other than abuse_* executable by the abuse login: %v", definers)
	}
	for _, q := range []string{`CREATE TEMP TABLE r9_tmp(x int)`, `SELECT pg_try_advisory_xact_lock(727002)`, `SELECT count(*) FROM pg_catalog.pg_roles`, `SELECT current_tenant()`} {
		_, err := pool.Exec(f.ctx, q)
		t.Logf("abuse login: %-48s -> %v", q, err)
	}

	hit := func(scope string, key []byte, limit, window, block int) bool {
		var ok bool
		must(t, "hit", pool.QueryRow(f.ctx, `SELECT abuse_hit($1, $2, $3, $4, $5)`, scope, key, limit, window, block).Scan(&ok))
		return ok
	}
	key := func(s string) []byte {
		var b []byte
		must(t, "key", pool.QueryRow(f.ctx, `SELECT sha256($1::bytea)`, []byte(s+uuid.NewString())).Scan(&b))
		return b
	}
	seq := func(scope string, k []byte, limit, window, block, n int) []bool {
		out := make([]bool, n)
		for i := range out {
			out[i] = hit(scope, k, limit, window, block)
		}
		return out
	}
	// Lockout: limit 3, window 2 s, block 3 s.
	k1 := key("lock")
	s1 := seq("auth_failure", k1, 3, 2, 3, 5)
	time.Sleep(3200 * time.Millisecond)
	s1b := seq("auth_failure", k1, 3, 2, 3, 1)
	t.Logf("lockout limit 3 window 2s block 3s: %v; after 3.2s: %v (want [true true true false false]; [true])", s1, s1b)
	if fmt.Sprint(s1) != "[true true true false false]" || !s1b[0] {
		r9open(t, "lockout sequence %v then %v", s1, s1b)
	} else {
		r9held(t, "lockout and reset at the window/lockout boundary behave as the in-process limiter")
	}
	// Block shorter than the window.
	k2 := key("short")
	s2 := seq("auth_failure", k2, 3, 4, 1, 3)
	time.Sleep(1200 * time.Millisecond)
	s2b := seq("auth_failure", k2, 3, 4, 1, 1)
	t.Logf("info: limit 3 window 4s block 1s: %v; 1.2s later (block over, window open): %v (the next event re-blocks: lockout lasts to the window end)", s2, s2b)
	// Plain rate limit.
	k3 := key("rate")
	s3 := seq("preauth", k3, 2, 1, 0, 3)
	time.Sleep(1100 * time.Millisecond)
	s3b := seq("preauth", k3, 2, 1, 0, 1)
	if fmt.Sprint(s3) != "[true true false]" || !s3b[0] {
		r9open(t, "rate limit sequence %v then %v", s3, s3b)
	} else {
		r9held(t, "rate limit 2 per 1s: %v then %v", s3, s3b)
	}
	// Storage: one row per distinct key, kept at least an hour.
	var before, after, size int64
	must(t, "count", f.admin.QueryRow(f.ctx, `SELECT count(*) FROM abuse_counters`).Scan(&before))
	t0 := time.Now()
	var allowed int64
	must(t, "flood", pool.QueryRow(f.ctx, `SELECT count(*) FILTER (WHERE abuse_hit('preauth', sha256(('r9-'||g||$1)::bytea), 600, 60, 0)) FROM generate_series(1, 100000) g`, uuid.NewString()).Scan(&allowed))
	el := time.Since(t0)
	must(t, "count2", f.admin.QueryRow(f.ctx, `SELECT count(*), pg_total_relation_size('abuse_counters') FROM abuse_counters`).Scan(&after, &size))
	t.Logf("info: 100,000 distinct client keys (e.g. one IPv6 /64 rotated per request) in %s: rows %d -> %d, abuse_counters %d MB (~%d bytes per key); all %d allowed; rows are swept only after window_end + 1 hour",
		el.Round(time.Millisecond), before, after, size>>20, size/after, allowed)
}

func TestR9_ScheduleEVMCostNoHolidays(t *testing.T) {
	w := newP2PWorld(t)
	f, c := w.f, w.cast
	w.approvedBOQ(t)
	planner := r8principal(f, "u-planner", []string{f.project}, "planner")
	v, err := f.svc.CreateSchedule(f.ctx, planner, w.scheduleInput())
	must(t, "schedule", err)
	must(t, "submit", f.svc.SubmitSchedule(f.ctx, planner, v))
	must(t, "baseline", f.svc.DecideSchedule(f.ctx, c.pm, v, true, ""))
	reader := r8principal(f, "u-site-reader", []string{f.project}, "site_engineer")
	for _, sd := range []string{"3000-01-01", "9999-12-31"} {
		ctx, cancel := context.WithTimeout(f.ctx, 60*time.Second)
		t0 := time.Now()
		ev, err := f.svc.ScheduleEVM(ctx, reader, f.project, d(sd))
		cancel()
		t.Logf("info: EVM at %s, no holidays: %s, PV %s err %v", sd, time.Since(t0).Round(time.Millisecond), ev.PV, err)
	}
	var setting string
	must(t, "timeout", r9raw(f, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT current_setting('statement_timeout')`).Scan(&setting)
	}))
	t.Logf("info: statement_timeout in the tenant transaction: %q", setting)
}
