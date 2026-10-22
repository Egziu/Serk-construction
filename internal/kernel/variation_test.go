package kernel

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/pkg/auth"
)

const voSHA = "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"

// TestJourneyB_Variation (migration 0026, GATEB-06). Contract (23,060,000):
// line 1 excavation 10,000 m3 @ 350; line 2 concrete 1,200 m3 @ 6,500;
// line 3 steel 120 t @ 98,000.
//
//	Measurement 1 verifies 4,000 / 300 / 20.
//	VO-1: line 2 +200 m3 (1,300,000); line 1 -1,000 m3 (-350,000); NEW line 4
//	gabions 500 m3 @ 2,400 (1,200,000). Value change 2,150,000; revised
//	contract value 25,210,000.
//	Measurement 2 verifies line 2 +1,050 (cumulative 1,350, beyond the signed
//	1,200 but within the varied 1,400) and line 4 200 m3.
//	IPC 1: cumulative gross 4,000x350 + 1,350x6,500 + 20x98,000 + 200x2,400
//	= 1,400,000 + 8,775,000 + 1,960,000 + 480,000 = 12,615,000.
func TestJourneyB_Variation(t *testing.T) {
	w := newARWorld(t)
	f, c := w.f, w.cast
	ctr := w.activeContract(t)
	w.measure(t, 10, "4000", "300", "20")
	instr := func(lines ...VariationLine) VariationInput {
		return VariationInput{Title: "Additional river protection", Reason: "Client instruction after the 2026 flood survey",
			ClientInstructionRef: "ERA-VO-001", ClientInstructionSHA256: voSHA, Lines: lines}
	}

	// Input controls.
	_, err := f.svc.CreateVariation(f.ctx, c.commercial, ctr, instr(VariationLine{LineNo: 1, Kind: "CHANGE", QtyDelta: dec("-6001")}))
	arDenied(t, "a reduction below the verified quantity", err, "already verified")
	_, err = f.svc.CreateVariation(f.ctx, c.commercial, ctr, instr(VariationLine{LineNo: 2, Kind: "NEW", Description: "Duplicate", Unit: "m3", QtyDelta: dec("1"), Rate: dec("1")}))
	arDenied(t, "a NEW line reusing a contract line number", err, "already used")
	_, err = f.svc.CreateVariation(f.ctx, c.commercial, ctr, instr(VariationLine{LineNo: 9, Kind: "CHANGE", QtyDelta: dec("5")}))
	arDenied(t, "a CHANGE to a line that does not exist", err, "does not exist")
	bad := instr(VariationLine{LineNo: 4, Kind: "NEW", Description: "Gabions", Unit: "m3", QtyDelta: dec("1"), Rate: dec("1")})
	bad.ClientInstructionSHA256 = "nope"
	_, err = f.svc.CreateVariation(f.ctx, c.commercial, ctr, bad)
	arDenied(t, "a variation without the instruction hash", err, "SHA-256")
	_, err = f.svc.CreateVariation(f.ctx, w.ar.qs, ctr, instr(VariationLine{LineNo: 2, Kind: "CHANGE", QtyDelta: dec("1")}))
	arDenied(t, "a variation by the quantity surveyor", err, "forbidden")

	vo, err := f.svc.CreateVariation(f.ctx, c.commercial, ctr, instr(
		VariationLine{LineNo: 2, Kind: "CHANGE", QtyDelta: dec("200")},
		VariationLine{LineNo: 1, Kind: "CHANGE", QtyDelta: dec("-1000")},
		VariationLine{LineNo: 4, Kind: "NEW", Description: "Gabion river protection", Unit: "m3", QtyDelta: dec("500"), Rate: dec("2400")}))
	must(t, "variation", err)
	must(t, "variation submit", f.svc.SubmitVariation(f.ctx, c.commercial, vo))
	var value decimal.Decimal
	must(t, "variation value", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT value_change FROM contract_variations WHERE id = $1::uuid`, vo).Scan(&value)
	}))
	if !value.Equal(dec("2150000")) {
		t.Errorf("variation value %s, want 2,150,000", value)
	}
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO variation_lines(variation_id, line_no, kind, description, unit, qty_delta, rate) VALUES ($1::uuid, 5, 'NEW', 'Extra', 'm3', 1, 1)`, vo)
		return err
	})
	arDenied(t, "a line added after submission", err, "only while the variation is DRAFT")
	err = f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO contract_lines(contract_id, line_no, description, unit, quantity, rate) VALUES ($1::uuid, 4, 'Gabion river protection', 'm3', 500, 2400)`, ctr)
		return err
	})
	arDenied(t, "a contract line added directly to an ACTIVE contract", err, "only by an approved variation")

	// Approval controls.
	stale := c.cfo
	stale.MFA = false
	arDenied(t, "approval without fresh MFA", f.svc.DecideVariation(f.ctx, stale, vo, true, ""), "multi-factor")
	both := c.commercial
	both.Roles = append([]string{"cfo"}, both.Roles...)
	arDenied(t, "self-approval of a variation", f.svc.DecideVariation(f.ctx, w.mfa(both), vo, true, ""), "segregation of duties")
	ai := w.mfa(c.cfo)
	ai.UserID, ai.Kind = "u-cfo-assistant", auth.KindAI
	arDenied(t, "approval by an AI principal", f.svc.DecideVariation(f.ctx, ai, vo, true, ""), "reserved to human principals")
	must(t, "variation approve", f.svc.DecideVariation(f.ctx, w.mfa(c.cfo), vo, true, ""))

	pos, err := f.svc.ContractPosition(f.ctx, c.commercial, ctr)
	must(t, "position", err)
	if !pos.ContractValue.Equal(dec("23060000")) || !pos.VariationsApproved.Equal(dec("2150000")) || !pos.RevisedContractValue.Equal(dec("25210000")) {
		t.Errorf("position after VO-1: value %s variations %s revised %s", pos.ContractValue, pos.VariationsApproved, pos.RevisedContractValue)
	}

	// Measurement within the varied quantities; beyond them it is refused.
	over, err := f.svc.CreateMeasurement(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC), []MeasurementLine{{2, dec("1101"), "Km 14"}})
	must(t, "over-measure draft", err)
	must(t, "over-measure submit", f.svc.SubmitMeasurement(f.ctx, w.ar.qs, over))
	arDenied(t, "measuring beyond the varied quantity", f.svc.DecideMeasurement(f.ctx, c.siteEng, over, true, ""), "including approved variations")
	must(t, "reject over-measure", f.svc.DecideMeasurement(f.ctx, c.siteEng, over, false, "Exceeds the varied quantity"))
	m2, err := f.svc.CreateMeasurement(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC),
		[]MeasurementLine{{2, dec("1050"), "Km 14"}, {4, dec("200"), "River km 13"}})
	must(t, "measurement 2", err)
	must(t, "measurement 2 submit", f.svc.SubmitMeasurement(f.ctx, w.ar.qs, m2))
	must(t, "measurement 2 verify", f.svc.DecideMeasurement(f.ctx, c.siteEng, m2, true, ""))
	ipc := w.certifiedIPC(t, 15, "ERA-IPC-01")
	w.checkIPC(t, ipc, ipcFigures{"12615000", "0", "12615000", "630750", "0", "1892250", "13876500"})

	// A reduction prepared before more work was verified is refused at approval.
	vo2, err := f.svc.CreateVariation(f.ctx, c.commercial, ctr, instr(VariationLine{LineNo: 3, Kind: "CHANGE", QtyDelta: dec("-90")}))
	must(t, "variation 2", err)
	must(t, "variation 2 submit", f.svc.SubmitVariation(f.ctx, c.commercial, vo2))
	m3, err := f.svc.CreateMeasurement(f.ctx, w.ar.qs, ctr, time.Date(2026, 10, 18, 0, 0, 0, 0, time.UTC), []MeasurementLine{{3, dec("15"), "Bridge 2"}})
	must(t, "measurement 3", err)
	must(t, "measurement 3 submit", f.svc.SubmitMeasurement(f.ctx, w.ar.qs, m3))
	must(t, "measurement 3 verify", f.svc.DecideMeasurement(f.ctx, c.siteEng, m3, true, ""))
	arDenied(t, "a reduction overtaken by verified work", f.svc.DecideVariation(f.ctx, w.mfa(c.cfo), vo2, true, ""), "already verified")
	arDenied(t, "rejecting without a reason", f.svc.DecideVariation(f.ctx, c.cfo, vo2, false, ""), "reason")
	must(t, "reject variation 2", f.svc.DecideVariation(f.ctx, c.cfo, vo2, false, "Steel quantity is still required"))
	vo3, err := f.svc.CreateVariation(f.ctx, c.commercial, ctr, instr(VariationLine{LineNo: 5, Kind: "NEW", Description: "Lighting", Unit: "no", QtyDelta: dec("10"), Rate: dec("15000")}))
	must(t, "variation 3", err)
	must(t, "cancel variation 3", f.svc.CancelVariation(f.ctx, c.commercial, vo3, "Instruction withdrawn by the client"))
	pos, err = f.svc.ContractPosition(f.ctx, c.commercial, ctr)
	must(t, "position", err)
	if !pos.RevisedContractValue.Equal(dec("25210000")) {
		t.Errorf("revised value after a rejected and a cancelled variation: %s", pos.RevisedContractValue)
	}
	t.Logf("position %+v", pos)
}
