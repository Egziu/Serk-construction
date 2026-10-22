package kernel

// Independent review 12 (site operations, 0037) probes, kept as regression
// tests after the fixes. "OPEN:" = defect, "held:" = control worked.
// docs/security/INDEPENDENT_REVIEW_12_2026-10-23.md. Synthetic data only.

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func r12raw(t *testing.T, f *fixture, name string, fn func(ctx context.Context, tx pgx.Tx) error) {
	t.Helper()
	if err := f.app.WithTenant(f.ctx, f.tenant, fn); err == nil {
		t.Errorf("OPEN: %s accepted", name)
	} else {
		t.Logf("held: %-70s %s", name, firstLine(err.Error()))
	}
}

// R12-F1/F3: forged command-log rows and sequence exhaustion.
func TestR12_CommandLogForgeryAndSequenceBound(t *testing.T) {
	f := newFixture(t)
	c := newSiteCast(f)
	dev, err := f.svc.RegisterDevice(f.ctx, fresh(c.eng), "Victim tablet")
	must(t, "register", err)
	r, err := f.svc.SaveDiary(f.ctx, c.eng, diaryIn(f, uuid.NewString(), 0, "48"))
	must(t, "diary", err)
	r12raw(t, f, "forged log row naming the owner (no attestation)", func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO site_sync_commands(device_id, client_op_id, seq, kind, actor, payload_sha256, client_time, outcome, diary_id, result)
			VALUES ($1::uuid, $2::uuid, 1, 'site_diary.save', 'u-site-eng', repeat('0',64), now(), 'APPLIED', $3::uuid, '{}')`, dev.ID, uuid.NewString(), r.ID)
		return err
	})
	r12raw(t, f, "forged log row with seq MaxInt64", func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO site_sync_commands(device_id, client_op_id, seq, kind, actor, payload_sha256, client_time, outcome, result)
			VALUES ($1::uuid, $2::uuid, 9223372036854775807, 'site_diary.save', 'u-site-eng', repeat('0',64), now(), 'REJECTED', '{}')`, dev.ID, uuid.NewString())
		return err
	})
	r12raw(t, f, "fake last-sync time", func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE site_devices SET last_sync_at = '2001-01-01' WHERE id = $1::uuid`, dev.ID)
		return err
	})
	// A command with a huge sequence is refused and not recorded; the device
	// keeps working.
	bad := SyncOp{OpID: uuid.NewString(), Seq: math.MaxInt64, Kind: "site_diary.save", ClientTime: time.Now(), Payload: json.RawMessage(`{"client_ref":"x"}`)}
	res, err := f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{bad})
	must(t, "huge seq", err)
	if res[0].Outcome != "REJECTED" || !strings.Contains(res[0].Error, "jumps more than 1000") {
		t.Errorf("OPEN: huge sequence: %+v", res[0])
	}
	res, err = f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{syncOp(1, "site_diary.save", savePayload(f, uuid.NewString(), 0, "8"), time.Now().Add(-time.Hour))})
	must(t, "next", err)
	if res[0].Outcome != "REJECTED" || res[0].Retry { // same project/day as the diary above: refused on its merits, recorded
		t.Logf("next command: %+v", res[0])
	}
	devs, err := f.svc.ListDevices(f.ctx, c.eng)
	must(t, "list", err)
	if devs[0].LastSeq != 1 {
		t.Errorf("OPEN: device sequence after a huge-seq attempt and one command: %d (want 1)", devs[0].LastSeq)
	} else {
		t.Logf("held: huge sequence refused and not recorded; the device continues at sequence 1")
	}
}

// R12-F8: canonical digest; duplicate and case-variant keys refused.
func TestR12_DigestCanonicalAndDuplicateKeys(t *testing.T) {
	f := newFixture(t)
	c := newSiteCast(f)
	dev, err := f.svc.RegisterDevice(f.ctx, fresh(c.eng), "Tablet digest")
	must(t, "register", err)
	op := syncOp(1, "site_diary.save", savePayload(f, uuid.NewString(), 0, "40"), time.Now())
	_, err = f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{op})
	must(t, "sync", err)
	var m map[string]json.RawMessage
	must(t, "decode", json.Unmarshal(op.Payload, &m))
	var sb strings.Builder
	sb.WriteString("{ ")
	keys := []string{"weather", "notes", "base_version", "labour", "equipment", "diary_date", "project_id", "client_ref"}
	for i, k := range keys {
		if i > 0 {
			sb.WriteString(" ,\n ")
		}
		sb.WriteString(`"` + k + `": ` + string(m[k]))
	}
	sb.WriteString(" }")
	variant := op
	variant.Payload = json.RawMessage(strings.Replace(sb.String(), `"Overcast"`, `"Overcast"`, 1))
	res, err := f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{variant})
	must(t, "variant", err)
	if !res[0].Replayed {
		t.Errorf("OPEN: re-ordered, re-spaced, re-escaped copy of the same command not recognised: %+v", res[0])
	} else {
		t.Logf("held: key order, whitespace and escape spelling do not change the command digest")
	}
	p := savePayload(f, uuid.NewString(), 0, "8")
	b, _ := json.Marshal(p)
	for name, payload := range map[string]string{
		"exact duplicate key":        strings.Replace(string(b), `"notes":`, `"notes":"FIRST","notes":`, 1),
		"case-variant duplicate key": strings.Replace(string(b), `"notes":`, `"notes":"FIRST","Notes":`, 1),
	} {
		dup := syncOp(2, "site_diary.save", nil, time.Now())
		dup.Payload = json.RawMessage(payload)
		res, err := f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{dup})
		must(t, name, err)
		if res[0].Outcome != "REJECTED" || !strings.Contains(res[0].Error, "duplicate key") {
			t.Errorf("OPEN: %s: %+v", name, res[0])
		} else {
			t.Logf("held: %s refused: %s", name, res[0].Error)
		}
	}
}

type r12FailIssuer struct{}

func (r12FailIssuer) Issue(context.Context, attest.Claims) (attest.Attestation, error) {
	return attest.Attestation{}, errors.New("signer: connection reset by peer")
}

// R12-F4: a temporary failure consumes nothing and holds back the rest of
// the batch; the retry applies the commands in order.
func TestR12_TransientFailureIsRetried(t *testing.T) {
	f := newFixture(t)
	c := newSiteCast(f)
	dev, err := f.svc.RegisterDevice(f.ctx, fresh(c.eng), "Tablet flaky")
	must(t, "register", err)
	flaky := New(f.app, auth.NewAuthorizer(nil, true)).UseApprovalSigner(r12FailIssuer{})
	ref := uuid.NewString()
	op1 := syncOp(1, "site_diary.save", savePayload(f, ref, 0, "40"), time.Now())
	op2 := syncOp(2, "site_diary.submit", map[string]any{"client_ref": ref, "base_version": 1}, time.Now())
	res, err := flaky.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{op1, op2})
	must(t, "outage", err)
	if !res[0].Retry || !res[1].Retry || !strings.Contains(res[1].Error, "earlier command") {
		t.Errorf("OPEN: during the signer outage: %+v", res)
	}
	var n int
	must(t, "log", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM site_sync_commands WHERE device_id = $1::uuid`, dev.ID).Scan(&n)
	}))
	if n != 0 {
		t.Errorf("OPEN: %d command(s) recorded during the outage", n)
	}
	res, err = f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{op1, op2})
	must(t, "retry", err)
	if res[0].Outcome != "APPLIED" || res[0].Replayed || res[1].Status != "SUBMITTED" {
		t.Errorf("OPEN: retry after recovery: %+v", res)
	} else {
		t.Logf("held: nothing consumed during the outage; the retry applied both commands in order")
	}
}

// R12-F2/F6: a DRAFT holding a project day can be withdrawn by its author or
// rejected by an approver; the database refuses a self-rejection.
func TestR12_DraftDayRelease(t *testing.T) {
	f := newFixture(t)
	c := newSiteCast(f)
	in := diaryIn(f, uuid.NewString(), 0, "8")
	in.Labour, in.Equipment, in.Notes = nil, nil, ""
	squat, err := f.svc.SaveDiary(f.ctx, c.eng, in)
	must(t, "squat", err)
	if _, err := f.svc.SaveDiary(f.ctx, c.eng2, diaryIn(f, uuid.NewString(), 0, "48")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("second diary for the day: %v", err)
	}
	if err := f.svc.DecideDiary(f.ctx, c.pm, squat.ID, false, ""); err == nil {
		t.Errorf("OPEN: rejection without a reason")
	}
	must(t, "reject draft", f.svc.DecideDiary(f.ctx, c.pm, squat.ID, false, "Empty diary holding the day"))
	r2, err := f.svc.SaveDiary(f.ctx, c.eng2, diaryIn(f, uuid.NewString(), 0, "48"))
	must(t, "colleague's diary after the rejection", err)
	if err := f.svc.CancelDiary(f.ctx, c.eng, r2.ID, "Not mine to cancel"); !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("OPEN: a colleague cancelled another person's diary: %v", err)
	}
	must(t, "author cancels", f.svc.CancelDiary(f.ctx, c.eng2, r2.ID, "Recorded under the wrong project"))
	if _, err := f.svc.SaveDiary(f.ctx, c.eng, diaryIn(f, uuid.NewString(), 0, "48")); err != nil {
		t.Errorf("OPEN: day not freed by the cancellation: %v", err)
	} else {
		t.Logf("held: a rejected or cancelled DRAFT frees the project day")
	}
	// Database-level: the author cannot reject their own diary even with the
	// approver role and a valid attestation.
	both := c.eng
	both.UserID, both.Roles = "u-both-roles", []string{"site_engineer", "project_manager"}
	in2 := diaryIn(f, uuid.NewString(), 0, "8")
	in2.DiaryDate = in2.DiaryDate.AddDate(0, 0, -1)
	own, err := f.svc.SaveDiary(f.ctx, both, in2)
	must(t, "own", err)
	r12raw(t, f, "author-attested REJECT of own diary (rejected_by = author)", func(ctx context.Context, tx pgx.Tx) error {
		if err := f.svc.authorize(ctx, tx, both, "site.diary.reject", "site_diary", own.ID, "REJECTED"); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE site_diaries SET status = 'REJECTED', decision_reason = 'self-rejected', rejected_by = 'u-both-roles' WHERE id = $1::uuid`, own.ID)
		return err
	})
	r12raw(t, f, "REJECT naming nobody", func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE site_diaries SET status = 'REJECTED', decision_reason = 'anonymous reject' WHERE id = $1::uuid`, own.ID)
		return err
	})
}

// R12-F5: lines cannot be added after the revision's attestation fired.
func TestR12_SetConstraintsImmediate(t *testing.T) {
	f := newFixture(t)
	c := newSiteCast(f)
	r, err := f.svc.SaveDiary(f.ctx, c.eng, diaryIn(f, uuid.NewString(), 0, "48"))
	must(t, "create", err)
	r12raw(t, f, "line added after SET CONSTRAINTS IMMEDIATE consumed the revision attestation", func(ctx context.Context, tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE site_diaries SET version = 2, notes = 'rev 2' WHERE id = $1::uuid`, r.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO site_diary_labour(diary_id, version, line_no, trade, headcount, hours) VALUES ($1::uuid, 2, 1, 'Masons', 6, 48)`, r.ID); err != nil {
			return err
		}
		if err := f.svc.authorize(ctx, tx, c.eng, "site.diary.revision.create", "site_diary", r.ID, ""); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SET CONSTRAINTS site_diary_attested IMMEDIATE`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO site_diary_labour(diary_id, version, line_no, trade, headcount, hours) VALUES ($1::uuid, 2, 2, 'Ghost gang', 100, 2400)`, r.ID)
		return err
	})
}

// R12-F7: active devices per person are capped.
func TestR12_DeviceCap(t *testing.T) {
	f := newFixture(t)
	c := newSiteCast(f)
	var last DeviceRegistration
	for i := 0; i < 5; i++ {
		d, err := f.svc.RegisterDevice(f.ctx, fresh(c.eng), "Tablet "+string(rune('A'+i)))
		must(t, "register", err)
		last = d
	}
	if _, err := f.svc.RegisterDevice(f.ctx, fresh(c.eng), "Tablet F"); err == nil {
		t.Errorf("OPEN: a sixth active device was registered")
	} else {
		t.Logf("held: sixth active device refused: %s", firstLine(err.Error()))
	}
	must(t, "revoke", f.svc.RevokeDevice(f.ctx, fresh(c.eng), last.ID, "Replaced by a new tablet"))
	if _, err := f.svc.RegisterDevice(f.ctx, fresh(c.eng), "Tablet F"); err != nil {
		t.Errorf("registration after a revocation: %v", err)
	}
}
