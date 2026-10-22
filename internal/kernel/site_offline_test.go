package kernel

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// Site operations and offline capture (0037, GATED-01).

type siteCast struct {
	eng, eng2, pm, outsider, secAdmin auth.Principal
}

func newSiteCast(f *fixture) siteCast {
	now := time.Now()
	mk := func(id string, projects []string, roles ...string) auth.Principal {
		return auth.Principal{UserID: id, TenantID: f.tenant, Roles: roles, ProjectIDs: projects, IssuedAt: now.Add(-time.Minute), Kind: auth.KindHuman}
	}
	proj := []string{f.project}
	return siteCast{
		eng:      mk("u-site-eng", proj, "site_engineer"),
		eng2:     mk("u-site-eng-2", proj, "site_engineer"),
		pm:       mk("u-site-pm", proj, "project_manager"),
		outsider: mk("u-site-other", []string{"11111111-1111-4111-8111-111111111111"}, "project_manager"),
		secAdmin: mk("u-sec-admin", nil, "security_admin"),
	}
}

func diaryIn(f *fixture, ref string, base int, labourHours string) DiaryInput {
	return DiaryInput{ClientRef: ref, ProjectID: f.project, DiaryDate: time.Now().UTC().Truncate(24 * time.Hour), Weather: "Sunny, 28 C",
		Notes: "Slab pour grid C3-C5", BaseVersion: base,
		Labour:    []DiaryLabour{{Trade: "Masons", Headcount: 6, Hours: decimal.RequireFromString(labourHours)}, {Trade: "Steel fixers", Headcount: 4, Hours: decimal.RequireFromString("32")}},
		Equipment: []DiaryEquipment{{Description: "Concrete pump 36 m", Hours: decimal.RequireFromString("6.5"), IdleHours: decimal.RequireFromString("1.5")}}}
}

func TestOffline_DiaryLifecycleOnline(t *testing.T) {
	f := newFixture(t)
	c := newSiteCast(f)
	ref := uuid.NewString()
	r1, err := f.svc.SaveDiary(f.ctx, c.eng, diaryIn(f, ref, 0, "48"))
	must(t, "create", err)
	if r1.Version != 1 || r1.Status != "DRAFT" || !strings.HasPrefix(r1.Number, "SDY-") {
		t.Fatalf("created %+v", r1)
	}
	r2, err := f.svc.SaveDiary(f.ctx, c.eng, diaryIn(f, ref, 1, "46.5"))
	must(t, "revise", err)
	if r2.Version != 2 || r2.ID != r1.ID {
		t.Fatalf("revised %+v", r2)
	}
	// A revision based on version 1 is now a conflict; nothing is merged.
	_, err = f.svc.SaveDiary(f.ctx, c.eng, diaryIn(f, ref, 1, "40"))
	var conflict *DiaryConflict
	if !errors.Is(err, postgres.ErrVersionConflict) || !errors.As(err, &conflict) || conflict.Version != 2 {
		t.Fatalf("stale revision: %v", err)
	}
	// Only the author revises; a second diary for the same project and day is refused.
	if _, err := f.svc.SaveDiary(f.ctx, c.eng2, diaryIn(f, ref, 2, "40")); !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("revision by another engineer: %v", err)
	}
	if _, err := f.svc.SaveDiary(f.ctx, c.eng2, diaryIn(f, uuid.NewString(), 0, "40")); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("second diary for the same day: %v", err)
	}
	// Validation: person-hours above 24 per head, bad decimals, future date.
	bad := diaryIn(f, uuid.NewString(), 0, "145")
	if _, err := f.svc.SaveDiary(f.ctx, c.eng, bad); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("145 person-hours for 6 people: %v", err)
	}
	future := diaryIn(f, uuid.NewString(), 0, "48")
	future.DiaryDate = time.Now().AddDate(0, 0, 5)
	if _, err := f.svc.SaveDiary(f.ctx, c.eng, future); err == nil {
		t.Errorf("a diary dated 5 days ahead was accepted")
	}
	// Submit with a stale version: conflict; with the current one: submitted.
	if err := f.svc.SubmitDiary(f.ctx, c.eng, r1.ID, 1); !errors.Is(err, postgres.ErrVersionConflict) {
		t.Errorf("stale submit: %v", err)
	}
	if err := f.svc.SubmitDiary(f.ctx, c.eng2, r1.ID, 2); !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("submit by someone else: %v", err)
	}
	must(t, "submit", f.svc.SubmitDiary(f.ctx, c.eng, r1.ID, 2))
	if _, err := f.svc.SaveDiary(f.ctx, c.eng, diaryIn(f, ref, 2, "40")); !errors.As(err, &conflict) || conflict.Status != "SUBMITTED" {
		t.Errorf("revision after submission: %v", err)
	}
	// Approval: not the author's role, not outside the project, a human PM.
	if err := f.svc.DecideDiary(f.ctx, c.eng, r1.ID, true, ""); !errors.Is(err, auth.ErrForbidden) {
		t.Errorf("approval by the author (no approve permission): %v", err)
	}
	if err := f.svc.DecideDiary(f.ctx, c.outsider, r1.ID, true, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("approval from outside the project: %v", err)
	}
	ai := c.pm
	ai.Kind = auth.KindAI
	if err := f.svc.DecideDiary(f.ctx, ai, r1.ID, true, ""); err == nil {
		t.Errorf("an AI principal approved a diary")
	}
	must(t, "approve", f.svc.DecideDiary(f.ctx, c.pm, r1.ID, true, ""))
	d, err := f.svc.GetP2PDoc(f.ctx, c.pm, "site_diary", r1.ID)
	must(t, "get", err)
	var detail struct {
		H struct {
			Status     string `json:"status"`
			ApprovedBy string `json:"approved_by"`
			Version    int    `json:"version"`
		} `json:"h"`
		Labour []struct {
			Hours   json.Number `json:"hours"`
			Version int         `json:"version"`
		} `json:"labour"`
	}
	must(t, "detail", json.Unmarshal(d.Detail, &detail))
	if detail.H.Status != "APPROVED" || detail.H.ApprovedBy != "u-site-pm" || detail.H.Version != 2 || len(detail.Labour) != 2 || detail.Labour[0].Hours.String() != "46.5" || detail.Labour[0].Version != 2 {
		t.Errorf("approved diary detail: %s", d.Detail)
	}
	// History: version 1's lines are kept.
	var v1 int
	must(t, "history", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM site_diary_labour WHERE diary_id = $1::uuid AND version = 1`, r1.ID).Scan(&v1)
	}))
	if v1 != 2 {
		t.Errorf("version 1 labour lines kept: %d", v1)
	}
	// The diary is visible to the project, not outside it.
	if _, err := f.svc.GetP2PDoc(f.ctx, c.outsider, "site_diary", r1.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("diary visible outside its project: %v", err)
	}
}

func syncOp(seq int64, kind string, payload any, at time.Time) SyncOp {
	b, _ := json.Marshal(payload)
	return SyncOp{OpID: uuid.NewString(), Seq: seq, Kind: kind, ClientTime: at, Payload: b}
}

func savePayload(f *fixture, ref string, base int, hours string) map[string]any {
	return map[string]any{"client_ref": ref, "project_id": f.project, "diary_date": time.Now().UTC().Format("2006-01-02"), "weather": "Overcast",
		"notes": "Formwork level 2", "base_version": base,
		"labour":    []map[string]any{{"trade": "Carpenters", "headcount": 5, "hours": hours}},
		"equipment": []map[string]any{{"description": "Tower crane TC-1", "hours": "7", "idle_hours": "1"}}}
}

func TestSync_IdempotencyConflictsAndRevocation(t *testing.T) {
	f := newFixture(t)
	c := newSiteCast(f)
	// Registration needs fresh MFA (the database requires it).
	if _, err := f.svc.RegisterDevice(f.ctx, c.eng, "Tablet A"); err == nil {
		t.Fatalf("device registered without fresh MFA")
	}
	dev, err := f.svc.RegisterDevice(f.ctx, fresh(c.eng), "Tablet A")
	must(t, "register", err)
	if !strings.HasPrefix(dev.Secret, "sfd_") || len(dev.Secret) < 40 {
		t.Fatalf("secret %q", dev.Secret)
	}
	var stored string
	must(t, "hash only", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT to_jsonb(d)::text FROM site_devices d WHERE id = $1::uuid`, dev.ID).Scan(&stored)
	}))
	if strings.Contains(stored, dev.Secret) || strings.Contains(stored, dev.Secret[4:]) {
		t.Errorf("the device secret is stored: %s", stored)
	}

	ref := uuid.NewString()
	offline := time.Now().Add(-3 * time.Hour) // queued while offline
	op1 := syncOp(1, "site_diary.save", savePayload(f, ref, 0, "40"), offline)
	op2 := syncOp(2, "site_diary.save", savePayload(f, ref, 1, "38.5"), offline.Add(time.Minute))
	res, err := f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{op1, op2})
	must(t, "sync", err)
	if res[0].Outcome != "APPLIED" || res[0].Version != 1 || res[1].Outcome != "APPLIED" || res[1].Version != 2 {
		t.Fatalf("first sync: %+v", res)
	}
	diaryID := res[0].DiaryID
	// The same commands again (lost acknowledgement): answered from the log.
	again, err := f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{op1, op2})
	must(t, "replay", err)
	if !again[0].Replayed || again[0].Outcome != "APPLIED" || again[0].Version != 1 || !again[1].Replayed || again[1].Version != 2 {
		t.Errorf("replay: %+v", again)
	}
	var version int
	must(t, "version", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT version FROM site_diaries WHERE id = $1::uuid`, diaryID).Scan(&version)
	}))
	if version != 2 {
		t.Errorf("replayed commands applied again: version %d", version)
	}
	// The same op id with a different payload is refused (not applied).
	forged := op2
	forged.Payload, _ = json.Marshal(savePayload(f, ref, 2, "1"))
	r, err := f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{forged})
	must(t, "forged replay", err)
	if r[0].Outcome != "REJECTED" || !strings.Contains(r[0].Error, "different command") {
		t.Errorf("op id reused with another payload: %+v", r[0])
	}
	// A new op id with an old sequence number is refused.
	r, _ = f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{syncOp(2, "site_diary.save", savePayload(f, ref, 2, "30"), time.Now())})
	if r[0].Outcome != "REJECTED" || !strings.Contains(r[0].Error, "sequence") {
		t.Errorf("stale sequence: %+v", r[0])
	}
	// Meanwhile the diary is revised online (version 3); the device's
	// revision based on version 2 is a CONFLICT, recorded, nothing merged.
	_, err = f.svc.SaveDiary(f.ctx, c.eng, DiaryInput{ClientRef: ref, ProjectID: f.project, DiaryDate: time.Now().UTC().Truncate(24 * time.Hour),
		Weather: "Overcast", Notes: "Edited at the site office", BaseVersion: 2,
		Labour: []DiaryLabour{{Trade: "Carpenters", Headcount: 5, Hours: decimal.RequireFromString("39")}}})
	must(t, "online revision", err)
	op3 := syncOp(3, "site_diary.save", savePayload(f, ref, 2, "37"), time.Now())
	r, err = f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{op3})
	must(t, "conflict sync", err)
	if r[0].Outcome != "CONFLICT" || r[0].ServerVersion != 3 || r[0].ServerStatus != "DRAFT" {
		t.Errorf("conflict: %+v", r[0])
	}
	// Re-based on version 3 and submitted, in one batch.
	op4 := syncOp(4, "site_diary.save", savePayload(f, ref, 3, "37"), time.Now())
	op5 := syncOp(5, "site_diary.submit", map[string]any{"client_ref": ref, "base_version": 4}, time.Now())
	r, err = f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{op4, op5})
	must(t, "rebase and submit", err)
	if r[0].Outcome != "APPLIED" || r[0].Version != 4 || r[1].Outcome != "APPLIED" || r[1].Status != "SUBMITTED" {
		t.Errorf("rebase and submit: %+v", r)
	}
	// The log keeps the claimed device time as evidence, next to the server's.
	var claimed, received time.Time
	var n int
	must(t, "log", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM site_sync_commands WHERE device_id = $1::uuid`, dev.ID).Scan(&n); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT client_time, received_at FROM site_sync_commands WHERE device_id = $1::uuid AND client_op_id = $2::uuid`, dev.ID, op1.OpID).Scan(&claimed, &received)
	}))
	if n != 5 || claimed.Unix() != offline.Unix() || received.Sub(claimed) < 2*time.Hour {
		t.Errorf("command log: %d rows, claimed %v received %v", n, claimed, received)
	}

	// Device credentials: wrong secret, another person's device.
	if _, err := f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret+"x", []SyncOp{syncOp(6, "site_diary.save", savePayload(f, uuid.NewString(), 0, "8"), time.Now())}); !errors.Is(err, ErrDeviceRefused) {
		t.Errorf("wrong secret: %v", err)
	}
	if _, err := f.svc.Sync(f.ctx, c.eng2, dev.ID, dev.Secret, []SyncOp{syncOp(6, "site_diary.save", savePayload(f, uuid.NewString(), 0, "8"), time.Now())}); !errors.Is(err, ErrDeviceRefused) {
		t.Errorf("someone else's device: %v", err)
	}

	// Lost device: a command queued BEFORE the revocation, arriving after it,
	// is refused. Revocation by the security administrator (not the owner).
	queued := syncOp(6, "site_diary.save", savePayload(f, uuid.NewString(), 0, "8"), time.Now().Add(-time.Hour))
	if err := f.svc.RevokeDevice(f.ctx, c.eng2, dev.ID, "Not my device"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revocation of another person's device by a peer: %v", err)
	}
	must(t, "revoke", f.svc.RevokeDevice(f.ctx, c.secAdmin, dev.ID, "Tablet reported stolen at gate 2"))
	if _, err := f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{queued}); !errors.Is(err, ErrDeviceRefused) {
		t.Errorf("sync after revocation: %v", err)
	}
	var refusals int
	must(t, "audit", f.admin.QueryRow(f.ctx, `SELECT count(*) FROM audit_log WHERE tenant_id = $1::uuid AND action = 'site.sync_refused' AND aggregate_id = $2`, f.tenant, dev.ID).Scan(&refusals))
	if refusals < 3 {
		t.Errorf("sync refusals audited: %d", refusals)
	}
	if err := f.svc.RevokeDevice(f.ctx, c.eng, dev.ID, "Again please"); err == nil {
		t.Errorf("a revoked device was revoked again")
	}
	devs, err := f.svc.ListDevices(f.ctx, c.eng)
	must(t, "list", err)
	if len(devs) != 1 || devs[0].Status != "REVOKED" || devs[0].LastSeq != 5 {
		t.Errorf("devices: %+v", devs)
	}
	// Approval of the device-made diary by the project manager.
	must(t, "approve", f.svc.DecideDiary(f.ctx, c.pm, diaryID, true, ""))
}

// The database enforces the rules without the kernel: raw statements with
// the tenant credential.
func TestOffline_DatabaseRules(t *testing.T) {
	f := newFixture(t)
	c := newSiteCast(f)
	dev, err := f.svc.RegisterDevice(f.ctx, fresh(c.eng), "Tablet B")
	must(t, "register", err)
	ref := uuid.NewString()
	r, err := f.svc.SaveDiary(f.ctx, c.eng, diaryIn(f, ref, 0, "48"))
	must(t, "create", err)
	raw := func(name, sql string, args ...any) error {
		t.Helper()
		err := f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql, args...)
			return err
		})
		if err == nil {
			t.Errorf("OPEN: %s accepted", name)
		} else {
			t.Logf("held: %-62s %s", name, firstLine(err.Error()))
		}
		return err
	}
	raw("lines added without an attested revision",
		`INSERT INTO site_diary_labour(diary_id, version, line_no, trade, headcount, hours) VALUES ($1::uuid, 1, 9, 'Ghost gang', 10, 80)`, r.ID)
	raw("revision without attestation (version bump)", `UPDATE site_diaries SET version = 2, notes = 'changed' WHERE id = $1::uuid`, r.ID)
	raw("content change without a version step", `UPDATE site_diaries SET notes = 'quietly changed' WHERE id = $1::uuid`, r.ID)
	raw("diary inserted without attestation",
		`INSERT INTO site_diaries(project_id, number, client_ref, diary_date, weather, created_by) VALUES ($1::uuid, 'SDY-X-1', $2::uuid, current_date - 1, 'Rain', 'u-site-eng')`,
		f.project, uuid.NewString())
	raw("submission without attestation", `UPDATE site_diaries SET status = 'SUBMITTED' WHERE id = $1::uuid`, r.ID)
	raw("diary dated in the future",
		`INSERT INTO site_diaries(project_id, number, client_ref, diary_date, weather, created_by) VALUES ($1::uuid, 'SDY-X-2', $2::uuid, current_date + 7, 'Rain', 'u-site-eng')`,
		f.project, uuid.NewString())
	raw("diary from another person's device",
		`INSERT INTO site_diaries(project_id, number, client_ref, diary_date, weather, created_by, origin_device_id) VALUES ($1::uuid, 'SDY-X-3', $2::uuid, current_date - 2, 'Rain', 'u-site-eng-2', $3::uuid)`,
		f.project, uuid.NewString(), dev.ID)
	raw("device key replaced", `UPDATE site_devices SET key_hash = repeat('b', 64) WHERE id = $1::uuid`, dev.ID)
	raw("device sequence moved without a command", `UPDATE site_devices SET last_seq = 99 WHERE id = $1::uuid`, dev.ID)
	raw("device revoked without attestation", `UPDATE site_devices SET status = 'REVOKED', revoked_by = 'u-site-eng', revoke_reason = 'test only' WHERE id = $1::uuid`, dev.ID)
	raw("command log row deleted", `DELETE FROM site_sync_commands`)
	raw("command for another person's device",
		`INSERT INTO site_sync_commands(device_id, client_op_id, seq, kind, actor, payload_sha256, client_time, outcome, result) VALUES ($1::uuid, $2::uuid, 1, 'site_diary.save', 'u-site-eng-2', repeat('a', 64), now(), 'REJECTED', '{}')`,
		dev.ID, uuid.NewString())
	raw("applied command naming a diary it did not write",
		`INSERT INTO site_sync_commands(device_id, client_op_id, seq, kind, actor, payload_sha256, client_time, outcome, diary_id, result) VALUES ($1::uuid, $2::uuid, 1, 'site_diary.save', 'u-site-eng', repeat('a', 64), now(), 'APPLIED', $3::uuid, '{}')`,
		dev.ID, uuid.NewString(), uuid.NewString())
	must(t, "revoke", f.svc.RevokeDevice(f.ctx, fresh(c.eng), dev.ID, "Handset replaced"))
	raw("revoked device reactivated", `UPDATE site_devices SET status = 'ACTIVE', revoked_by = NULL, revoked_at = NULL, revoke_reason = NULL WHERE id = $1::uuid`, dev.ID)
	raw("command for a revoked device",
		`INSERT INTO site_sync_commands(device_id, client_op_id, seq, kind, actor, payload_sha256, client_time, outcome, result) VALUES ($1::uuid, $2::uuid, 7, 'site_diary.save', 'u-site-eng', repeat('a', 64), now(), 'REJECTED', '{}')`,
		dev.ID, uuid.NewString())
	// The approved content is the attested content: approval after a raw
	// change attempt still sees the original lines.
	must(t, "submit", f.svc.SubmitDiary(f.ctx, c.eng, r.ID, 1))
	must(t, "approve", f.svc.DecideDiary(f.ctx, c.pm, r.ID, true, ""))
	raw("approved diary edited", `UPDATE site_diaries SET weather = 'Storm' WHERE id = $1::uuid`, r.ID)
	var lines int
	must(t, "lines", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM site_diary_labour WHERE diary_id = $1::uuid`, r.ID).Scan(&lines)
	}))
	if lines != 2 {
		t.Errorf("labour lines after the attempts: %d", lines)
	}
}

// A command retried while the first attempt is still in flight (flaky field
// connectivity) is applied exactly once; two different commands carrying the
// same sequence number cannot both be applied; a revocation racing a sync
// leaves no command applied after it commits.
func TestSync_ConcurrentRetriesApplyOnce(t *testing.T) {
	f := newFixture(t)
	c := newSiteCast(f)
	dev, err := f.svc.RegisterDevice(f.ctx, fresh(c.eng), "Tablet C")
	must(t, "register", err)
	ref := uuid.NewString()
	op := syncOp(1, "site_diary.save", savePayload(f, ref, 0, "40"), time.Now())
	const n = 8
	type out struct {
		r   []SyncResult
		err error
	}
	results := make(chan out, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		go func() {
			<-start
			r, err := f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{op})
			results <- out{r, err}
		}()
	}
	close(start)
	applied, replayed := 0, 0
	for i := 0; i < n; i++ {
		o := <-results
		if o.err != nil {
			t.Errorf("concurrent sync: %v", o.err)
			continue
		}
		switch {
		case o.r[0].Outcome == "APPLIED" && !o.r[0].Replayed:
			applied++
		case o.r[0].Outcome == "APPLIED" && o.r[0].Replayed:
			replayed++
		default:
			t.Logf("other outcome: %+v", o.r[0])
		}
	}
	var diaries, commands int
	must(t, "count", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM site_diaries WHERE client_ref = $1::uuid`, ref).Scan(&diaries); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM site_sync_commands WHERE device_id = $1::uuid`, dev.ID).Scan(&commands)
	}))
	if applied != 1 || diaries != 1 || commands != 1 {
		t.Errorf("%d concurrent retries: applied %d, replayed %d, diaries %d, logged commands %d (want 1/%d/1/1)", n, applied, replayed, diaries, commands, n-1)
	} else {
		t.Logf("held: %d concurrent retries: applied once, %d answered from the log", n, replayed)
	}

	// Two different commands with the same next sequence number, concurrently.
	a := syncOp(2, "site_diary.save", savePayload(f, ref, 1, "41"), time.Now())
	b := syncOp(2, "site_diary.save", savePayload(f, ref, 1, "42"), time.Now())
	ra, rb := make(chan []SyncResult, 1), make(chan []SyncResult, 1)
	go func() { r, _ := f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{a}); ra <- r }()
	go func() { r, _ := f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, []SyncOp{b}); rb <- r }()
	x, y := <-ra, <-rb
	if (x[0].Outcome == "APPLIED") == (y[0].Outcome == "APPLIED") {
		t.Errorf("same sequence twice: %+v / %+v", x[0], y[0])
	}

	// Revocation racing a sync: whatever order the database chose, nothing
	// is applied after the revocation committed.
	ops := []SyncOp{}
	for i := 0; i < 20; i++ {
		ops = append(ops, syncOp(int64(3+i), "site_diary.save", savePayload(f, uuid.NewString(), 0, "8"), time.Now()))
	}
	// Each command is a diary for the same project and date: the first is
	// applied, the rest are refused as duplicates of the day; the race is on
	// the device lock, which both paths take.
	done := make(chan struct{})
	go func() { _, _ = f.svc.Sync(f.ctx, c.eng, dev.ID, dev.Secret, ops); close(done) }()
	must(t, "revoke", f.svc.RevokeDevice(f.ctx, fresh(c.eng), dev.ID, "Racing the sync on purpose"))
	<-done
	var after int
	must(t, "after", f.app.WithTenant(f.ctx, f.tenant, func(ctx context.Context, tx pgx.Tx) error {
		// A revoked device row never changes, so its last_seq is frozen at the
		// revocation; every recorded command moves last_seq in its own
		// transaction, so a command recorded after the revocation would
		// exceed it.
		return tx.QueryRow(ctx, `SELECT count(*) FROM site_sync_commands c JOIN site_devices d ON d.id = c.device_id
			WHERE c.device_id = $1::uuid AND c.seq > d.last_seq`, dev.ID).Scan(&after)
	}))
	if after != 0 {
		t.Errorf("OPEN: %d command(s) recorded after the revocation committed", after)
	} else {
		t.Logf("held: no command recorded after the revocation")
	}
}
