package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// syncReq posts /v1/sync with device credentials in headers.
func (a *p2pAPI) syncReq(token, deviceID, secret string, ops []map[string]any) (int, map[string]any) {
	a.t.Helper()
	b, _ := json.Marshal(map[string]any{"ops": ops})
	req, _ := http.NewRequest("POST", a.srv.URL+"/v1/sync", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if deviceID != "" {
		req.Header.Set(headerDeviceID, deviceID)
		req.Header.Set(headerDeviceKey, secret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func siteOp(seq int, kind string, payload map[string]any, at time.Time) map[string]any {
	return map[string]any{"op_id": uuid.NewString(), "seq": seq, "kind": kind, "client_time": at.UTC().Format(time.RFC3339), "payload": payload}
}

// TestSync_APIDeviceDiaryApproval: register a device (step-up), sync an
// offline diary and its submission, replay, approve, online revisions with a
// conflict, revocation of the device and of the person's sessions.
func TestSync_APIDeviceDiaryApproval(t *testing.T) {
	a := newP2PAPI(t)
	P := []string{a.project}
	eng, engMFA := a.tok("u-site-eng", P, false, "site_engineer"), a.tok("u-site-eng", P, true, "site_engineer")
	pm := a.tok("u-site-pm", P, false, "project_manager")
	sec := a.tok("u-sec", nil, false, "security_admin")

	if st, out := a.do("POST", "/v1/site/devices", eng, map[string]any{"label": "Tablet 7"}); st != 401 || !strings.Contains(asJSON(out), "step_up_required") {
		t.Errorf("device registration without step-up: %d %v", st, out)
	}
	st, reg := a.do("POST", "/v1/site/devices", engMFA, map[string]any{"label": "Tablet 7"})
	if st != 201 || reg["id"] == nil || !strings.HasPrefix(reg["secret"].(string), "sfd_") {
		t.Fatalf("register: %d %v", st, reg)
	}
	dev, secret := reg["id"].(string), reg["secret"].(string)
	list := a.call(200, "GET", "/v1/site/devices", eng, nil)
	if items := list["items"].([]any); len(items) != 1 || strings.Contains(asJSON(list), "key_hash") || strings.Contains(asJSON(list), secret) {
		t.Errorf("device list: %v", list)
	}

	ref := uuid.NewString()
	yesterday := time.Now().AddDate(0, 0, -1).UTC().Format("2006-01-02")
	save := map[string]any{"client_ref": ref, "project_id": a.project, "diary_date": yesterday, "weather": "Light rain until 10:00", "notes": "Drainage trench chainage 2+300",
		"base_version": 0, "labour": []map[string]any{{"trade": "Labourers", "headcount": 12, "hours": "96"}},
		"equipment": []map[string]any{{"description": "Excavator CAT 320", "hours": "7.5", "idle_hours": "0.5"}}}
	ops := []map[string]any{siteOp(1, "site_diary.save", save, time.Now().Add(-20*time.Hour)),
		siteOp(2, "site_diary.submit", map[string]any{"client_ref": ref, "base_version": 1}, time.Now().Add(-19*time.Hour))}
	if st, out := a.syncReq(eng, "", "", ops); st != 403 || !strings.Contains(asJSON(out), "device_refused") {
		t.Errorf("sync without device credentials: %d %v", st, out)
	}
	if st, _ := a.syncReq(pm, dev, secret, ops); st != 403 {
		t.Errorf("sync by a person without site.diary.manage: %d", st)
	}
	st, out := a.syncReq(eng, dev, secret, ops)
	res, _ := out["results"].([]any)
	if st != 200 || len(res) != 2 || res[0].(map[string]any)["outcome"] != "APPLIED" || res[1].(map[string]any)["status"] != "SUBMITTED" {
		t.Fatalf("sync: %d %v", st, out)
	}
	diary := res[0].(map[string]any)["diary_id"].(string)
	// Lost acknowledgement: the device sends the same batch again.
	_, out = a.syncReq(eng, dev, secret, ops)
	if r := out["results"].([]any); r[0].(map[string]any)["replayed"] != true || r[1].(map[string]any)["replayed"] != true {
		t.Errorf("replay: %v", out)
	}
	// The project manager approves; the author cannot.
	if st, _ := a.do("POST", "/v1/site/diaries/"+diary+"/approve", eng, nil); st != 403 {
		t.Errorf("approval by the author: %d", st)
	}
	a.call(200, "POST", "/v1/site/diaries/"+diary+"/approve", pm, nil)
	approved := a.call(200, "GET", "/v1/p2p/site_diary?status=APPROVED", pm, nil)
	if !strings.Contains(asJSON(approved), diary) {
		t.Errorf("approved diaries: %v", approved)
	}

	// Online diary: create (201), revise (200), stale revision (409).
	ref2 := uuid.NewString()
	body := map[string]any{"client_ref": ref2, "project_id": a.project, "diary_date": time.Now().UTC().Format("2006-01-02"), "weather": "Clear", "notes": "Compaction tests",
		"base_version": 0, "labour": []map[string]any{{"trade": "Surveyors", "headcount": 2, "hours": "16"}}}
	created := a.call(201, "POST", "/v1/site/diaries", eng, body)
	body["base_version"] = 1
	body["notes"] = "Compaction tests: 3 of 4 passed"
	if r := a.call(200, "POST", "/v1/site/diaries", eng, body); r["version"] != float64(2) || r["id"] != created["id"] {
		t.Errorf("revision: %v", r)
	}
	if st, out := a.do("POST", "/v1/site/diaries", eng, body); st != 409 || !strings.Contains(asJSON(out), "version_conflict") {
		t.Errorf("stale revision: %d %v", st, out)
	}

	// Revocation by the security administrator; the device can no longer sync.
	if st, _ := a.do("POST", "/v1/site/devices/"+dev+"/revoke", sec, map[string]any{}); st != 422 {
		t.Errorf("revocation without a reason: %d", st)
	}
	a.call(200, "POST", "/v1/site/devices/"+dev+"/revoke", sec, map[string]any{"reason": "Reported lost by the site engineer"})
	if st, _ := a.syncReq(eng, dev, secret, []map[string]any{siteOp(3, "site_diary.save", save, time.Now())}); st != 403 {
		t.Errorf("sync with a revoked device: %d", st)
	}

	// A new device, then the person's sessions are revoked: the old token
	// cannot sync even with a valid device.
	_, reg2 := a.do("POST", "/v1/site/devices", engMFA, map[string]any{"label": "Tablet 8"})
	dev2, secret2 := reg2["id"].(string), reg2["secret"].(string)
	time.Sleep(1100 * time.Millisecond)
	a.call(200, "POST", "/v1/identity/sessions/revoke", sec, map[string]any{"subject": "u-site-eng", "reason": "Phone stolen with the app signed in"})
	if st, _ := a.syncReq(eng, dev2, secret2, []map[string]any{siteOp(1, "site_diary.save", save, time.Now())}); st != 401 {
		t.Errorf("sync with a revoked session: %d", st)
	}
}

func asJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
