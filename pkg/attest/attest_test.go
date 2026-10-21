package attest

import (
	"errors"
	"strings"
	"testing"
	"time"
)

var master = []byte("test-master-signing-secret-0123456789abcdef")

func TestSignVerifyAndTamper(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	s := Signer{Master: master, Now: func() time.Time { return now }}
	a, err := s.Sign(Claims{Tenant: "t1", Actor: "alice", Action: "journal.approve", SubjectType: "journal", SubjectID: "j1",
		SubjectHash: "abc", Perms: []string{"journal.read", "journal.approve"}, MFA: true, AuthTime: now.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	key := TenantKey(master, "t1")
	if err := Verify(key, a, now); err != nil {
		t.Fatal(err)
	}
	if a.Perms[0] != "journal.approve" || a.ExpiresAt-a.IssuedAt != 120 || a.Nonce == "" {
		t.Fatalf("claims %+v", a.Claims)
	}
	for name, mut := range map[string]func(*Attestation){
		"actor":   func(x *Attestation) { x.Actor = "mallory" },
		"subject": func(x *Attestation) { x.SubjectID = "j2" },
		"hash":    func(x *Attestation) { x.SubjectHash = "abd" },
		"mfa":     func(x *Attestation) { x.MFA = false },
		"perms":   func(x *Attestation) { x.Perms = append(x.Perms, "journal.post") },
		"expiry":  func(x *Attestation) { x.ExpiresAt += 3600 },
		"tenant":  func(x *Attestation) { x.Tenant = "t2" },
	} {
		b := a
		b.Perms = append([]string(nil), a.Perms...)
		mut(&b)
		if err := Verify(key, b, now); !errors.Is(err, ErrInvalid) {
			t.Errorf("tampered %s accepted", name)
		}
	}
	if err := Verify(TenantKey(master, "t2"), a, now); err == nil {
		t.Fatal("other tenant's key verified")
	}
	if err := Verify(key, a, now.Add(3*time.Minute)); err == nil {
		t.Fatal("expired attestation verified")
	}
	if _, err := s.Sign(Claims{Tenant: "t1", Actor: "a\x1fb"}); err == nil {
		t.Fatal("separator injection signed")
	}
	if _, err := (Signer{Master: []byte("short")}).Sign(Claims{}); err == nil {
		t.Fatal("short secret accepted")
	}
	if !strings.Contains(a.JSON(), `"sig"`) {
		t.Fatal("json")
	}
}
