package datakey

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestRoundTripBindingAndRotation(t *testing.T) {
	m1, m2 := make([]byte, 32), make([]byte, 32)
	rand.Read(m1)
	rand.Read(m2)
	r := Ring{Current: Key{ID: "k1", Master: m1}}
	ct, err := r.Encrypt("t1", AAD("supplier_bank_accounts", "row-1", "t1"), []byte("1000123456789"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("1000123456789")) {
		t.Fatal("plaintext in ciphertext")
	}
	pt, err := r.Decrypt("t1", AAD("supplier_bank_accounts", "row-1", "t1"), ct)
	if err != nil || string(pt) != "1000123456789" {
		t.Fatalf("round trip: %q %v", pt, err)
	}
	// Bound to the row, the table and the tenant.
	for name, aad := range map[string][]byte{"other row": AAD("supplier_bank_accounts", "row-2", "t1"),
		"other table": AAD("company_bank_accounts", "row-1", "t1"), "other tenant": AAD("supplier_bank_accounts", "row-1", "t2")} {
		if _, err := r.Decrypt("t1", aad, ct); err == nil {
			t.Errorf("%s: decrypted", name)
		}
	}
	if _, err := r.Decrypt("t2", AAD("supplier_bank_accounts", "row-1", "t1"), ct); err == nil {
		t.Error("another tenant's subkey decrypted")
	}
	// Rotation: a new current key still reads the old ciphertext while the
	// old key is in Previous, and not after it is dropped.
	r2 := Ring{Current: Key{ID: "k2", Master: m2}, Previous: []Key{{ID: "k1", Master: m1}}}
	if pt, err := r2.Decrypt("t1", AAD("supplier_bank_accounts", "row-1", "t1"), ct); err != nil || string(pt) != "1000123456789" {
		t.Errorf("rotated ring cannot read old ciphertext: %v", err)
	}
	if _, err := (Ring{Current: Key{ID: "k2", Master: m2}}).Decrypt("t1", AAD("supplier_bank_accounts", "row-1", "t1"), ct); err == nil {
		t.Error("ciphertext under a dropped key decrypted")
	}
	// Tampering.
	bad := append([]byte(nil), ct...)
	bad[len(bad)-1] ^= 1
	if _, err := r.Decrypt("t1", AAD("supplier_bank_accounts", "row-1", "t1"), bad); err == nil {
		t.Error("tampered ciphertext decrypted")
	}
	if _, err := (Ring{Current: Key{ID: "k", Master: []byte("short")}}).Encrypt("t", nil, []byte("x")); err == nil {
		t.Error("short master accepted")
	}
}

func TestDigestIsKeyedAndPerTenant(t *testing.T) {
	k1, k2 := make([]byte, 32), make([]byte, 32)
	rand.Read(k1)
	rand.Read(k2)
	a, _ := Digest(k1, "t1", "1000123456789")
	b, _ := Digest(k1, "t1", "1000123456789")
	c, _ := Digest(k1, "t2", "1000123456789")
	d, _ := Digest(k2, "t1", "1000123456789")
	if a != b || a == c || a == d || len(a) != 69 || a[:5] != "hkey:" {
		t.Errorf("digest: %s %s %s %s", a, b, c, d)
	}
	if _, err := Digest([]byte("short"), "t1", "x"); err == nil {
		t.Error("short digest key accepted")
	}
}
