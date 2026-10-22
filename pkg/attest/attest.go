// Package attest issues and verifies approval attestations: short-lived,
// single-use, HMAC-SHA256-signed statements that a specific authenticated
// person, holding specific permissions and (optionally) a fresh multi-factor
// login, authorises one action on one subject in its current content.
//
// The issuer is either the API's kernel (development: the signing secret is
// in the API process) or, in production, the separate serk-signer process
// (remote.go): it holds the signing secret, re-verifies the person's own
// bearer token, and signs only claims that token supports. The verifier is
// PostgreSQL
// (approval_authorize(), migration 0007), which holds the per-tenant
// verification key in a table no application login can read. A stolen or
// injected tenant database credential therefore cannot manufacture an
// approval: it has no key, and every sensitive transition requires a
// verified attestation recorded in the same transaction.
//
// The canonical message is the fields below joined with U+001F, in this
// exact order; the SQL verifier builds the same string (keep in sync with
// approval_canonical() in 0007_approval_attestation.sql).
package attest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Version of the canonical format.
const Version = 1

// MaxTTL is the longest lifetime the database accepts.
const MaxTTL = 5 * time.Minute

// Claims is the signed content of an attestation.
type Claims struct {
	V           int      `json:"v"`
	KeyID       string   `json:"kid"`
	Tenant      string   `json:"tenant"`
	Actor       string   `json:"actor"`
	Action      string   `json:"action"`
	SubjectType string   `json:"subject_type"`
	SubjectID   string   `json:"subject_id"`
	SubjectHash string   `json:"subject_hash"`
	Context     string   `json:"ctx"`
	Perms       []string `json:"perms"`
	MFA         bool     `json:"mfa"`
	AuthTime    int64    `json:"auth_time"`
	IssuedAt    int64    `json:"iat"`
	ExpiresAt   int64    `json:"exp"`
	Nonce       string   `json:"nonce"`
}

// Attestation is Claims plus the hex HMAC-SHA256 signature.
type Attestation struct {
	Claims
	Sig string `json:"sig"`
}

// Canonical returns the exact byte string that is signed.
func (c Claims) Canonical() string {
	perms := append([]string(nil), c.Perms...)
	sort.Strings(perms)
	mfa := "0"
	if c.MFA {
		mfa = "1"
	}
	return strings.Join([]string{
		strconv.Itoa(c.V), c.KeyID, c.Tenant, c.Actor, c.Action, c.SubjectType, c.SubjectID, c.SubjectHash, c.Context,
		strings.Join(perms, ","), mfa, strconv.FormatInt(c.AuthTime, 10), strconv.FormatInt(c.IssuedAt, 10),
		strconv.FormatInt(c.ExpiresAt, 10), c.Nonce,
	}, "\x1f")
}

// TenantKey derives a tenant's verification key from the master signing
// secret: HMAC-SHA256(master, "serk-approval:" + tenant). The database stores
// the derived key, never the master.
func TenantKey(master []byte, tenant string) []byte {
	m := hmac.New(sha256.New, master)
	m.Write([]byte("serk-approval:" + tenant))
	return m.Sum(nil)
}

// Errors.
var (
	ErrInvalid = errors.New("attest: invalid attestation")
)

// Issuer issues attestations: Signer (in-process) or Remote (serk-signer).
type Issuer interface {
	Issue(ctx context.Context, c Claims) (Attestation, error)
}

// Signer issues attestations with the signing secret in this process.
type Signer struct {
	Master []byte
	KeyID  string
	TTL    time.Duration
	Now    func() time.Time
}

// Issue implements Issuer.
func (s Signer) Issue(_ context.Context, c Claims) (Attestation, error) { return s.Sign(c) }

// Sign completes c (version, key id, times, nonce) and signs it.
func (s Signer) Sign(c Claims) (Attestation, error) {
	if len(s.Master) < 32 {
		return Attestation{}, fmt.Errorf("%w: signing secret must be at least 32 bytes", ErrInvalid)
	}
	if strings.ContainsRune(c.Tenant+c.Actor+c.Action+c.SubjectType+c.SubjectID+c.SubjectHash+c.Context+s.KeyID+strings.Join(c.Perms, ""), '\x1f') {
		return Attestation{}, fmt.Errorf("%w: separator in a field", ErrInvalid)
	}
	for _, p := range c.Perms {
		if p == "" || strings.ContainsRune(p, ',') {
			return Attestation{}, fmt.Errorf("%w: empty permission or comma in a permission", ErrInvalid)
		}
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	ttl := s.TTL
	if ttl <= 0 || ttl > MaxTTL {
		ttl = 2 * time.Minute
	}
	t := now().UTC()
	c.V, c.KeyID = Version, s.KeyID
	if c.KeyID == "" {
		c.KeyID = "v1"
	}
	c.IssuedAt, c.ExpiresAt = t.Unix(), t.Add(ttl).Unix()
	c.Nonce = uuid.NewString()
	if c.Perms == nil {
		c.Perms = []string{}
	}
	sort.Strings(c.Perms)
	m := hmac.New(sha256.New, TenantKey(s.Master, c.Tenant))
	m.Write([]byte(c.Canonical()))
	return Attestation{Claims: c, Sig: hex.EncodeToString(m.Sum(nil))}, nil
}

// Verify checks a signature with a tenant key (used by tests and tooling;
// production verification happens in PostgreSQL).
func Verify(key []byte, a Attestation, now time.Time) error {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(a.Canonical()))
	want := m.Sum(nil)
	got, err := hex.DecodeString(a.Sig)
	if err != nil || !hmac.Equal(want, got) {
		return fmt.Errorf("%w: signature", ErrInvalid)
	}
	if now.Unix() >= a.ExpiresAt || a.ExpiresAt-a.IssuedAt > int64(MaxTTL/time.Second) {
		return fmt.Errorf("%w: expired", ErrInvalid)
	}
	return nil
}

// JSON encodes the attestation for transport to the database.
func (a Attestation) JSON() string {
	b, _ := json.Marshal(a)
	return string(b)
}
