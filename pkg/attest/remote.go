package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"time"
)

// Remote issues attestations through the separate serk-signer process
// (R-SIGNER): the API holds no signing secret. The signer receives the
// claims together with the person's own bearer token, re-verifies that
// token, and signs only claims the token supports (same tenant and actor,
// MFA only if the token carries it, permissions the roles grant). A
// compromised API process therefore cannot manufacture approvals for people
// who are not logged in, and every issuance is logged by the signer.
//
// Transport: HTTP over a unix socket shared with the signer (same host or
// pod). The socket's file mode is the access control; the API cannot read
// the secret and the signer exposes nothing else.
type Remote struct {
	Socket  string
	Timeout time.Duration
	client  *http.Client
}

// ErrNoBearer: the context carries no end-user credential, so the signer
// would have nothing to verify. Background work never issues attestations.
var ErrNoBearer = errors.New("attest: no end-user credential in context for the signer")

type bearerKey struct{}

// WithBearer stores the person's raw bearer token for the remote signer. It
// is set by the API's authentication middleware and read only here.
func WithBearer(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, bearerKey{}, token)
}

// BearerFrom returns the stored bearer token ("" when none).
func BearerFrom(ctx context.Context) string {
	t, _ := ctx.Value(bearerKey{}).(string)
	return t
}

// SignRequest is the wire format (signer side: internal/signer).
type SignRequest struct {
	Claims Claims `json:"claims"`
}

// SignResponse is the wire format.
type SignResponse struct {
	Attestation *Attestation `json:"attestation,omitempty"`
	Error       string       `json:"error,omitempty"`
}

func (r *Remote) http() *http.Client {
	if r.client == nil {
		sock := r.Socket
		r.client = &http.Client{Timeout: r.timeout(), Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", sock)
			},
			MaxIdleConns: 8, IdleConnTimeout: 60 * time.Second}}
	}
	return r.client
}

func (r *Remote) timeout() time.Duration {
	if r.Timeout <= 0 {
		return 3 * time.Second
	}
	return r.Timeout
}

// Issue implements Issuer.
func (r *Remote) Issue(ctx context.Context, c Claims) (Attestation, error) {
	tok := BearerFrom(ctx)
	if tok == "" {
		return Attestation{}, ErrNoBearer
	}
	body, _ := json.Marshal(SignRequest{Claims: c})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://serk-signer/v1/sign", bytes.NewReader(body))
	if err != nil {
		return Attestation{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := r.http().Do(req)
	if err != nil {
		return Attestation{}, fmt.Errorf("%w: signer unreachable: %v", ErrInvalid, err)
	}
	defer resp.Body.Close()
	var out SignResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return Attestation{}, fmt.Errorf("%w: signer response: %v", ErrInvalid, err)
	}
	if resp.StatusCode != http.StatusOK || out.Attestation == nil {
		if out.Error == "" {
			out.Error = resp.Status
		}
		return Attestation{}, fmt.Errorf("%w: signer refused: %s", ErrInvalid, out.Error)
	}
	// The API trusts the signer for the signature only; the claims it sent
	// must come back unchanged, so a signer cannot widen them.
	got := out.Attestation.Claims
	if got.Tenant != c.Tenant || got.Actor != c.Actor || got.Action != c.Action || got.SubjectType != c.SubjectType ||
		got.SubjectID != c.SubjectID || got.SubjectHash != c.SubjectHash || got.Context != c.Context || got.MFA != c.MFA ||
		got.AuthTime != c.AuthTime || !samePerms(got.Perms, c.Perms) {
		return Attestation{}, fmt.Errorf("%w: signer altered the claims", ErrInvalid)
	}
	// R10-F6: the fields the signer fills must be well formed.
	now := time.Now().Unix()
	if got.V != Version || got.KeyID == "" || len(got.KeyID) > 16 || !nonceForm.MatchString(got.Nonce) || !sigForm.MatchString(out.Attestation.Sig) ||
		got.ExpiresAt <= got.IssuedAt || got.ExpiresAt-got.IssuedAt > int64(MaxTTL/time.Second) || got.IssuedAt > now+60 || got.IssuedAt < now-int64(MaxTTL/time.Second)-60 || got.ExpiresAt <= now {
		return Attestation{}, fmt.Errorf("%w: malformed attestation from the signer", ErrInvalid)
	}
	return *out.Attestation, nil
}

var (
	nonceForm = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	sigForm   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func samePerms(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
