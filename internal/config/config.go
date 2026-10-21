// Package config loads and validates runtime configuration (SC-06).
//
// The environment defaults to "production" so that forgetting to set it can
// never silently enable development relaxations. Production refuses: shared
// HMAC tokens (OIDC only), plaintext or unverified database TLS, superuser
// database logins, weak or well-known secrets, wildcard trusted proxies, and
// relaxed segregation of duties. Secrets may be supplied inline (VAR) or via
// a file (VAR_FILE, e.g. Docker/Kubernetes secrets); never both.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Env is the deployment environment.
type Env string

const (
	Development Env = "development"
	Staging     Env = "staging"
	Production  Env = "production"
)

// Config is the validated API configuration.
type Config struct {
	Env    Env
	Listen string

	DBBaseDSN      string            // postgres URL without user info
	TenantDBSecret []byte            // derives per-tenant role passwords
	ApprovalSecret []byte            // signs approval attestations (GATEA-APPROVAL-01); distinct from TenantDBSecret
	HealthDSN      string            // privilege-less role for readiness
	DedicatedDSNs  map[string]string // tenant -> DSN (DEDICATED_DB tier)

	// Authentication: OIDC (required in production) or HS256 (dev/staging).
	OIDCIssuer, OIDCAudience, OIDCJWKSURL              string
	OIDCTenantClaim, OIDCRolesClaim, OIDCProjectsClaim string
	HS256Secret                                        []byte
	TokenIssuer, TokenAudience                         string

	SoDStrict          bool
	RatePerMinute      int
	PreAuthPerMinute   int
	AuthFailuresPerMin int
	TrustedProxies     []netip.Prefix

	// Workflow timers (SLA escalation, expiry). Enabled when SchedulerDSN is
	// set: a login that is a member of serk_scheduler only.
	SchedulerDSN          string
	WorkflowTimerInterval int // seconds

	// Observability (GATEA-11). MetricsListen serves /metrics on a separate,
	// internal-only listener ("" = disabled). MonitorDSN is a login that is a
	// member of serk_monitor only (EXECUTE ops_health_metrics()).
	MetricsListen string
	MonitorDSN    string
}

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("config: invalid")

// Source abstracts the process environment and filesystem for tests.
type Source struct {
	Getenv   func(string) string
	ReadFile func(string) ([]byte, error)
}

// OS is the real process environment.
var OS = Source{Getenv: os.Getenv, ReadFile: os.ReadFile}

func (s Source) secret(name string) ([]byte, error) {
	v, f := s.Getenv(name), s.Getenv(name+"_FILE")
	switch {
	case v != "" && f != "":
		return nil, fmt.Errorf("%w: set %s or %s_FILE, not both", ErrInvalid, name, name)
	case f != "":
		b, err := s.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("%w: reading %s_FILE: %v", ErrInvalid, name, err)
		}
		return []byte(strings.TrimRight(string(b), "\r\n")), nil
	}
	return []byte(v), nil
}

func (s Source) str(name, def string) string {
	if v := s.Getenv(name); v != "" {
		return v
	}
	return def
}

func (s Source) num(name string, def int) (int, error) {
	v := s.Getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%w: %s must be a positive integer", ErrInvalid, name)
	}
	return n, nil
}

// Load reads and validates the configuration.
func Load(src Source) (Config, error) {
	c := Config{
		Env:               Env(src.str("SERK_ENV", string(Production))),
		Listen:            src.str("SERK_LISTEN", ":8080"),
		DBBaseDSN:         src.Getenv("SERK_DB_BASE_DSN"),
		OIDCIssuer:        src.Getenv("SERK_OIDC_ISSUER"),
		OIDCAudience:      src.Getenv("SERK_OIDC_AUDIENCE"),
		OIDCJWKSURL:       src.Getenv("SERK_OIDC_JWKS_URL"),
		OIDCTenantClaim:   src.str("SERK_OIDC_TENANT_CLAIM", "tid"),
		OIDCRolesClaim:    src.str("SERK_OIDC_ROLES_CLAIM", "roles"),
		OIDCProjectsClaim: src.str("SERK_OIDC_PROJECTS_CLAIM", "projects"),
		TokenIssuer:       src.str("SERK_TOKEN_ISSUER", "serk-id"),
		TokenAudience:     src.str("SERK_TOKEN_AUDIENCE", "serk-construction"),
		SoDStrict:         src.str("SERK_SOD_STRICT", "true") != "false",
	}
	var err error
	if c.TenantDBSecret, err = src.secret("SERK_TENANT_DB_SECRET"); err != nil {
		return Config{}, err
	}
	if c.ApprovalSecret, err = src.secret("SERK_APPROVAL_SIGNING_KEY"); err != nil {
		return Config{}, err
	}
	if c.HS256Secret, err = src.secret("SERK_TOKEN_SECRET"); err != nil {
		return Config{}, err
	}
	health, err := src.secret("SERK_HEALTH_DSN")
	if err != nil {
		return Config{}, err
	}
	c.HealthDSN = string(health)
	sched, err := src.secret("SERK_SCHEDULER_DSN")
	if err != nil {
		return Config{}, err
	}
	c.SchedulerDSN = string(sched)
	c.MetricsListen = src.str("SERK_METRICS_LISTEN", "")
	mon, err := src.secret("SERK_MONITOR_DSN")
	if err != nil {
		return Config{}, err
	}
	c.MonitorDSN = string(mon)
	if c.WorkflowTimerInterval, err = src.num("SERK_WORKFLOW_TIMER_INTERVAL_SECONDS", 30); err != nil {
		return Config{}, err
	}
	if c.RatePerMinute, err = src.num("SERK_RATE_PER_MIN", 300); err != nil {
		return Config{}, err
	}
	if c.PreAuthPerMinute, err = src.num("SERK_PREAUTH_PER_MIN", 600); err != nil {
		return Config{}, err
	}
	if c.AuthFailuresPerMin, err = src.num("SERK_AUTH_FAILURES_PER_MIN", 20); err != nil {
		return Config{}, err
	}
	for _, p := range strings.Split(src.Getenv("SERK_TRUSTED_PROXIES"), ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		pre, err := netip.ParsePrefix(p)
		if err != nil {
			return Config{}, fmt.Errorf("%w: SERK_TRUSTED_PROXIES %q: %v", ErrInvalid, p, err)
		}
		c.TrustedProxies = append(c.TrustedProxies, pre)
	}
	if f := src.Getenv("SERK_DEDICATED_DSNS_FILE"); f != "" {
		b, err := src.ReadFile(f)
		if err != nil {
			return Config{}, fmt.Errorf("%w: reading SERK_DEDICATED_DSNS_FILE: %v", ErrInvalid, err)
		}
		if err := json.Unmarshal(b, &c.DedicatedDSNs); err != nil {
			return Config{}, fmt.Errorf("%w: SERK_DEDICATED_DSNS_FILE must be a JSON object tenant->dsn", ErrInvalid)
		}
	}
	return c, c.Validate()
}

// Validate applies environment-specific rules.
func (c Config) Validate() error {
	var errs []string
	bad := func(f string, a ...any) { errs = append(errs, fmt.Sprintf(f, a...)) }
	prod := c.Env == Production
	switch c.Env {
	case Development, Staging, Production:
	default:
		bad("SERK_ENV must be development, staging or production (got %q)", c.Env)
	}
	if c.DBBaseDSN == "" {
		bad("SERK_DB_BASE_DSN is required")
	} else if u, err := url.Parse(c.DBBaseDSN); err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		bad("SERK_DB_BASE_DSN must be a postgres:// URL")
	} else {
		if u.User != nil {
			bad("SERK_DB_BASE_DSN must not contain credentials (each tenant connects as its own role)")
		}
		if prod {
			checkTLS(u, "SERK_DB_BASE_DSN", bad)
		}
	}
	if err := checkSecret(c.TenantDBSecret, prod); err != "" {
		bad("SERK_TENANT_DB_SECRET %s", err)
	}
	if err := checkSecret(c.ApprovalSecret, prod); err != "" {
		bad("SERK_APPROVAL_SIGNING_KEY %s", err)
	} else if string(c.ApprovalSecret) == string(c.TenantDBSecret) {
		bad("SERK_APPROVAL_SIGNING_KEY must differ from SERK_TENANT_DB_SECRET")
	}
	if c.HealthDSN == "" {
		bad("SERK_HEALTH_DSN is required (a login role with no table privileges)")
	} else if prod {
		checkDSN(c.HealthDSN, "SERK_HEALTH_DSN", bad)
	}
	if c.WorkflowTimerInterval > 3600 {
		bad("SERK_WORKFLOW_TIMER_INTERVAL_SECONDS must be at most 3600")
	}
	if c.SchedulerDSN != "" && prod {
		checkDSN(c.SchedulerDSN, "SERK_SCHEDULER_DSN", bad)
	}
	if c.MetricsListen != "" && c.MetricsListen == c.Listen {
		bad("SERK_METRICS_LISTEN must be a separate, internal-only listener (not SERK_LISTEN)")
	}
	if c.MonitorDSN != "" && c.MetricsListen == "" {
		bad("SERK_MONITOR_DSN is set but SERK_METRICS_LISTEN is not: database health would never be exposed")
	}
	if c.MonitorDSN != "" && prod {
		checkDSN(c.MonitorDSN, "SERK_MONITOR_DSN", bad)
	}
	for tenant, dsn := range c.DedicatedDSNs {
		if prod {
			checkDSN(dsn, "dedicated DSN of tenant "+tenant, bad)
		}
	}
	oidc := c.OIDCIssuer != "" || c.OIDCJWKSURL != "" || c.OIDCAudience != ""
	switch {
	case oidc:
		if c.OIDCIssuer == "" || c.OIDCJWKSURL == "" || c.OIDCAudience == "" {
			bad("OIDC needs SERK_OIDC_ISSUER, SERK_OIDC_JWKS_URL and SERK_OIDC_AUDIENCE")
		}
		if prod && (!strings.HasPrefix(c.OIDCIssuer, "https://") || !strings.HasPrefix(c.OIDCJWKSURL, "https://")) {
			bad("OIDC issuer and JWKS URL must use https in production")
		}
		if len(c.HS256Secret) > 0 {
			bad("configure either OIDC or SERK_TOKEN_SECRET, not both")
		}
	case prod:
		bad("production requires OIDC (SERK_OIDC_*); shared-secret HS256 tokens are for development and staging only")
	default:
		if err := checkSecret(c.HS256Secret, false); err != "" {
			bad("SERK_TOKEN_SECRET %s", err)
		}
	}
	if prod && !c.SoDStrict {
		bad("SERK_SOD_STRICT=false is not allowed in production")
	}
	for _, p := range c.TrustedProxies {
		if p.Bits() == 0 {
			bad("SERK_TRUSTED_PROXIES must not contain a wildcard prefix (%s)", p)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w (%s):\n  - %s", ErrInvalid, c.Env, strings.Join(errs, "\n  - "))
	}
	return nil
}

var weakMarkers = []string{"change-me", "changeme", "password", "postgres", "serk_api", "secret", "example", "default", "test", "dev"}

// checkSecret returns a reason when a secret is unacceptable.
func checkSecret(b []byte, prod bool) string {
	if len(b) < 32 {
		return "must be at least 32 bytes"
	}
	distinct := map[byte]bool{}
	for _, x := range b {
		distinct[x] = true
	}
	if len(distinct) < 12 {
		return "has too little variety to be random"
	}
	if prod {
		low := strings.ToLower(string(b))
		for _, m := range weakMarkers {
			if strings.Contains(low, m) {
				return fmt.Sprintf("looks like a placeholder or well-known value (contains %q); generate one with `openssl rand -hex 32`", m)
			}
		}
	}
	return ""
}

func checkDSN(dsn, name string, bad func(string, ...any)) {
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		bad("%s must be a postgres:// URL", name)
		return
	}
	if u.User != nil {
		switch strings.ToLower(u.User.Username()) {
		case "postgres", "root", "admin", "rdsadmin", "azure_superuser":
			bad("%s must not use a superuser/administrative login (%s)", name, u.User.Username())
		}
		if pw, ok := u.User.Password(); ok && checkSecret([]byte(pw), true) != "" {
			bad("%s uses a weak password", name)
		}
	}
	checkTLS(u, name, bad)
}

// checkTLS requires verify-full unless the host is a local unix socket.
func checkTLS(u *url.URL, name string, bad func(string, ...any)) {
	q := u.Query()
	host := u.Hostname()
	if h := q.Get("host"); h != "" {
		host = h
	}
	if strings.HasPrefix(host, "/") {
		return // unix socket: no network path
	}
	if q.Get("sslmode") != "verify-full" {
		bad("%s must use sslmode=verify-full in production (got %q)", name, q.Get("sslmode"))
	}
}
