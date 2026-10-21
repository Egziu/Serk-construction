package config

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func src(env map[string]string, files map[string]string) Source {
	return Source{
		Getenv: func(k string) string { return env[k] },
		ReadFile: func(p string) ([]byte, error) {
			if v, ok := files[p]; ok {
				return []byte(v), nil
			}
			return nil, os.ErrNotExist
		},
	}
}

const (
	goodSecret  = "3f9a1c7e5b2d8f4a6c0e9b1d7f3a5c8e2b4d6f8a0c1e3b5d7f9a2c4e6b8d0f1a"
	goodSecret2 = "a8c2e4f6b1d3f5a7c9e0b2d4f6a8c1e3b5d7f9a0c2e4b6d8f1a3c5e7b9d2f4a6"
	goodSecret3 = "71c4e9a2f6b08d3e5a7c1f9b2d4e6a8c0f3b5d7e9a1c4f6b8d0e2a5c7f9b1d3e"
)

func prodEnv() map[string]string {
	return map[string]string{
		"SERK_DB_BASE_DSN":          "postgres://db.internal:5432/serk?sslmode=verify-full",
		"SERK_TENANT_DB_SECRET":     goodSecret,
		"SERK_APPROVAL_SIGNING_KEY": goodSecret3,
		"SERK_HEALTH_DSN":           "postgres://serk_health:" + goodSecret2 + "@db.internal:5432/serk?sslmode=verify-full",
		"SERK_OIDC_ISSUER":          "https://id.serk.example/realms/serk",
		"SERK_OIDC_JWKS_URL":        "https://id.serk.example/realms/serk/protocol/openid-connect/certs",
		"SERK_OIDC_AUDIENCE":        "serk-construction",
	}
}

func TestProductionAcceptsHardenedConfig(t *testing.T) {
	c, err := Load(src(prodEnv(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Env != Production || !c.SoDStrict {
		t.Fatalf("%+v", c)
	}
}

// SC-06: the values shipped in the 0.1.0 docker-compose.yml are refused when
// SERK_ENV is unset (which defaults to production).
func TestProductionRefusesTheOldDemoDefaults(t *testing.T) {
	old := map[string]string{
		"SERK_DB_BASE_DSN":      "postgres://db:5432/serk_construction?sslmode=disable",
		"SERK_HEALTH_DSN":       "postgres://postgres:postgres@db:5432/serk_construction?sslmode=disable",
		"SERK_TOKEN_SECRET":     "change-me-to-a-random-32-byte-or-longer-secret",
		"SERK_TENANT_DB_SECRET": "change-me-to-a-random-32-byte-or-longer-secret",
		"SERK_SOD_STRICT":       "false",
		"SERK_TRUSTED_PROXIES":  "0.0.0.0/0",
	}
	_, err := Load(src(old, nil))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("demo defaults accepted: %v", err)
	}
	for _, want := range []string{"sslmode=verify-full", "superuser", "placeholder", "OIDC", "SERK_SOD_STRICT", "wildcard"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q:\n%v", want, err)
		}
	}
	t.Log(err)
}

func TestProductionRules(t *testing.T) {
	mut := func(f func(m map[string]string)) error {
		m := prodEnv()
		f(m)
		_, err := Load(src(m, nil))
		return err
	}
	cases := map[string]func(m map[string]string){
		"base DSN with credentials":    func(m map[string]string) { m["SERK_DB_BASE_DSN"] = "postgres://u:p@db/serk?sslmode=verify-full" },
		"sslmode=require":              func(m map[string]string) { m["SERK_DB_BASE_DSN"] = "postgres://db/serk?sslmode=require" },
		"short tenant secret":          func(m map[string]string) { m["SERK_TENANT_DB_SECRET"] = "abc" },
		"low-variety secret":           func(m map[string]string) { m["SERK_TENANT_DB_SECRET"] = strings.Repeat("ab", 20) },
		"missing approval key":         func(m map[string]string) { delete(m, "SERK_APPROVAL_SIGNING_KEY") },
		"approval key = tenant secret": func(m map[string]string) { m["SERK_APPROVAL_SIGNING_KEY"] = m["SERK_TENANT_DB_SECRET"] },
		"HS256 in production": func(m map[string]string) {
			delete(m, "SERK_OIDC_ISSUER")
			delete(m, "SERK_OIDC_JWKS_URL")
			delete(m, "SERK_OIDC_AUDIENCE")
			m["SERK_TOKEN_SECRET"] = goodSecret2
		},
		"http JWKS":           func(m map[string]string) { m["SERK_OIDC_JWKS_URL"] = "http://id/certs" },
		"partial OIDC":        func(m map[string]string) { delete(m, "SERK_OIDC_AUDIENCE") },
		"unknown environment": func(m map[string]string) { m["SERK_ENV"] = "prod" },
		"health as postgres": func(m map[string]string) {
			m["SERK_HEALTH_DSN"] = "postgres://postgres:" + goodSecret2 + "@db/serk?sslmode=verify-full"
		},
		"secret inline + file": func(m map[string]string) { m["SERK_TENANT_DB_SECRET_FILE"] = "/run/secrets/x" },
	}
	for name, f := range cases {
		if err := mut(f); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted", name)
		}
	}
	// Unix sockets need no TLS; secrets may come from files.
	m := prodEnv()
	m["SERK_DB_BASE_DSN"] = "postgres:///serk?host=/var/run/postgresql"
	delete(m, "SERK_TENANT_DB_SECRET")
	m["SERK_TENANT_DB_SECRET_FILE"] = "/run/secrets/tenant"
	if _, err := Load(src(m, map[string]string{"/run/secrets/tenant": goodSecret + "\n"})); err != nil {
		t.Fatalf("socket + secret file refused: %v", err)
	}
}

func TestDevelopmentRelaxations(t *testing.T) {
	_, err := Load(src(map[string]string{
		"SERK_ENV": "development", "SERK_DB_BASE_DSN": "postgres://localhost:5432/serk?sslmode=disable",
		"SERK_TENANT_DB_SECRET": goodSecret, "SERK_TOKEN_SECRET": goodSecret2, "SERK_APPROVAL_SIGNING_KEY": goodSecret3,
		"SERK_HEALTH_DSN": "postgres://serk_health:x@localhost/serk?sslmode=disable",
	}, nil))
	if err != nil {
		t.Fatalf("development config refused: %v", err)
	}
}

// SC-06: the production compose manifest must not reintroduce demo defaults.
func TestProductionManifestHasNoDemoDefaults(t *testing.T) {
	b, err := os.ReadFile("../../deploy/docker-compose.prod.yml")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, bad := range []string{"sslmode=disable", "change-me", "POSTGRES_PASSWORD:", "SERK_TOKEN_SECRET", "SERK_ENV: development", "5432:5432", "serk-devtoken"} {
		if strings.Contains(s, bad) {
			t.Errorf("docker-compose.prod.yml contains %q", bad)
		}
	}
	for _, need := range []string{"SERK_ENV: production", "no-new-privileges", "read_only: true", "internal: true", "_FILE"} {
		if !strings.Contains(s, need) {
			t.Errorf("docker-compose.prod.yml lacks %q", need)
		}
	}
	df, _ := os.ReadFile("../../deploy/Dockerfile")
	for _, line := range strings.Split(string(df), "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "#") {
			continue
		}
		if strings.Contains(l, "serk-devtoken") {
			t.Errorf("Dockerfile builds or copies the dev token tool: %s", l)
		}
	}
	if !strings.Contains(string(df), "USER nonroot") {
		t.Error("Dockerfile does not drop to a non-root user")
	}
}

// GATEA-11: metrics are on a separate listener; a monitor DSN without a
// listener, or a plaintext monitor DSN in production, is refused.
func TestObservabilityConfig(t *testing.T) {
	env := prodEnv()
	env["SERK_METRICS_LISTEN"] = "10.0.0.5:9464"
	env["SERK_MONITOR_DSN"] = "postgres://serk_metrics:" + goodSecret2 + "@db.internal:5432/serk?sslmode=verify-full"
	c, err := Load(src(env, nil))
	if err != nil {
		t.Fatalf("hardened observability config refused: %v", err)
	}
	if c.MetricsListen != "10.0.0.5:9464" || c.MonitorDSN == "" {
		t.Fatalf("%+v", c)
	}
	for name, mutate := range map[string]func(map[string]string){
		"metrics on the public listener": func(e map[string]string) { e["SERK_METRICS_LISTEN"] = ":8080" },
		"monitor DSN without a listener": func(e map[string]string) { delete(e, "SERK_METRICS_LISTEN") },
		"plaintext monitor DSN": func(e map[string]string) {
			e["SERK_MONITOR_DSN"] = "postgres://serk_metrics:x@db:5432/serk?sslmode=disable"
		},
	} {
		e := map[string]string{}
		for k, v := range env {
			e[k] = v
		}
		mutate(e)
		if _, err := Load(src(e, nil)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}
