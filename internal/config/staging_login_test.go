package config

import (
	"strings"
	"testing"
)

// The staging persona sign-in is a test-environment convenience: it is
// refused in production, needs a tenant and a real passphrase, and cannot
// be mixed with OIDC.
func TestStagingLoginConfig(t *testing.T) {
	staging := func() map[string]string {
		return map[string]string{"SERK_ENV": "staging", "SERK_DB_BASE_DSN": "postgres://db:5432/serk?sslmode=prefer",
			"SERK_TENANT_DB_SECRET": goodSecret, "SERK_SIGNER_SOCKET": "/tmp/serk/signer.sock", "SERK_TOKEN_SECRET": goodSecret2,
			"SERK_HEALTH_DSN":               "postgres://serk_health@db:5432/serk?sslmode=prefer",
			"SERK_STAGING_LOGIN_PASSPHRASE": "a-long-staging-passphrase", "SERK_STAGING_TENANT": "5e4c0000-0000-4000-8000-00000000de30",
			"SERK_STAGING_PROJECTS": "p1, p2,"}
	}
	c, err := Load(src(staging(), nil))
	if err != nil {
		t.Fatalf("staging with persona sign-in refused: %v", err)
	}
	if string(c.StagingLoginPassphrase) != "a-long-staging-passphrase" || len(c.StagingProjects) != 2 || c.StagingProjects[1] != "p2" {
		t.Fatalf("parsed %+v", c)
	}
	for name, mod := range map[string]func(m map[string]string){
		"short passphrase":    func(m map[string]string) { m["SERK_STAGING_LOGIN_PASSPHRASE"] = "short" },
		"no tenant":           func(m map[string]string) { delete(m, "SERK_STAGING_TENANT") },
		"passphrase = secret": func(m map[string]string) { m["SERK_STAGING_LOGIN_PASSPHRASE"] = goodSecret2 },
		"with OIDC": func(m map[string]string) {
			delete(m, "SERK_TOKEN_SECRET")
			m["SERK_OIDC_ISSUER"], m["SERK_OIDC_JWKS_URL"], m["SERK_OIDC_AUDIENCE"] = "https://id.example", "https://id.example/jwks", "serk"
		},
	} {
		m := staging()
		mod(m)
		if _, err := Load(src(m, nil)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, k := range []string{"SERK_STAGING_LOGIN_PASSPHRASE", "SERK_STAGING_TENANT"} {
		p := prodEnv()
		p[k] = "a-long-staging-passphrase"
		_, err := Load(src(p, nil))
		if err == nil || !strings.Contains(err.Error(), "refused in production") {
			t.Errorf("production with %s: %v", k, err)
		}
	}
}
