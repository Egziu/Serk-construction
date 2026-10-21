// serk-api serves the SERK Construction financial kernel API.
//
// Configuration is read from the environment and validated by
// internal/config (fail-closed; SERK_ENV defaults to production). Run
// `serk-api check-config` in a deployment pipeline to validate without
// starting. Development tokens are minted by the separate serk-devtoken
// binary, which is not part of the production image.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/serk-group/serk-construction/internal/config"
	"github.com/serk-group/serk-construction/internal/httpapi"
	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.Load(config.OS)
	if len(os.Args) > 1 && os.Args[1] == "check-config" {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("configuration valid for %s\n", cfg.Env)
		return
	}
	if err != nil {
		log.Error("configuration refused", "err", err.Error())
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	creds := postgres.DedicatedCredentials{DSNs: cfg.DedicatedDSNs,
		Fallback: postgres.DerivedCredentials{BaseDSN: cfg.DBBaseDSN, Secret: cfg.TenantDBSecret}}
	router, err := postgres.NewRouter(ctx, postgres.RouterConfig{Credentials: creds, HealthDSN: cfg.HealthDSN})
	if err != nil {
		log.Error("database router", "err", err)
		os.Exit(1)
	}
	defer router.Close()

	var verifier httpapi.TokenVerifier
	if cfg.OIDCIssuer != "" {
		v := &httpapi.JWKSVerifier{Issuer: cfg.OIDCIssuer, Audience: cfg.OIDCAudience, JWKSURL: cfg.OIDCJWKSURL,
			TenantClaim: cfg.OIDCTenantClaim, RolesClaim: cfg.OIDCRolesClaim, ProjectsClaim: cfg.OIDCProjectsClaim}
		if err := v.Refresh(ctx); err != nil {
			log.Error("OIDC JWKS unavailable at startup", "err", err)
			os.Exit(1)
		}
		verifier = v
	} else {
		log.Warn("using HS256 shared-secret tokens: development/staging only", "env", cfg.Env)
		verifier = httpapi.HS256Verifier{Secret: cfg.HS256Secret, Issuer: cfg.TokenIssuer, Audience: cfg.TokenAudience}
	}

	svc := kernel.New(router, auth.NewAuthorizer(nil, cfg.SoDStrict))
	h := httpapi.New(httpapi.Config{Verifier: verifier, Kernel: svc, Store: router, Logger: log, RatePerMinute: cfg.RatePerMinute,
		Abuse: httpapi.AbuseConfig{PreAuthPerMinute: cfg.PreAuthPerMinute, AuthFailuresPerMinute: cfg.AuthFailuresPerMin, TrustedProxies: cfg.TrustedProxies}})
	log.Info("starting", "env", cfg.Env, "auth", map[bool]string{true: "oidc", false: "hs256"}[cfg.OIDCIssuer != ""])
	if err := httpapi.Listen(ctx, cfg.Listen, h, log); err != nil {
		log.Error("server", "err", err)
		os.Exit(1)
	}
}
