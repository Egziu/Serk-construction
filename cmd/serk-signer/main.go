// serk-signer is the isolated approval signer (R-SIGNER). It holds the
// approval signing secret, which the API process no longer has in
// production, and signs attestations only for claims the person's own
// bearer token supports. It listens on a unix socket shared with the API.
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
	"github.com/serk-group/serk-construction/internal/obs"
	"github.com/serk-group/serk-construction/internal/signer"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.LoadSigner(config.OS)
	if len(os.Args) > 1 && os.Args[1] == "check-config" {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("signer configuration valid for %s\n", cfg.Env)
		return
	}
	if err != nil {
		log.Error("configuration refused", "err", err.Error())
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	var verifier signer.TokenVerifier
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
	metrics := obs.NewRegistry()
	h := signer.New(signer.Config{Verifier: verifier, Keyring: signer.FileKeyring{Master: cfg.Master, ID: cfg.KeyID},
		Authz: auth.NewAuthorizer(nil, true), Logger: log, Metrics: metrics, PerActorPerMinute: cfg.PerActorPerMinute})
	if cfg.MetricsListen != "" {
		go func() {
			if err := httpapi.Listen(ctx, cfg.MetricsListen, metrics.Handler(), log); err != nil {
				log.Error("metrics listener", "err", err)
			}
		}()
	}
	log.Info("starting signer", "env", cfg.Env, "kid", cfg.KeyID)
	if err := signer.Listen(ctx, cfg.Socket, h, log); err != nil {
		log.Error("signer", "err", err)
		os.Exit(1)
	}
}
