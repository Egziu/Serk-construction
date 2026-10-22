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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/serk-group/serk-construction/internal/config"
	"github.com/serk-group/serk-construction/internal/httpapi"
	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/obs"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/attest"
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
	// In-database controls assume tenant logins hold no TEMP and no advisory
	// locks (R7-F9, deploy/02). Production refuses to start otherwise.
	if issues, err := router.Posture(ctx); err != nil || len(issues) > 0 {
		if cfg.Env == config.Production {
			log.Error("database posture", "issues", issues, "err", err)
			os.Exit(1)
		}
		log.Warn("database posture (refused in production)", "issues", issues, "err", err)
	}

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

	svc := kernel.New(router, auth.NewAuthorizer(nil, cfg.SoDStrict)).UseApprovalSigner(attest.Signer{Master: cfg.ApprovalSecret})
	metrics := obs.NewRegistry()
	if cfg.MonitorDSN != "" {
		mon, err := pgxpool.New(ctx, cfg.MonitorDSN)
		if err != nil {
			log.Error("monitor database", "err", err)
			os.Exit(1)
		}
		defer mon.Close()
		metrics.Collect(obs.DBHealth{Pool: mon}.Collector())
	}
	if cfg.MetricsListen != "" {
		go func() {
			if err := httpapi.Listen(ctx, cfg.MetricsListen, metrics.Handler(), log); err != nil {
				log.Error("metrics listener", "err", err)
			}
		}()
	} else {
		log.Warn("metrics disabled (SERK_METRICS_LISTEN not set): no SLO or alert signals will be available")
	}
	abuse := httpapi.AbuseConfig{PreAuthPerMinute: cfg.PreAuthPerMinute, AuthFailuresPerMinute: cfg.AuthFailuresPerMin, TrustedProxies: cfg.TrustedProxies}
	if cfg.AbuseDSN != "" {
		ab, err := pgxpool.New(ctx, cfg.AbuseDSN)
		if err != nil {
			log.Error("abuse-limit database", "err", err)
			os.Exit(1)
		}
		defer ab.Close()
		if err := ab.Ping(ctx); err != nil {
			log.Error("abuse-limit database unreachable at startup", "err", err)
			os.Exit(1)
		}
		abuse.Shared, abuse.KeySecret = postgres.AbuseStore{Pool: ab}, cfg.AbuseKey
	} else {
		log.Warn("abuse limits are per replica (SERK_ABUSE_DSN not set): refused in production")
	}
	h := httpapi.New(httpapi.Config{Verifier: verifier, Kernel: svc, Store: router, Logger: log, RatePerMinute: cfg.RatePerMinute, Metrics: metrics,
		Abuse: abuse})
	if cfg.SchedulerDSN != "" {
		sched, err := pgxpool.New(ctx, cfg.SchedulerDSN)
		if err != nil {
			log.Error("scheduler database", "err", err)
			os.Exit(1)
		}
		defer sched.Close()
		go runWorkflowTimers(ctx, svc, sched, time.Duration(cfg.WorkflowTimerInterval)*time.Second, log)
	} else {
		log.Warn("workflow timers disabled (SERK_SCHEDULER_DSN not set): SLA escalation and expiry will not run")
	}
	log.Info("starting", "env", cfg.Env, "auth", map[bool]string{true: "oidc", false: "hs256"}[cfg.OIDCIssuer != ""])
	if err := httpapi.Listen(ctx, cfg.Listen, h, log); err != nil {
		log.Error("server", "err", err)
		os.Exit(1)
	}
}

// runWorkflowTimers escalates and expires workflow steps. State is in the
// database, so a restart loses nothing; several API replicas may run it
// concurrently (instances are claimed with SKIP LOCKED).
func runWorkflowTimers(ctx context.Context, svc *kernel.Service, sched *pgxpool.Pool, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	lister := func(ctx context.Context) ([]string, error) { return postgres.DueWorkflowTenants(ctx, sched, 1000) }
	for {
		res, err := svc.RunDueWorkflowTimers(ctx, lister)
		if err != nil && ctx.Err() == nil {
			log.Error("workflow timers", "err", err)
		} else if res.Escalated+res.Expired > 0 {
			log.Info("workflow timers", "escalated", res.Escalated, "expired", res.Expired)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
