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

	"github.com/serk-group/serk-construction/internal/aiphrase"
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

	var issuer attest.Issuer = attest.Signer{Master: cfg.ApprovalSecret}
	if cfg.SignerSocket != "" {
		// R-SIGNER: the signing secret lives in serk-signer, not here.
		issuer = &attest.Remote{Socket: cfg.SignerSocket}
	} else {
		log.Warn("approval signing key is inside the API process (refused in production): run serk-signer and set SERK_SIGNER_SOCKET")
	}
	svc := kernel.New(router, auth.NewAuthorizer(nil, cfg.SoDStrict)).UseApprovalSigner(issuer)
	if cfg.AIEndpoint != "" {
		ph, err := aiphrase.New(aiphrase.Config{Endpoint: cfg.AIEndpoint, APIKey: string(cfg.AIKey), Model: cfg.AIModel})
		if err != nil {
			log.Error("assistant model", "err", err)
			os.Exit(1)
		}
		svc.UsePhraser(ph)
		log.Info("assistant phrasing model enabled (rephrases computed facts only)", "model", cfg.AIModel)
	} else {
		log.Info("assistant runs deterministically (no SERK_AI_ENDPOINT)")
	}
	if ring := cfg.BankDataRing(); ring != nil {
		svc.UseBankDataKeys(*ring)
	} else {
		log.Warn("no SERK_BANK_DATA_KEY: bank account numbers cannot be recorded or revealed (refused in production)")
	}
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
	var staging *httpapi.StagingLogin
	if len(cfg.StagingLoginPassphrase) > 0 && cfg.Env != config.Production {
		log.Warn("STAGING persona sign-in enabled: test environment with synthetic data only", "tenant", cfg.StagingTenant)
		staging = &httpapi.StagingLogin{Passphrase: cfg.StagingLoginPassphrase, Tenant: cfg.StagingTenant, Projects: cfg.StagingProjects,
			Signer: httpapi.HS256Verifier{Secret: cfg.HS256Secret, Issuer: cfg.TokenIssuer, Audience: cfg.TokenAudience}}
		for _, c := range cfg.StagingCompanies {
			staging.Companies = append(staging.Companies, httpapi.StagingCompany{ID: c.ID, Name: c.Name, Projects: c.Projects})
		}
	}
	h := httpapi.New(httpapi.Config{Verifier: verifier, Kernel: svc, Store: router, Logger: log, RatePerMinute: cfg.RatePerMinute, Metrics: metrics,
		Abuse: abuse, Staging: staging, CompanyName: cfg.CompanyName})
	if cfg.SchedulerDSN != "" {
		sched, err := pgxpool.New(ctx, cfg.SchedulerDSN)
		if err != nil {
			log.Error("scheduler database", "err", err)
			os.Exit(1)
		}
		defer sched.Close()
		go runWorkflowTimers(ctx, svc, sched, time.Duration(cfg.WorkflowTimerInterval)*time.Second, log)
		go runAutomation(ctx, svc, sched, time.Duration(cfg.AutomationInterval)*time.Second, log)
	} else {
		log.Warn("workflow timers disabled (SERK_SCHEDULER_DSN not set): SLA escalation and expiry will not run")
	}
	log.Info("starting", "env", cfg.Env, "auth", map[bool]string{true: "oidc", false: "hs256"}[cfg.OIDCIssuer != ""])
	if err := httpapi.Listen(ctx, cfg.Listen, h, log); err != nil {
		log.Error("server", "err", err)
		os.Exit(1)
	}
}

// runAutomation evaluates the customers' active rules and records risk
// snapshots. Like the workflow timers it learns tenant ids from the
// scheduler login and acts inside each tenant's own role; it only notifies.
func runAutomation(ctx context.Context, svc *kernel.Service, sched *pgxpool.Pool, every time.Duration, log *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	lister := func(ctx context.Context) ([]string, error) { return postgres.DueAutomationTenants(ctx, sched, 1000) }
	for {
		res, err := svc.RunDueAutomation(ctx, lister)
		if err != nil && ctx.Err() == nil {
			log.Error("automation", "err", err)
		}
		if res.Rules+res.Snapshots > 0 {
			log.Info("automation", "rules", res.Rules, "findings", res.Findings, "notified", res.Notified, "resolved", res.Resolved, "snapshots", res.Snapshots)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
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
