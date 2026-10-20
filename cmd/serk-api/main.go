// serk-api serves the SERK Construction financial kernel API.
//
// Environment:
//
//	SERK_APP_DSN        PostgreSQL DSN for the application role (required)
//	SERK_TOKEN_SECRET   HS256 shared secret, >= 32 bytes (required)
//	SERK_TOKEN_ISSUER   expected token issuer   (default serk-id)
//	SERK_TOKEN_AUDIENCE expected token audience (default serk-construction)
//	SERK_LISTEN         listen address          (default :8080)
//	SERK_SOD_STRICT     "false" relaxes poster≠approver (default true)
//	SERK_RATE_PER_MIN   per-principal request budget (default 300)
//
// Sub-command "token" mints a development token:
//
//	serk-api token --sub u1 --tenant <uuid> --roles accountant,finance_manager
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/serk-group/serk-construction/internal/httpapi"
	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	verifier := httpapi.HS256Verifier{
		Secret:   []byte(os.Getenv("SERK_TOKEN_SECRET")),
		Issuer:   envOr("SERK_TOKEN_ISSUER", "serk-id"),
		Audience: envOr("SERK_TOKEN_AUDIENCE", "serk-construction"),
	}
	if len(os.Args) > 1 && os.Args[1] == "token" {
		mintToken(verifier, os.Args[2:])
		return
	}
	if len(verifier.Secret) < 32 {
		log.Error("SERK_TOKEN_SECRET must be at least 32 bytes")
		os.Exit(2)
	}
	dsn := os.Getenv("SERK_APP_DSN")
	if dsn == "" {
		log.Error("SERK_APP_DSN is required")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store, err := postgres.Open(ctx, dsn)
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	defer store.Close()

	strict := envOr("SERK_SOD_STRICT", "true") != "false"
	rate, _ := strconv.Atoi(envOr("SERK_RATE_PER_MIN", "300"))
	svc := kernel.New(store, auth.NewAuthorizer(nil, strict))
	h := httpapi.New(httpapi.Config{Verifier: verifier, Kernel: svc, Store: store, Logger: log, RatePerMinute: rate})
	if err := httpapi.Listen(ctx, envOr("SERK_LISTEN", ":8080"), h, log); err != nil {
		log.Error("server", "err", err)
		os.Exit(1)
	}
}

func mintToken(v httpapi.HS256Verifier, args []string) {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	sub := fs.String("sub", "", "user id")
	tenant := fs.String("tenant", "", "tenant uuid")
	roles := fs.String("roles", "accountant", "comma-separated roles")
	ttl := fs.Duration("ttl", time.Hour, "token lifetime")
	_ = fs.Parse(args)
	if *sub == "" || *tenant == "" {
		fmt.Fprintln(os.Stderr, "--sub and --tenant are required")
		os.Exit(2)
	}
	now := time.Now()
	tok, err := v.Sign(httpapi.Claims{Subject: *sub, TenantID: *tenant, Roles: strings.Split(*roles, ","),
		IssuedAt: now.Unix(), ExpiresAt: now.Add(*ttl).Unix(), Issuer: v.Issuer, Audience: v.Audience})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(tok)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
