// serk-relay delivers transactional-outbox events to a signed webhook.
//
// Environment:
//
//	SERK_RELAY_DSN(_FILE)       login role that is a member of serk_publisher only
//	SERK_WEBHOOK_URL            https endpoint of the integration target
//	SERK_WEBHOOK_SECRET(_FILE)  HMAC signing secret, >= 32 bytes
//	SERK_RELAY_INTERVAL         poll interval (default 2s)
//	SERK_RELAY_TENANT           optional: restrict to one tenant
//
// Subcommand `serk-relay replay <event-id>` returns a dead-lettered event to
// the queue after the target is fixed.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/serk-group/serk-construction/internal/relay"
)

func secret(name string) string {
	if f := os.Getenv(name + "_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading %s_FILE: %v\n", name, err)
			os.Exit(2)
		}
		return strings.TrimRight(string(b), "\r\n")
	}
	return os.Getenv(name)
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := pgxpool.New(ctx, secret("SERK_RELAY_DSN"))
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	defer pool.Close()
	if len(os.Args) == 3 && os.Args[1] == "replay" {
		if err := relay.Replay(ctx, pool, os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("replayed", os.Args[2])
		return
	}
	url, sec := os.Getenv("SERK_WEBHOOK_URL"), secret("SERK_WEBHOOK_SECRET")
	if !strings.HasPrefix(url, "https://") && os.Getenv("SERK_ENV") != "development" {
		log.Error("SERK_WEBHOOK_URL must be https outside development")
		os.Exit(2)
	}
	if len(sec) < 32 {
		log.Error("SERK_WEBHOOK_SECRET must be at least 32 bytes")
		os.Exit(2)
	}
	interval, err := time.ParseDuration(envOr("SERK_RELAY_INTERVAL", "2s"))
	if err != nil {
		log.Error("SERK_RELAY_INTERVAL", "err", err)
		os.Exit(2)
	}
	r := &relay.Relay{DB: pool, Pub: relay.WebhookPublisher{URL: url, Secret: []byte(sec)}, Log: log, TenantID: os.Getenv("SERK_RELAY_TENANT")}
	log.Info("relay started", "interval", interval.String())
	if err := r.Run(ctx, interval); err != nil && ctx.Err() == nil {
		log.Error("relay", "err", err)
		os.Exit(1)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
