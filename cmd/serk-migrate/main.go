// serk-migrate applies the embedded SQL migrations and provisions tenants.
//
//	serk-migrate                                   apply pending migrations
//	serk-migrate provision-tenant --tenant <uuid> --name "Acme PLC"
//	                                               create the tenant, its database role and mapping
//
// Environment: SERK_ADMIN_DSN (or SERK_ADMIN_DSN_FILE), the schema owner with
// CREATEROLE. provision-tenant also needs SERK_APPROVAL_SIGNING_KEY(_FILE) (the
// approval attestation secret) and SERK_TENANT_DB_SECRET(_FILE), the
// same secret the API derives tenant passwords from.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/datakey"
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
	dsn := secret("SERK_ADMIN_DSN")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "SERK_ADMIN_DSN (or SERK_ADMIN_DSN_FILE) is required")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer conn.Close(ctx)

	if len(os.Args) > 1 && os.Args[1] == "provision-tenant" {
		fs := flag.NewFlagSet("provision-tenant", flag.ExitOnError)
		tenant := fs.String("tenant", "", "tenant uuid")
		name := fs.String("name", "", "tenant display name")
		_ = fs.Parse(os.Args[2:])
		sec := secret("SERK_TENANT_DB_SECRET")
		approval := secret("SERK_APPROVAL_SIGNING_KEY")
		if *tenant == "" || *name == "" || len(sec) < 32 || len(approval) < 32 || approval == sec {
			fmt.Fprintln(os.Stderr, "--tenant, --name, SERK_TENANT_DB_SECRET and a different SERK_APPROVAL_SIGNING_KEY (each >= 32 bytes) are required")
			os.Exit(2)
		}
		if err := postgres.ProvisionTenant(ctx, conn, *tenant, *name, postgres.TenantPassword([]byte(sec), *tenant)); err != nil {
			fmt.Fprintln(os.Stderr, "provision:", err)
			os.Exit(1)
		}
		// The database stores only the derived per-tenant verification key.
		if err := postgres.InstallApprovalKey(ctx, conn, *tenant, "v1", attest.TenantKey([]byte(approval), *tenant)); err != nil {
			fmt.Fprintln(os.Stderr, "approval key:", err)
			os.Exit(1)
		}
		role, _ := postgres.RoleName(*tenant)
		fmt.Printf("tenant %s provisioned with database role %s\n", *tenant, role)
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "encrypt-bank-accounts" {
		// 0032: convert pre-0032 plaintext account numbers to ciphertext.
		// Runs as the schema owner with SERK_BANK_DATA_KEY; the posture check
		// refuses production start-up until no plaintext remains.
		key := secret("SERK_BANK_DATA_KEY")
		if len(key) < 32 {
			fmt.Fprintln(os.Stderr, "SERK_BANK_DATA_KEY (>= 32 bytes) is required")
			os.Exit(2)
		}
		ring := datakey.Ring{Current: datakey.Key{ID: envOr("SERK_BANK_DATA_KEY_ID", "k1"), Master: []byte(key)}}
		n, err := postgres.EncryptBankAccounts(ctx, conn, ring)
		if err != nil {
			fmt.Fprintln(os.Stderr, "encrypt-bank-accounts:", err)
			os.Exit(1)
		}
		fmt.Printf("%d bank account number(s) encrypted\n", n)
		return
	}

	applied, err := postgres.Migrate(ctx, conn)
	for _, a := range applied {
		fmt.Println("applied", a)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		os.Exit(1)
	}
	if len(applied) == 0 {
		fmt.Println("schema up to date")
	}
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
