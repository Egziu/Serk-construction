// serk-devtoken mints HS256 tokens for local development and staging. It is
// not built into the production image and refuses to run when SERK_ENV is
// production or unset.
//
//	SERK_ENV=development SERK_TOKEN_SECRET=... serk-devtoken --sub u1 --tenant <uuid> --roles accountant --mfa
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/serk-group/serk-construction/internal/httpapi"
)

func main() {
	env := os.Getenv("SERK_ENV")
	if env != "development" && env != "staging" {
		fmt.Fprintln(os.Stderr, "serk-devtoken runs only with SERK_ENV=development or staging")
		os.Exit(2)
	}
	sub := flag.String("sub", "", "user id")
	tenant := flag.String("tenant", "", "tenant uuid")
	roles := flag.String("roles", "accountant", "comma-separated roles")
	projects := flag.String("projects", "", "comma-separated project ids (empty = none)")
	mfa := flag.Bool("mfa", false, "assert a fresh multi-factor login (amr=pwd,otp)")
	ttl := flag.Duration("ttl", time.Hour, "token lifetime")
	flag.Parse()
	if *sub == "" || *tenant == "" {
		fmt.Fprintln(os.Stderr, "--sub and --tenant are required")
		os.Exit(2)
	}
	v := httpapi.HS256Verifier{Secret: []byte(os.Getenv("SERK_TOKEN_SECRET")), Issuer: envOr("SERK_TOKEN_ISSUER", "serk-id"), Audience: envOr("SERK_TOKEN_AUDIENCE", "serk-construction")}
	now := time.Now()
	c := httpapi.Claims{Subject: *sub, TenantID: *tenant, Roles: strings.Split(*roles, ","), IssuedAt: now.Unix(), ExpiresAt: now.Add(*ttl).Unix(),
		Issuer: v.Issuer, Audience: v.Audience}
	if *projects != "" {
		c.Projects = strings.Split(*projects, ",")
	}
	if *mfa {
		c.AMR, c.AuthTime = []string{"pwd", "otp"}, now.Unix()
	}
	tok, err := v.Sign(c)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(tok)
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
