// serk-migrate applies the embedded SQL migrations with an admin connection.
//
//	SERK_ADMIN_DSN=postgres://owner:pw@host/db serk-migrate
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
)

func main() {
	dsn := os.Getenv("SERK_ADMIN_DSN")
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "SERK_ADMIN_DSN is required")
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
