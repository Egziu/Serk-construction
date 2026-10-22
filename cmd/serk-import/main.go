// serk-import validates a legacy data bundle (GATEA-13) before any load.
// It never writes to the database: a bundle with exceptions is sent back
// for correction; a clean one is loaded, in a later step, as DRAFT
// documents that people approve and post.
//
//	serk-import validate --dir <bundle> --cutover YYYY-MM-DD [--ap 2000] [--ar 1100] [--minor-units 2] [--json report.json]
//
// Exit status: 0 clean, 3 exceptions, 2 usage.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/serk-group/serk-construction/pkg/legacy"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "validate" {
		fmt.Fprintln(os.Stderr, "usage: serk-import validate --dir <bundle> --cutover YYYY-MM-DD [--ap CODE] [--ar CODE] [--minor-units N] [--json FILE]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	dir := fs.String("dir", "", "bundle directory")
	cut := fs.String("cutover", "", "cut-over date (YYYY-MM-DD); nothing may be dated after it")
	ap := fs.String("ap", "2000", "AP control account code")
	ar := fs.String("ar", "1100", "AR control account code")
	minor := fs.Int("minor-units", 2, "decimals of the functional currency")
	out := fs.String("json", "", "write the full report as JSON to this file")
	_ = fs.Parse(os.Args[2:])
	cutover, err := time.Parse("2006-01-02", *cut)
	if *dir == "" || err != nil {
		fmt.Fprintln(os.Stderr, "--dir and a valid --cutover are required")
		os.Exit(2)
	}
	s := legacy.Validate(legacy.Options{Dir: *dir, CutOver: cutover, MinorUnits: int32(*minor), APAccount: *ap, ARAccount: *ar})
	for f, n := range s.Files {
		fmt.Printf("%-24s %6d rows\n", f, n)
	}
	fmt.Printf("opening balances: debit %s credit %s balanced=%v; open payables %s; open receivables %s\n", s.TotalDebit, s.TotalCredt, s.Balanced, s.Payables, s.Receivable)
	for _, e := range s.Exceptions {
		fmt.Printf("EXCEPTION %s:%d %s: %s\n", e.File, e.Line, e.Rule, e.Text)
	}
	if *out != "" {
		b, _ := json.MarshalIndent(s, "", " ")
		if err := os.WriteFile(*out, b, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if len(s.Exceptions) > 0 {
		fmt.Printf("%d exception(s): the bundle is not loadable; correct the source data and validate again\n", len(s.Exceptions))
		os.Exit(3)
	}
	fmt.Println("bundle is clean: loadable as DRAFT documents for human approval")
}
