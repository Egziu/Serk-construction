// Package legacy validates a legacy data bundle before anything is loaded
// (GATEA-13). It reads the CSV files below, checks every reference and every
// financial rule, and reports each exception with file, line and rule. It
// never loads: a bundle with exceptions is sent back for correction, and a
// clean one is loaded as DRAFT documents that people approve and post (the
// loader is not part of this package).
//
// Bundle (UTF-8 CSV with a header row):
//
//	accounts.csv          code,name,type                     type: ASSET LIABILITY EQUITY REVENUE EXPENSE
//	suppliers.csv         code,name,tin
//	customers.csv         code,name
//	cost_codes.csv        code,name
//	opening_balances.csv  account_code,cost_code,debit,credit  one line per account (debit XOR credit); must balance
//	open_payables.csv     supplier_code,number,invoice_date,due_date,amount   open supplier invoices
//	open_receivables.csv  customer_code,number,invoice_date,due_date,amount   open customer invoices
//
// Amounts are in the entity's functional currency, at most minor_units
// decimals. Dates are YYYY-MM-DD and must fall on or before the cut-over
// date. The sum of open payables must equal the opening balance of the AP
// control account, and open receivables that of the AR control account.
package legacy

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/shopspring/decimal"
)

// Options of a validation run.
type Options struct {
	Dir        string
	CutOver    time.Time
	MinorUnits int32
	APAccount  string // code of the AP control account
	ARAccount  string // code of the AR control account
}

// Exception is one finding; the bundle is rejected while any exists.
type Exception struct {
	File string `json:"file"`
	Line int    `json:"line"` // 1-based, 1 = header; 0 = file level
	Rule string `json:"rule"`
	Text string `json:"detail"`
}

// Summary of a run.
type Summary struct {
	Files      map[string]int `json:"rows_by_file"`
	Exceptions []Exception    `json:"exceptions"`
	Balanced   bool           `json:"opening_balances_balanced"`
	TotalDebit string         `json:"opening_debit"`
	TotalCredt string         `json:"opening_credit"`
	Payables   string         `json:"open_payables_total"`
	Receivable string         `json:"open_receivables_total"`
}

var (
	codeForm = regexp.MustCompile(`^[A-Z0-9][A-Z0-9._/-]{0,39}$`)
	tinForm  = regexp.MustCompile(`^[A-Z0-9-]{4,20}$`)
	acctType = map[string]bool{"ASSET": true, "LIABILITY": true, "EQUITY": true, "REVENUE": true, "EXPENSE": true}
)

type table struct {
	name string
	hdr  []string
	rows [][]string
}

func readCSV(dir, name string, want []string) (*table, []Exception) {
	f, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return nil, []Exception{{File: name, Rule: "FILE", Text: "missing: " + err.Error()}}
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.TrimLeadingSpace = true
	hdr, err := r.Read()
	if err != nil {
		return nil, []Exception{{File: name, Rule: "FILE", Text: "no header row"}}
	}
	for i := range hdr {
		hdr[i] = strings.TrimSpace(strings.ToLower(hdr[i]))
	}
	if strings.Join(hdr, ",") != strings.Join(want, ",") {
		return nil, []Exception{{File: name, Line: 1, Rule: "HEADER", Text: fmt.Sprintf("columns %q, want %q", strings.Join(hdr, ","), strings.Join(want, ","))}}
	}
	t := &table{name: name, hdr: hdr}
	var ex []Exception
	for n := 2; ; n++ {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			ex = append(ex, Exception{File: name, Line: n, Rule: "CSV", Text: err.Error()})
			continue
		}
		for i := range rec {
			rec[i] = strings.TrimSpace(rec[i])
		}
		t.rows = append(t.rows, rec)
	}
	return t, ex
}

// Validate runs every rule and returns the summary (never an error for a
// bad bundle: those are exceptions).
func Validate(o Options) Summary {
	s := Summary{Files: map[string]int{}}
	add := func(file string, line int, rule, text string) {
		s.Exceptions = append(s.Exceptions, Exception{file, line, rule, text})
	}
	money := func(file string, line int, col, v string) (decimal.Decimal, bool) {
		if v == "" {
			return decimal.Zero, true
		}
		d, err := decimal.NewFromString(v)
		if err != nil {
			add(file, line, "AMOUNT", col+" is not a number: "+v)
			return decimal.Zero, false
		}
		if d.Exponent() < -o.MinorUnits {
			add(file, line, "PRECISION", fmt.Sprintf("%s %s has more than %d decimals", col, v, o.MinorUnits))
			return d, false
		}
		return d, true
	}
	date := func(file string, line int, col, v string) (time.Time, bool) {
		d, err := time.Parse("2006-01-02", v)
		if err != nil {
			add(file, line, "DATE", col+" is not YYYY-MM-DD: "+v)
			return d, false
		}
		if d.After(o.CutOver) {
			add(file, line, "CUTOVER", fmt.Sprintf("%s %s is after the cut-over date %s", col, v, o.CutOver.Format("2006-01-02")))
			return d, false
		}
		return d, true
	}
	uniq := func(file string, line int, seen map[string]int, key, what string) bool {
		if first, dup := seen[key]; dup {
			add(file, line, "DUPLICATE", fmt.Sprintf("%s %q repeats line %d", what, key, first))
			return false
		}
		seen[key] = line
		return true
	}

	accounts, ex := readCSV(o.Dir, "accounts.csv", []string{"code", "name", "type"})
	s.Exceptions = append(s.Exceptions, ex...)
	acct := map[string]string{}
	if accounts != nil {
		seen := map[string]int{}
		for i, r := range accounts.rows {
			n := i + 2
			if !codeForm.MatchString(r[0]) {
				add("accounts.csv", n, "CODE", "account code "+r[0])
			}
			if r[1] == "" {
				add("accounts.csv", n, "NAME", "empty name")
			}
			if !acctType[r[2]] {
				add("accounts.csv", n, "TYPE", "account type "+r[2])
			}
			if uniq("accounts.csv", n, seen, r[0], "account") {
				acct[r[0]] = r[2]
			}
		}
		s.Files["accounts.csv"] = len(accounts.rows)
	}
	for _, c := range []struct{ code, what string }{{o.APAccount, "AP control"}, {o.ARAccount, "AR control"}} {
		if _, ok := acct[c.code]; !ok && accounts != nil {
			add("accounts.csv", 0, "CONTROL", c.what+" account "+c.code+" is not in the chart")
		}
	}

	suppliers, ex := readCSV(o.Dir, "suppliers.csv", []string{"code", "name", "tin"})
	s.Exceptions = append(s.Exceptions, ex...)
	sup := map[string]bool{}
	if suppliers != nil {
		seen, tins := map[string]int{}, map[string]int{}
		for i, r := range suppliers.rows {
			n := i + 2
			if !codeForm.MatchString(r[0]) {
				add("suppliers.csv", n, "CODE", "supplier code "+r[0])
			}
			if r[1] == "" {
				add("suppliers.csv", n, "NAME", "empty name")
			}
			if !tinForm.MatchString(r[2]) {
				add("suppliers.csv", n, "TIN", "tax id "+r[2])
			} else {
				uniq("suppliers.csv", n, tins, r[2], "tax id")
			}
			if uniq("suppliers.csv", n, seen, r[0], "supplier") {
				sup[r[0]] = true
			}
		}
		s.Files["suppliers.csv"] = len(suppliers.rows)
	}

	customers, ex := readCSV(o.Dir, "customers.csv", []string{"code", "name"})
	s.Exceptions = append(s.Exceptions, ex...)
	cust := map[string]bool{}
	if customers != nil {
		seen := map[string]int{}
		for i, r := range customers.rows {
			n := i + 2
			if !codeForm.MatchString(r[0]) {
				add("customers.csv", n, "CODE", "customer code "+r[0])
			}
			if r[1] == "" {
				add("customers.csv", n, "NAME", "empty name")
			}
			if uniq("customers.csv", n, seen, r[0], "customer") {
				cust[r[0]] = true
			}
		}
		s.Files["customers.csv"] = len(customers.rows)
	}

	costCodes, ex := readCSV(o.Dir, "cost_codes.csv", []string{"code", "name"})
	s.Exceptions = append(s.Exceptions, ex...)
	cc := map[string]bool{}
	if costCodes != nil {
		seen := map[string]int{}
		for i, r := range costCodes.rows {
			n := i + 2
			if !codeForm.MatchString(r[0]) {
				add("cost_codes.csv", n, "CODE", "cost code "+r[0])
			}
			if uniq("cost_codes.csv", n, seen, r[0], "cost code") {
				cc[r[0]] = true
			}
		}
		s.Files["cost_codes.csv"] = len(costCodes.rows)
	}

	ob, ex := readCSV(o.Dir, "opening_balances.csv", []string{"account_code", "cost_code", "debit", "credit"})
	s.Exceptions = append(s.Exceptions, ex...)
	debit, credit := decimal.Zero, decimal.Zero
	apOpening, arOpening := decimal.Zero, decimal.Zero
	if ob != nil {
		seen := map[string]int{}
		for i, r := range ob.rows {
			n := i + 2
			typ, ok := acct[r[0]]
			if !ok {
				add("opening_balances.csv", n, "FK", "account "+r[0]+" is not in accounts.csv")
			}
			if r[1] != "" && !cc[r[1]] {
				add("opening_balances.csv", n, "FK", "cost code "+r[1]+" is not in cost_codes.csv")
			}
			if (typ == "EXPENSE" || typ == "REVENUE") && r[1] == "" {
				add("opening_balances.csv", n, "COSTCODE", "a "+strings.ToLower(typ)+" balance needs a cost code")
			}
			d, okd := money("opening_balances.csv", n, "debit", r[2])
			c, okc := money("opening_balances.csv", n, "credit", r[3])
			if okd && okc {
				switch {
				case d.IsNegative() || c.IsNegative():
					add("opening_balances.csv", n, "SIGN", "negative amount")
				case d.IsZero() == c.IsZero():
					add("opening_balances.csv", n, "ONESIDE", "exactly one of debit and credit must be non-zero")
				default:
					debit, credit = debit.Add(d), credit.Add(c)
					if r[0] == o.APAccount {
						apOpening = apOpening.Add(c).Sub(d)
					}
					if r[0] == o.ARAccount {
						arOpening = arOpening.Add(d).Sub(c)
					}
				}
			}
			uniq("opening_balances.csv", n, seen, r[0]+"/"+r[1], "account/cost code")
		}
		s.Files["opening_balances.csv"] = len(ob.rows)
		s.Balanced = debit.Equal(credit)
		if !s.Balanced {
			add("opening_balances.csv", 0, "BALANCE", fmt.Sprintf("debits %s do not equal credits %s (difference %s)", debit, credit, debit.Sub(credit)))
		}
	}
	s.TotalDebit, s.TotalCredt = debit.String(), credit.String()

	openItems := func(file, party string, parties map[string]bool, control decimal.Decimal, controlName string) decimal.Decimal {
		t, ex := readCSV(o.Dir, file, []string{party + "_code", "number", "invoice_date", "due_date", "amount"})
		s.Exceptions = append(s.Exceptions, ex...)
		total := decimal.Zero
		if t == nil {
			return total
		}
		seen := map[string]int{}
		for i, r := range t.rows {
			n := i + 2
			if !parties[r[0]] {
				add(file, n, "FK", party+" "+r[0]+" is not in "+party+"s.csv")
			}
			if r[1] == "" {
				add(file, n, "NUMBER", "empty document number")
			}
			uniq(file, n, seen, r[0]+"/"+r[1], party+"/number")
			inv, ok1 := date(file, n, "invoice_date", r[2])
			due, err := time.Parse("2006-01-02", r[3])
			if err != nil {
				add(file, n, "DATE", "due_date is not YYYY-MM-DD: "+r[3])
			} else if ok1 && due.Before(inv) {
				add(file, n, "DUE", "due_date before invoice_date")
			}
			a, ok := money(file, n, "amount", r[4])
			if ok {
				if !a.IsPositive() {
					add(file, n, "SIGN", "amount must be positive (credits are separate documents)")
				} else {
					total = total.Add(a)
				}
			}
		}
		s.Files[file] = len(t.rows)
		if ob != nil && !total.Equal(control) {
			add(file, 0, "CONTROL", fmt.Sprintf("open items total %s does not equal the %s opening balance %s", total, controlName, control))
		}
		return total
	}
	s.Payables = openItems("open_payables.csv", "supplier", sup, apOpening, "AP control").String()
	s.Receivable = openItems("open_receivables.csv", "customer", cust, arOpening, "AR control").String()

	sort.SliceStable(s.Exceptions, func(i, j int) bool {
		if s.Exceptions[i].File != s.Exceptions[j].File {
			return s.Exceptions[i].File < s.Exceptions[j].File
		}
		return s.Exceptions[i].Line < s.Exceptions[j].Line
	})
	return s
}
