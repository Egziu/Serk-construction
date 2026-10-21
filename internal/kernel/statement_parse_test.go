package kernel

import (
	"strings"
	"testing"
)

// The statement parser accepts exactly one meaning per file and refuses what
// the database would refuse, before any attestation is signed.
func TestParseStatementRefusesAmbiguousOrInvalidFiles(t *testing.T) {
	const bank = "0b0f2a4e-1111-4222-8333-944455566677"
	ok := `{"company_bank_id":"` + bank + `","statement_no":"S-1","statement_date":"2026-10-22","opening_balance":"10","closing_balance":"5",` +
		`"lines":[{"booking_date":"2026-10-22","amount":"-5","reference":"PAY-1","counterparty":"X"}]}`
	if _, err := ParseStatement([]byte(ok)); err != nil {
		t.Fatalf("valid statement refused: %v", err)
	}
	for name, raw := range map[string]string{
		"duplicate key":         strings.Replace(ok, `"statement_no":"S-1"`, `"statement_no":"S-1","statement_no":"S-2"`, 1),
		"duplicate line key":    strings.Replace(ok, `"amount":"-5"`, `"amount":"-5","amount":"-500"`, 1),
		"unknown field":         strings.Replace(ok, `"statement_no"`, `"note":"x","statement_no"`, 1),
		"trailing data":         ok + `{}`,
		"NUL in reference":      strings.Replace(ok, `PAY-1`, `PAY\u00001`, 1),
		"zero amount":           strings.Replace(ok, `"-5","reference"`, `"0","reference"`, 1),
		"19 integer digits":     strings.Replace(ok, `"-5","reference"`, `"-1000000000000000000","reference"`, 1),
		"7 decimals":            strings.Replace(ok, `"-5","reference"`, `"-5.0000001","reference"`, 1),
		"bad date":              strings.Replace(ok, `"statement_date":"2026-10-22"`, `"statement_date":"22/10/2026"`, 1),
		"not a bank account id": strings.Replace(ok, bank, "CBE", 1),
	} {
		if _, err := ParseStatement([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			t.Logf("refused %-22s %v", name+":", err)
		}
	}
}
