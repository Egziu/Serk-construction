package export

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGroupDigits(t *testing.T) {
	for in, want := range map[string][2]string{
		"86000.000000":   {"86,000.00", "86,000"},
		"-1234567.005":   {"-1,234,567.01", "-1,234,567.005"},
		"0.004":          {"0.00", "0.004"},
		"999.995":        {"1,000.00", "999.995"},
		"-0.001":         {"0.00", "-0.001"},
		"12":             {"12.00", "12"},
		"5310000.010000": {"5,310,000.01", "5,310,000.01"},
		"abc":            {"abc", "abc"},
	} {
		if got := groupDigits(in, 2); got != want[0] {
			t.Errorf("groupDigits(%q, 2) = %q, want %q", in, got, want[0])
		}
		if got := groupDigits(in, -1); got != want[1] {
			t.Errorf("groupDigits(%q, -1) = %q, want %q", in, got, want[1])
		}
	}
}

// A purchase-order response as the API returns it.
const sampleDoc = `{"id":"7d1f","number":"PO-2026-000001","status":"APPROVED","created_by":"u-buyer","created_at":"2026-10-25T09:30:00Z",
 "detail":{"h":{"id":"7d1f","tenant_id":"t","number":"PO-2026-000001","supplier_id":"s1","currency":"ETB","subtotal":"1720000.000000",
   "tax_amount":"258000.000000","total":"1978000.000000","needed_by":"2026-11-15","approved_by":"u-proc-manager","approved_at":"2026-10-25T10:00:00Z",
   "description":"Reinforcement steel Grade 60 — Mekelle ring road, ሰላም"},
  "lines":[{"line_no":1,"description":"Steel G60 12mm","unit":"t","quantity":"20.000000","unit_price":"86000.000000","amount":"1720000.000000","cost_code_id":"c"},
           {"line_no":2,"description":"Delivery","unit":"trip","quantity":"1.5","unit_price":"0","amount":"0"}]}}`

func sample(t *testing.T) Doc {
	d, err := FromJSON("Purchase order PO-2026-000001", []byte(sampleDoc))
	if err != nil {
		t.Fatal(err)
	}
	d.Company, d.GeneratedBy = "SERK Demo Construction PLC", "u-auditor"
	d.GeneratedAt = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	return d
}

func TestFromJSON(t *testing.T) {
	d := sample(t)
	meta := map[string]string{}
	for _, kv := range d.Meta {
		meta[kv.K] = kv.V
	}
	if meta["Number"] != "PO-2026-000001" || meta["Total"] != "1,978,000.00" || meta["Needed by"] != "15 Nov 2026" || meta["Status"] != "APPROVED" {
		t.Fatalf("meta %v", d.Meta)
	}
	for _, kv := range d.Meta {
		if strings.Contains(kv.K, "Tenant") || kv.K == "Id" || kv.K == "Supplier" {
			t.Errorf("internal field exported: %v", kv)
		}
	}
	if len(d.Sections) != 1 || d.Sections[0].Title != "Lines" {
		t.Fatalf("sections %+v", d.Sections)
	}
	tb := d.Sections[0].Table
	var labels []string
	for _, c := range tb.Columns {
		labels = append(labels, c.Label)
	}
	if strings.Join(labels, "|") != "Line no|Description|Unit|Quantity|Unit price|Amount" {
		t.Fatalf("columns %v", labels)
	}
	if tb.Rows[0][4].Text != "86,000.00" || tb.Rows[0][4].Num != "86000.000000" || tb.Rows[1][3].Text != "1.5" {
		t.Fatalf("row %+v", tb.Rows)
	}
}

func render(t *testing.T, f Format) []byte {
	var b bytes.Buffer
	if err := Write(&b, f, sample(t)); err != nil {
		t.Fatal(err)
	}
	if dir := os.Getenv("SERK_EXPORT_SAMPLES"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "sample."+string(f)), b.Bytes(), 0o644)
	}
	return b.Bytes()
}

func zipText(t *testing.T, b []byte, name string) string {
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range zr.File {
		if f.Name == name {
			rc, _ := f.Open()
			s, _ := io.ReadAll(rc)
			return string(s)
		}
	}
	t.Fatalf("%s missing", name)
	return ""
}

func TestPDF(t *testing.T) {
	b := render(t, PDF)
	if !bytes.HasPrefix(b, []byte("%PDF-1.4")) || !bytes.HasSuffix(b, []byte("%%EOF\n")) {
		t.Fatal("not a PDF")
	}
	// The xref offsets must point at their objects.
	xref := regexp.MustCompile(`(?s)xref\n0 (\d+)\n(.*?)trailer`).FindSubmatch(b)
	if xref == nil {
		t.Fatal("no xref")
	}
	for i, ln := range strings.Split(strings.TrimSpace(string(xref[2])), "\n")[1:] {
		var off int
		if _, err := fmtSscan(ln[:10], &off); err != nil {
			t.Fatal(err)
		}
		want := []byte(strings.TrimSpace(strings.Split(string(b[off:off+12]), "\n")[0]))
		if !bytes.HasPrefix(want, []byte(itoa(i+1)+" 0 obj")) {
			t.Fatalf("xref entry %d points at %q", i+1, want)
		}
	}
	// Company, title, amounts and page footer are in the content.
	var all strings.Builder
	for _, m := range regexp.MustCompile(`(?s)stream\n(.*?)\nendstream`).FindAllSubmatch(b, -1) {
		zr, err := zlib.NewReader(bytes.NewReader(m[1]))
		if err != nil {
			t.Fatal(err)
		}
		s, _ := io.ReadAll(zr)
		all.Write(s)
	}
	for _, want := range []string{"(SERK Demo Construction PLC)", "(Purchase order PO-2026-000001)", "(1,978,000.00)", "(Page 1 of 1)", "(86,000.00)"} {
		if !strings.Contains(all.String(), want) {
			t.Errorf("PDF content lacks %s", want)
		}
	}
}

func TestDOCX(t *testing.T) {
	b := render(t, DOCX)
	doc := zipText(t, b, "word/document.xml")
	for _, want := range []string{"Purchase order PO-2026-000001", "1,978,000.00", "ሰላም", "<w:tblHeader/>"} {
		if !strings.Contains(doc, want) {
			t.Errorf("document.xml lacks %q", want)
		}
	}
	if h := zipText(t, b, "word/header1.xml"); !strings.Contains(h, "SERK Demo Construction PLC") {
		t.Error("header lacks the company")
	}
	if a := zipText(t, b, "docProps/app.xml"); !strings.Contains(a, "<Company>SERK Demo Construction PLC</Company>") {
		t.Error("app.xml lacks the company")
	}
}

func TestXLSX(t *testing.T) {
	b := render(t, XLSX)
	wb := zipText(t, b, "xl/workbook.xml")
	if !strings.Contains(wb, `name="Summary"`) || !strings.Contains(wb, `name="Lines"`) {
		t.Fatalf("sheets %s", wb)
	}
	lines := zipText(t, b, "xl/worksheets/sheet2.xml")
	// Exact decimal stored, money style, frozen header, filter.
	for _, want := range []string{`<v>86000.000000</v>`, `s="5"`, `state="frozen"`, `<autoFilter ref="A4:F6"/>`} {
		if !strings.Contains(lines, want) {
			t.Errorf("sheet2 lacks %q", want)
		}
	}
	if s := zipText(t, b, "xl/worksheets/sheet1.xml"); !strings.Contains(s, "SERK Demo Construction PLC") {
		t.Error("summary lacks the company")
	}
}

func TestFileName(t *testing.T) {
	d := sample(t)
	if got := FileName(d, PDF); got != "serk-demo-construction-plc-purchase-order-po-2026-000001-20261025-1200.pdf" {
		t.Fatal(got)
	}
	d.Company, d.Title = "../../etc", `a"b`
	if got := FileName(d, XLSX); strings.ContainsAny(got, `/"\`) {
		t.Fatal(got)
	}
}

func fmtSscan(s string, v *int) (int, error) { n, err := strconv.Atoi(s); *v = n; return 1, err }
func itoa(i int) string                      { return fmt.Sprint(i) }

// Ethiopic text embeds the Noto Sans Ethiopic font; Latin-only documents do not.
func TestPDFEthiopicFontOnlyWhenNeeded(t *testing.T) {
	if !bytes.Contains(render(t, PDF), []byte("/BaseFont /NotoSansEthiopic")) {
		t.Error("Ethiopic text without the embedded font")
	}
	var b bytes.Buffer
	if err := Write(&b, PDF, Doc{Title: "Latin only", Meta: []KV{{"Name", "Mekelle"}}}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b.Bytes(), []byte("NotoSansEthiopic")) {
		t.Error("font embedded in a Latin-only document")
	}
	if isEthiopic('A') || !isEthiopic('ሰ') {
		t.Error("isEthiopic")
	}
}
