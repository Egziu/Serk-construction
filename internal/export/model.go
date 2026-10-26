// Package export renders a report or document as PDF, DOCX or XLSX with the
// company letterhead. It uses the Go standard library only (no new
// dependencies). It never queries data itself: callers hand it what the
// authorised API already returned for the requesting person, so an export can
// never show more than the screen does.
package export

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// Doc is a format-neutral document.
type Doc struct {
	Company     string // letterhead: the legal entity (or configured company name)
	Brand       string // product line under the letterhead
	Title       string
	Subtitle    string
	GeneratedBy string
	GeneratedAt time.Time
	// Watermark is printed faintly across every PDF page and in the DOCX
	// header and XLSX summary (who the copy was prepared for).
	Watermark string
	Meta      []KV
	Sections  []Section
}

// KV is one labelled value.
type KV struct{ K, V string }

// Section is a titled group: key/value details and/or a table.
type Section struct {
	Title string
	Meta  []KV
	Table *Table
}

// Table is a grid of cells under labelled columns.
type Table struct {
	Columns []Column
	Rows    [][]Cell
}

// Column describes one table column.
type Column struct {
	Label   string
	Numeric bool
	Money   bool
}

// Cell is display text plus, for numbers, the exact decimal for spreadsheets.
type Cell struct {
	Text string
	Num  string // exact decimal ("" when not numeric)
}

// Format is an output format.
type Format string

const (
	PDF  Format = "pdf"
	DOCX Format = "docx"
	XLSX Format = "xlsx"
)

// ErrFormat is returned for an unknown format.
var ErrFormat = errors.New("export: format must be pdf, docx or xlsx")

// ContentType returns the media type of a format.
func (f Format) ContentType() string {
	switch f {
	case PDF:
		return "application/pdf"
	case DOCX:
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case XLSX:
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	}
	return "application/octet-stream"
}

// Write renders d in format f.
func Write(w io.Writer, f Format, d Doc) error {
	if d.GeneratedAt.IsZero() {
		d.GeneratedAt = time.Now()
	}
	if d.Brand == "" {
		d.Brand = "SERK Construction"
	}
	if d.Company == "" {
		d.Company = d.Brand
	}
	switch f {
	case PDF:
		return writePDF(w, d)
	case DOCX:
		return writeDOCX(w, d)
	case XLSX:
		return writeXLSX(w, d)
	}
	return ErrFormat
}

// FileName is a safe attachment name: company-title-date.ext.
func FileName(d Doc, f Format) string {
	slug := func(s string) string {
		s = strings.ToLower(s)
		var b strings.Builder
		dash := false
		for _, r := range s {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				b.WriteRune(r)
				dash = false
			} else if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
		out := strings.Trim(b.String(), "-")
		if len(out) > 48 {
			out = strings.Trim(out[:48], "-")
		}
		return out
	}
	parts := []string{}
	for _, p := range []string{slug(d.Company), slug(d.Title)} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		parts = []string{"serk-export"}
	}
	return fmt.Sprintf("%s-%s.%s", strings.Join(parts, "-"), d.GeneratedAt.Format("20060102-1504"), f)
}

// footerLine is the provenance line printed on every page.
func footerLine(d Doc) string {
	s := "Generated " + d.GeneratedAt.Format("2 Jan 2006 15:04 MST")
	if d.GeneratedBy != "" {
		s += " by " + d.GeneratedBy
	}
	return s + " · " + d.Brand
}

var decimalRe = regexp.MustCompile(`^-?\d+(\.\d+)?$`)

// groupDigits formats an exact decimal string with thousands separators and
// the given number of decimals (rounding half away from zero on the string,
// never through float64). places < 0 keeps the significant decimals.
func groupDigits(s string, places int) string {
	if !decimalRe.MatchString(s) {
		return s
	}
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	ip, fp, _ := strings.Cut(s, ".")
	if places >= 0 {
		if len(fp) > places {
			round := fp[places] >= '5'
			fp = fp[:places]
			if round {
				digits := []byte(ip + fp)
				i := len(digits) - 1
				for ; i >= 0; i-- {
					if digits[i] == '9' {
						digits[i] = '0'
						continue
					}
					digits[i]++
					break
				}
				str := string(digits)
				if i < 0 {
					str = "1" + str
				}
				ip, fp = str[:len(str)-places], str[len(str)-places:]
			}
		}
		for len(fp) < places {
			fp += "0"
		}
	} else {
		fp = strings.TrimRight(fp, "0")
	}
	ip = strings.TrimLeft(ip, "0")
	if ip == "" {
		ip = "0"
	}
	var b strings.Builder
	for i, r := range ip {
		if i > 0 && (len(ip)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	out := b.String()
	if fp != "" {
		out += "." + fp
	}
	if neg && strings.Trim(out, "0.,") != "" {
		out = "-" + out
	}
	return out
}
