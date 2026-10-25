package export

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Internal or derived fields that mean nothing to a reader (as the console).
var hidden = map[string]bool{"tenant_id": true, "id": true, "normalized_number": true, "bank_snapshot": true, "command_hash": true,
	"source_sha256": true, "legal_entity_id": true, "match_detail": true, "es": true, "ef": true, "ls": true, "lf": true, "detail": true,
	"permissions": true, "idempotency_key": true}

// Reading order of document fields and of line columns (as the console).
var fieldOrder = []string{"number", "invoice_number", "statement_no", "code", "name", "label", "description", "justification", "title", "status",
	"technical_status", "match_status", "currency", "subtotal", "tax_amount", "total", "amount", "invoice_date", "due_date", "received_on",
	"value_date", "needed_by", "valid_until", "due_at",
	"line_no", "po_line_no", "pr_line_no", "item_no", "activity_code", "pred_code", "succ_code", "link_type", "lag", "duration",
	"early_start", "early_finish", "late_start", "late_finish", "total_float", "free_float", "critical", "budget", "percent_complete",
	"actual_start", "actual_finish", "unit", "quantity", "qty_received", "received_qty", "billed_qty_cumulative", "est_unit_price",
	"unit_price", "po_price", "invoice_price", "rate", "price_variance_pct", "within_tolerance", "est_amount", "note",
	"account_code", "account_name", "account_type", "debit", "credit", "balance",
	"party", "document", "days_overdue", "not_due", "d1_30", "d31_60", "d61_90", "over_90", "open"}

var (
	moneyKey  = regexp.MustCompile(`amount|total|price|balance|subtotal|threshold|gross$|_value$|recovery$|_held$|received$|recovered$|_open$|^open$|_released$|_cost$|value_change$|_approved$|^budget$|^debit$|^credit$|^not_due$|^d\d+_\d+$|^over_\d+$|^bac$|^pv$|^ev$|^ac$|^sv$|^cv$|^eac$|^etc$|^vac$|committed|actual|available|revenue|margin`)
	numericKy = regexp.MustCompile(`quantity|qty|price|amount|rate|total|pct|line|budget|duration|float|percent|lag|hours|headcount|version|debit|credit|balance|days|open|due|d\d|over_|^[bpe]v$|^ac$|^[sc]v$|^[sc]pi$|eac|etc|vac|committed|actual|available|revenue|margin|difference|subledger|^gl$|unposted|value`)
	stampKey  = regexp.MustCompile(`_at$`)
	dateKey   = regexp.MustCompile(`(_date|_on|_by_date|^date|_from|_to|needed_by|valid_until|_start|_finish)$`)
	idKey     = regexp.MustCompile(`(_id|_ids)$`)
)

// Column order of line tables (as the console).
var lineOrder = []string{"line_no", "po_line_no", "pr_line_no", "po_line", "item_no", "number", "invoice_number", "code", "account_code", "activity_code",
	"name", "account_name", "account_type", "party", "document", "label", "pred_code", "succ_code", "link_type", "lag",
	"duration", "early_start", "early_finish", "late_start", "late_finish", "total_float", "free_float", "critical", "budget", "percent_complete",
	"actual_start", "actual_finish", "description", "status", "unit", "quantity", "qty_received", "received_qty", "billed_qty_cumulative",
	"est_unit_price", "unit_price", "po_price", "invoice_price", "rate", "price_variance_pct", "within_tolerance", "est_amount", "amount",
	"invoice_date", "due_date", "days_overdue", "not_due", "d1_30", "d31_60", "d61_90", "over_90", "open", "debit", "credit", "balance", "note"}

func rankIn(order []string, k string) int {
	for i, f := range order {
		if f == k {
			return i
		}
	}
	n := len(order)
	if strings.HasSuffix(k, "_by") || strings.HasSuffix(k, "_at") {
		return n + 1
	}
	return n
}

func rank(k string) int {
	for i, f := range fieldOrder {
		if f == k {
			return i
		}
	}
	n := len(fieldOrder)
	if strings.HasSuffix(k, "_by") || strings.HasSuffix(k, "_at") {
		return n + 1
	}
	return n
}

func orderedKeys(m map[string]any) []string { return orderedBy(fieldOrder, m) }

func orderedBy(order []string, m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		ri, rj := rankIn(order, keys[i]), rankIn(order, keys[j])
		if ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})
	return keys
}

// Words turns a field name into a label: "due_date" -> "Due date".
func Words(k string) string {
	k = strings.TrimSuffix(k, "_id")
	switch k {
	case "d1_30":
		return "1–30 days"
	case "d31_60":
		return "31–60 days"
	case "d61_90":
		return "61–90 days"
	case "over_90":
		return "Over 90 days"
	case "ipc":
		return "IPC"
	case "label":
		return "Description"
	case "bac", "pv", "ev", "ac", "sv", "cv", "spi", "cpi", "eac", "etc", "vac", "gl", "vat":
		return strings.ToUpper(k)
	}
	s := strings.ReplaceAll(k, "_", " ")
	r := []rune(s)
	if len(r) > 0 {
		r[0] = unicode.ToUpper(r[0])
	}
	return string(r)
}

// scalar formats a JSON value for display; num is the exact decimal when the
// value is numeric.
func scalar(k string, v any) (text, num string, ok bool) {
	switch x := v.(type) {
	case nil:
		return "", "", false
	case bool:
		if x {
			return "Yes", "", true
		}
		return "No", "", true
	case json.Number:
		return fmtNum(k, x.String()), x.String(), true
	case float64:
		s := fmt.Sprintf("%v", x)
		return fmtNum(k, s), s, true
	case string:
		if stampKey.MatchString(k) {
			if t, err := time.Parse(time.RFC3339Nano, x); err == nil {
				return t.Format("2 Jan 2006 15:04"), "", true
			}
		}
		if dateKey.MatchString(k) && len(x) >= 10 {
			if t, err := time.Parse("2006-01-02", x[:10]); err == nil {
				return t.Format("2 Jan 2006"), "", true
			}
		}
		if decimalRe.MatchString(x) && numericKy.MatchString(k) {
			return fmtNum(k, x), x, true
		}
		return x, "", true
	}
	return "", "", false
}

func fmtNum(k, s string) string {
	if strings.HasSuffix(k, "_pct") {
		// Stored as a fraction (0.05 = 5%).
		if f, err := parseDec(s); err == nil {
			return fmt.Sprintf("%.2f%%", f*100)
		}
	}
	if moneyKey.MatchString(k) {
		return groupDigits(s, 2)
	}
	return groupDigits(s, -1)
}

func parseDec(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscan(s, &f)
	return f, err
}

// FromJSON converts an API response into a document: top-level scalars and
// a document's header become details; every array of objects becomes a
// table; nested objects become their own sections.
func FromJSON(title string, raw []byte) (Doc, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return Doc{}, fmt.Errorf("export: response is not JSON: %w", err)
	}
	d := Doc{Title: title}
	switch x := v.(type) {
	case []any:
		if t := tableOf(x); t != nil {
			d.Sections = append(d.Sections, Section{Title: title, Table: t})
		}
	case map[string]any:
		d.Meta, d.Sections = walk(x, "")
		// A document's header (detail.h / detail.q / detail) is part of its details.
		if det, ok := x["detail"].(map[string]any); ok {
			head := det
			for _, k := range []string{"h", "q"} {
				if m, ok := det[k].(map[string]any); ok {
					head = m
				}
			}
			for _, k := range orderedKeys(head) {
				if hidden[k] || idKey.MatchString(k) || present(d.Meta, Words(k)) {
					continue
				}
				if t, _, ok := scalar(k, head[k]); ok && t != "" {
					d.Meta = append(d.Meta, KV{Words(k), t})
				}
			}
			_, secs := walk(det, "")
			d.Sections = append(d.Sections, secs...)
			if md, ok := head["match_detail"].(map[string]any); ok {
				if lines, ok := md["lines"].([]any); ok {
					if t := tableOf(lines); t != nil {
						d.Sections = append(d.Sections, Section{Title: "Three-way match", Table: t})
					}
				}
			}
		}
	}
	return d, nil
}

func present(kvs []KV, k string) bool {
	for _, kv := range kvs {
		if kv.K == k {
			return true
		}
	}
	return false
}

func walk(m map[string]any, _ string) ([]KV, []Section) {
	var meta []KV
	var secs []Section
	for _, k := range orderedKeys(m) {
		if hidden[k] || k == "h" || k == "q" {
			continue
		}
		v := m[k]
		switch x := v.(type) {
		case []any:
			if t := tableOf(x); t != nil {
				secs = append(secs, Section{Title: Words(k), Table: t})
			} else if len(x) > 0 && !idKey.MatchString(k) {
				parts := make([]string, 0, len(x))
				for _, e := range x {
					if t, _, ok := scalar(k, e); ok {
						parts = append(parts, t)
					}
				}
				meta = append(meta, KV{Words(k), strings.Join(parts, ", ")})
			}
		case map[string]any:
			sm, ss := walk(x, k)
			if len(sm) > 0 {
				secs = append(secs, Section{Title: Words(k), Meta: sm})
			}
			secs = append(secs, ss...)
		default:
			if idKey.MatchString(k) {
				continue
			}
			if t, _, ok := scalar(k, v); ok && t != "" {
				meta = append(meta, KV{Words(k), t})
			}
		}
	}
	return meta, secs
}

// tableOf turns an array of objects into a table (nil if it is not one).
// A row that wraps its record in a single object field ({"q": {...}}) is
// unwrapped.
func tableOf(items []any) *Table {
	var rows []map[string]any
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			return nil
		}
		if len(m) == 1 {
			for _, inner := range m {
				if im, ok := inner.(map[string]any); ok {
					m = im
				}
			}
		}
		rows = append(rows, m)
	}
	if len(rows) == 0 {
		return nil
	}
	seen := map[string]bool{}
	union := map[string]any{}
	for _, r := range rows {
		for k, v := range r {
			if seen[k] || hidden[k] || idKey.MatchString(k) {
				continue
			}
			switch v.(type) {
			case map[string]any, []any:
				continue
			}
			seen[k] = true
			union[k] = v
		}
	}
	keys := orderedBy(lineOrder, union)
	if len(keys) == 0 {
		return nil
	}
	t := &Table{}
	for _, k := range keys {
		t.Columns = append(t.Columns, Column{Label: Words(k), Numeric: numericKy.MatchString(k), Money: moneyKey.MatchString(k)})
	}
	for _, r := range rows {
		row := make([]Cell, len(keys))
		for i, k := range keys {
			if txt, num, ok := scalar(k, r[k]); ok {
				row[i] = Cell{Text: txt, Num: num}
			}
		}
		t.Rows = append(t.Rows, row)
	}
	// A column is numeric only if every non-empty cell is.
	for i := range t.Columns {
		if !t.Columns[i].Numeric {
			continue
		}
		for _, row := range t.Rows {
			if row[i].Text != "" && row[i].Num == "" {
				t.Columns[i].Numeric, t.Columns[i].Money = false, false
				break
			}
		}
	}
	return t
}
