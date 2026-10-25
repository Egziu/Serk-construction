package export

import (
	"fmt"
	"io"
	"strings"
)

// XLSX: a "Summary" sheet with the letterhead and details, then one sheet per
// table with a frozen, filtered header row. Numbers are stored as exact
// decimals (not floats rounded for display); money uses #,##0.00.

// Cell styles (index into cellXfs).
const (
	xsDefault = iota
	xsCompany
	xsTitle
	xsMuted
	xsHeader
	xsMoney
	xsNumber
	xsLabel
	xsText
	xsBrand
	xsHeaderNum
)

func colName(i int) string {
	s := ""
	for i++; i > 0; i = (i - 1) / 26 {
		s = string(rune('A'+(i-1)%26)) + s
	}
	return s
}

type sheetBuilder struct {
	rows   strings.Builder
	r      int
	widths map[int]int
}

func (b *sheetBuilder) row(cells ...string) {
	b.r++
	fmt.Fprintf(&b.rows, `<row r="%d">%s</row>`, b.r, strings.Join(cells, ""))
}

func (b *sheetBuilder) str(c int, style int, s string) string {
	if l := len([]rune(s)); l > b.widths[c] {
		b.widths[c] = l
	}
	return fmt.Sprintf(`<c r="%s%d" t="inlineStr" s="%d"><is><t xml:space="preserve">%s</t></is></c>`, colName(c), b.r+1, style, xesc(s))
}

// title writes a cell that may overflow into empty neighbours; it does not
// widen its column.
func (b *sheetBuilder) title(c int, style int, s string) string {
	return fmt.Sprintf(`<c r="%s%d" t="inlineStr" s="%d"><is><t xml:space="preserve">%s</t></is></c>`, colName(c), b.r+1, style, xesc(s))
}

func (b *sheetBuilder) num(c int, style int, v, shown string) string {
	if l := len([]rune(shown)); l > b.widths[c] {
		b.widths[c] = l
	}
	return fmt.Sprintf(`<c r="%s%d" s="%d"><v>%s</v></c>`, colName(c), b.r+1, style, v)
}

func (b *sheetBuilder) xml(freezeRow int, filter string, minW map[int]int) string {
	var s strings.Builder
	s.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">`)
	s.WriteString(`<sheetViews><sheetView workbookViewId="0" showGridLines="0">`)
	if freezeRow > 0 {
		fmt.Fprintf(&s, `<pane ySplit="%d" topLeftCell="A%d" activePane="bottomLeft" state="frozen"/>`, freezeRow, freezeRow+1)
	}
	s.WriteString(`</sheetView></sheetViews><sheetFormatPr defaultRowHeight="16"/>`)
	if len(b.widths) > 0 {
		s.WriteString("<cols>")
		max := 0
		for c := range b.widths {
			if c > max {
				max = c
			}
		}
		for c := 0; c <= max; c++ {
			w := b.widths[c] + 3
			if m := minW[c]; w < m {
				w = m
			}
			if w > 60 {
				w = 60
			}
			if w < 8 {
				w = 8
			}
			fmt.Fprintf(&s, `<col min="%d" max="%d" width="%d" customWidth="1"/>`, c+1, c+1, w)
		}
		s.WriteString("</cols>")
	}
	s.WriteString("<sheetData>" + b.rows.String() + "</sheetData>")
	if filter != "" {
		s.WriteString(`<autoFilter ref="` + filter + `"/>`)
	}
	s.WriteString(`<pageMargins left="0.5" right="0.5" top="0.75" bottom="0.75" header="0.3" footer="0.3"/><pageSetup orientation="landscape" fitToWidth="1" fitToHeight="0"/>`)
	s.WriteString(`</worksheet>`)
	return s.String()
}

func sheetTitle(s string, used map[string]bool) string {
	s = strings.Map(func(r rune) rune {
		if strings.ContainsRune(`[]:*?/\`, r) {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if s == "" {
		s = "Table"
	}
	if r := []rune(s); len(r) > 28 {
		s = string(r[:28])
	}
	base, n := s, 2
	for used[strings.ToLower(s)] {
		s = fmt.Sprintf("%s %d", base, n)
		n++
	}
	used[strings.ToLower(s)] = true
	return s
}

func writeXLSX(w io.Writer, d Doc) error {
	type sheet struct{ name, xml string }
	var sheets []sheet
	used := map[string]bool{}

	// Summary.
	sb := &sheetBuilder{widths: map[int]int{}}
	sb.row(sb.title(0, xsCompany, d.Company))
	sb.row(sb.title(0, xsBrand, strings.ToUpper(d.Brand)))
	sb.row()
	sb.row(sb.title(0, xsTitle, d.Title))
	if d.Subtitle != "" {
		sb.row(sb.title(0, xsMuted, d.Subtitle))
	}
	sb.row(sb.title(0, xsMuted, footerLine(d)))
	sb.row()
	addKV := func(b *sheetBuilder, kvs []KV) {
		for _, kv := range kvs {
			b.row(b.str(0, xsLabel, kv.K), b.str(1, xsText, kv.V))
		}
	}
	addKV(sb, d.Meta)
	for _, s := range d.Sections {
		if len(s.Meta) > 0 {
			sb.row()
			sb.row(sb.title(0, xsTitle, s.Title))
			addKV(sb, s.Meta)
		}
	}
	sheets = append(sheets, sheet{sheetTitle("Summary", used), sb.xml(0, "", map[int]int{0: 24, 1: 40})})

	for _, s := range d.Sections {
		t := s.Table
		if t == nil || len(t.Columns) == 0 {
			continue
		}
		b := &sheetBuilder{widths: map[int]int{}}
		b.row(b.title(0, xsCompany, d.Company))
		b.row(b.title(0, xsTitle, s.Title+" · "+d.Title))
		b.row()
		hdr := make([]string, len(t.Columns))
		for i, c := range t.Columns {
			st := xsHeader
			if c.Numeric {
				st = xsHeaderNum
			}
			hdr[i] = b.str(i, st, c.Label)
		}
		b.row(hdr...)
		headRow := b.r
		for _, r := range t.Rows {
			cells := make([]string, 0, len(r))
			for i, c := range r {
				switch {
				case c.Num != "" && t.Columns[i].Money:
					cells = append(cells, b.num(i, xsMoney, c.Num, c.Text))
				case c.Num != "" && t.Columns[i].Numeric:
					cells = append(cells, b.num(i, xsNumber, c.Num, c.Text))
				case c.Text != "":
					cells = append(cells, b.str(i, xsText, c.Text))
				}
			}
			b.row(cells...)
		}
		filter := fmt.Sprintf("A%d:%s%d", headRow, colName(len(t.Columns)-1), b.r)
		sheets = append(sheets, sheet{sheetTitle(s.Title, used), b.xml(headRow, filter, nil)})
	}

	styles := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<numFmts count="2"><numFmt numFmtId="164" formatCode="#,##0.00;[Red]-#,##0.00"/><numFmt numFmtId="165" formatCode="#,##0.######"/></numFmts>
<fonts count="7">
<font><sz val="10"/><color rgb="FF` + hexInk + `"/><name val="Calibri"/><family val="2"/></font>
<font><b/><sz val="16"/><color rgb="FF` + hexGreen + `"/><name val="Georgia"/><family val="1"/></font>
<font><b/><sz val="12"/><color rgb="FF` + hexInk + `"/><name val="Georgia"/><family val="1"/></font>
<font><i/><sz val="9"/><color rgb="FF` + hexMuted + `"/><name val="Calibri"/><family val="2"/></font>
<font><b/><sz val="10"/><color rgb="FF` + hexCream + `"/><name val="Calibri"/><family val="2"/></font>
<font><b/><sz val="10"/><color rgb="FF` + hexMuted + `"/><name val="Calibri"/><family val="2"/></font>
<font><b/><sz val="9"/><color rgb="FF` + hexBrass + `"/><name val="Calibri"/><family val="2"/></font>
</fonts>
<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="FF` + hexGreen + `"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border>
<border><left/><right/><top/><bottom style="thin"><color rgb="FF` + hexLine + `"/></bottom><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="11">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="2" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="3" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="4" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment vertical="center" wrapText="1"/></xf>
<xf numFmtId="164" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1"/>
<xf numFmtId="165" fontId="0" fillId="0" borderId="1" xfId="0" applyNumberFormat="1" applyBorder="1"/>
<xf numFmtId="0" fontId="5" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment vertical="top"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="1" xfId="0" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="6" fillId="0" borderId="0" xfId="0" applyFont="1"/>
<xf numFmtId="0" fontId="4" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1" applyAlignment="1"><alignment horizontal="right" vertical="center" wrapText="1"/></xf>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>`

	var ct, wbSheets, wbRels strings.Builder
	files := [][2]string{}
	for i, s := range sheets {
		fmt.Fprintf(&ct, `<Override PartName="/xl/worksheets/sheet%d.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`, i+1)
		fmt.Fprintf(&wbSheets, `<sheet name="%s" sheetId="%d" r:id="rId%d"/>`, xesc(s.name), i+1, i+1)
		fmt.Fprintf(&wbRels, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet%d.xml"/>`, i+1, i+1)
		files = append(files, [2]string{fmt.Sprintf("xl/worksheets/sheet%d.xml", i+1), s.xml})
	}
	fmt.Fprintf(&wbRels, `<Relationship Id="rId%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`, len(sheets)+1)
	head := [][2]string{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>` + ct.String() + `
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>`},
		{"xl/workbook.xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><bookViews><workbookView/></bookViews><sheets>` + wbSheets.String() + `</sheets></workbook>`},
		{"xl/_rels/workbook.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">` + wbRels.String() + `</Relationships>`},
		{"xl/styles.xml", styles},
		{"docProps/core.xml", coreProps(d)},
		{"docProps/app.xml", appProps(d)},
	}
	return zipFiles(w, append(head, files...))
}
