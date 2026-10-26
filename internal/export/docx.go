package export

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"
)

// Office Open XML helpers shared by DOCX and XLSX.

func xesc(s string) string {
	var b strings.Builder
	// Drop characters XML 1.0 forbids.
	clean := strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' || (r >= 0x20 && r <= 0xD7FF) || (r >= 0xE000 && r <= 0xFFFD) || (r >= 0x10000 && r <= 0x10FFFF) {
			return r
		}
		return -1
	}, s)
	_ = xml.EscapeText(&b, []byte(clean))
	return b.String()
}

func zipFiles(w io.Writer, files [][2]string) error {
	zw := zip.NewWriter(w)
	for _, f := range files {
		hdr := &zip.FileHeader{Name: f[0], Method: zip.Deflate, Modified: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
		fw, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(fw, f[1]); err != nil {
			return err
		}
	}
	return zw.Close()
}

func coreProps(d Doc) string {
	ts := d.GeneratedAt.UTC().Format("2006-01-02T15:04:05Z")
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>` + xesc(d.Title) + `</dc:title><dc:creator>` + xesc(d.GeneratedBy) + `</dc:creator><cp:lastModifiedBy>` + xesc(d.GeneratedBy) + `</cp:lastModifiedBy>
<dc:description>` + xesc(footerLine(d)) + `</dc:description>
<dcterms:created xsi:type="dcterms:W3CDTF">` + ts + `</dcterms:created><dcterms:modified xsi:type="dcterms:W3CDTF">` + ts + `</dcterms:modified>
</cp:coreProperties>`
}

func appProps(d Doc) string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>` + xesc(d.Brand) +
		`</Application><Company>` + xesc(d.Company) + `</Company></Properties>`
}

// ---------- DOCX ----------

const (
	hexGreen = "1B4A33"
	hexInk   = "10291D"
	hexCream = "F3ECD9"
	hexPaper = "FBF7EC"
	hexMuted = "4A5A4E"
	hexLine  = "D8CDB0"
	hexBrass = "8A6420"
)

func run(text string, bold bool, size int, color string) string {
	var p strings.Builder
	p.WriteString("<w:r><w:rPr>")
	if bold {
		p.WriteString("<w:b/>")
	}
	if color != "" {
		p.WriteString(`<w:color w:val="` + color + `"/>`)
	}
	if size > 0 {
		fmt.Fprintf(&p, `<w:sz w:val="%d"/><w:szCs w:val="%d"/>`, size, size)
	}
	p.WriteString(`</w:rPr><w:t xml:space="preserve">` + xesc(text) + `</w:t></w:r>`)
	return p.String()
}

func para(style, align string, runs ...string) string {
	var b strings.Builder
	b.WriteString("<w:p><w:pPr>")
	if style != "" {
		b.WriteString(`<w:pStyle w:val="` + style + `"/>`)
	}
	if align != "" {
		b.WriteString(`<w:jc w:val="` + align + `"/>`)
	}
	b.WriteString("</w:pPr>")
	for _, r := range runs {
		b.WriteString(r)
	}
	b.WriteString("</w:p>")
	return b.String()
}

func cell(width int, fill string, content string) string {
	shd := ""
	if fill != "" {
		shd = `<w:shd w:val="clear" w:color="auto" w:fill="` + fill + `"/>`
	}
	return fmt.Sprintf(`<w:tc><w:tcPr><w:tcW w:w="%d" w:type="dxa"/>%s</w:tcPr>%s</w:tc>`, width, shd, content)
}

func writeDOCX(w io.Writer, d Doc) error {
	wide := 0
	for _, s := range d.Sections {
		if s.Table != nil && len(s.Table.Columns) > wide {
			wide = len(s.Table.Columns)
		}
	}
	pw, ph, orient := 11906, 16838, ""
	if wide > 6 {
		pw, ph, orient = 16838, 11906, ` w:orient="landscape"`
	}
	inner := pw - 2*1000

	var body strings.Builder
	body.WriteString(para("Title", "", run(d.Title, false, 0, "")))
	if d.Subtitle != "" {
		body.WriteString(para("Subtitle", "", run(d.Subtitle, false, 0, "")))
	}
	kvTable := func(kvs []KV) {
		if len(kvs) == 0 {
			return
		}
		lw := inner * 30 / 100
		body.WriteString(`<w:tbl><w:tblPr><w:tblW w:w="` + fmt.Sprint(inner) + `" w:type="dxa"/><w:tblLayout w:type="fixed"/><w:tblCellMar><w:top w:w="40" w:type="dxa"/><w:bottom w:w="40" w:type="dxa"/></w:tblCellMar></w:tblPr><w:tblGrid>`)
		fmt.Fprintf(&body, `<w:gridCol w:w="%d"/><w:gridCol w:w="%d"/></w:tblGrid>`, lw, inner-lw)
		for _, kv := range kvs {
			body.WriteString("<w:tr>" + cell(lw, "", para("Label", "", run(kv.K, true, 17, hexMuted))) + cell(inner-lw, "", para("Cell", "", run(kv.V, false, 19, hexInk))) + "</w:tr>")
		}
		body.WriteString("</w:tbl>")
		body.WriteString(para("", "", ""))
	}
	kvTable(d.Meta)
	for _, s := range d.Sections {
		if s.Title != "" {
			body.WriteString(para("Heading2", "", run(s.Title, false, 0, "")))
		}
		kvTable(s.Meta)
		if t := s.Table; t != nil && len(t.Columns) > 0 {
			// Column widths proportional to content, within the page.
			nat := make([]int, len(t.Columns))
			total := 0
			for i, c := range t.Columns {
				nat[i] = len([]rune(c.Label))
				for _, r := range t.Rows {
					if l := len([]rune(r[i].Text)); l > nat[i] {
						nat[i] = l
					}
				}
				if nat[i] > 40 {
					nat[i] = 40
				}
				if nat[i] < 6 {
					nat[i] = 6
				}
				total += nat[i]
			}
			widths := make([]int, len(nat))
			for i := range nat {
				widths[i] = nat[i] * inner / total
			}
			body.WriteString(`<w:tbl><w:tblPr><w:tblStyle w:val="SerkTable"/><w:tblW w:w="` + fmt.Sprint(inner) + `" w:type="dxa"/><w:tblLayout w:type="fixed"/></w:tblPr><w:tblGrid>`)
			for _, wd := range widths {
				fmt.Fprintf(&body, `<w:gridCol w:w="%d"/>`, wd)
			}
			body.WriteString(`</w:tblGrid><w:tr><w:trPr><w:tblHeader/><w:cantSplit/></w:trPr>`)
			for i, c := range t.Columns {
				al := ""
				if c.Numeric {
					al = "right"
				}
				body.WriteString(cell(widths[i], hexGreen, para("Cell", al, run(strings.ToUpper(c.Label), true, 15, hexCream))))
			}
			body.WriteString("</w:tr>")
			for ri, r := range t.Rows {
				fill := ""
				if ri%2 == 1 {
					fill = hexPaper
				}
				body.WriteString("<w:tr><w:trPr><w:cantSplit/></w:trPr>")
				for i, c := range t.Columns {
					al := ""
					if c.Numeric {
						al = "right"
					}
					body.WriteString(cell(widths[i], fill, para("Cell", al, run(r[i].Text, false, 17, hexInk))))
				}
				body.WriteString("</w:tr>")
			}
			body.WriteString("</w:tbl>")
			if len(t.Rows) == 0 {
				body.WriteString(para("", "", run("No rows.", false, 18, hexMuted)))
			}
			body.WriteString(para("", "", ""))
		}
	}
	fmt.Fprintf(&body, `<w:sectPr><w:headerReference w:type="default" r:id="rIdHeader"/><w:footerReference w:type="default" r:id="rIdFooter"/>`+
		`<w:pgSz w:w="%d" w:h="%d"%s/><w:pgMar w:top="1400" w:right="1000" w:bottom="1100" w:left="1000" w:header="500" w:footer="500" w:gutter="0"/></w:sectPr>`, pw, ph, orient)

	const ns = `xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"`
	document := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document ` + ns + `><w:body>` + body.String() + `</w:body></w:document>`

	tab := fmt.Sprint(inner)
	header := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:hdr ` + ns + `>` +
		`<w:p><w:pPr><w:pBdr><w:bottom w:val="single" w:sz="12" w:space="4" w:color="` + hexBrass + `"/></w:pBdr><w:tabs><w:tab w:val="right" w:pos="` + tab + `"/></w:tabs></w:pPr>` +
		`<w:r><w:rPr><w:rFonts w:ascii="Georgia" w:hAnsi="Georgia"/><w:b/><w:color w:val="` + hexGreen + `"/><w:sz w:val="28"/></w:rPr><w:t xml:space="preserve">` + xesc(d.Company) + `</w:t></w:r>` +
		`<w:r><w:tab/></w:r><w:r><w:rPr><w:b/><w:caps/><w:color w:val="` + hexBrass + `"/><w:sz w:val="16"/></w:rPr><w:t>` + xesc(d.Brand) + `</w:t></w:r></w:p>` +
		wmPara(d) + `</w:hdr>`
	footer := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr ` + ns + `>` +
		`<w:p><w:pPr><w:pBdr><w:top w:val="single" w:sz="4" w:space="4" w:color="` + hexLine + `"/></w:pBdr><w:tabs><w:tab w:val="right" w:pos="` + tab + `"/></w:tabs></w:pPr>` +
		run(footerLine(d), false, 15, hexMuted) + `<w:r><w:tab/></w:r>` + run("Page ", true, 15, hexMuted) +
		`<w:r><w:rPr><w:b/><w:color w:val="` + hexMuted + `"/><w:sz w:val="15"/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:rPr><w:b/><w:sz w:val="15"/></w:rPr><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:rPr><w:b/><w:sz w:val="15"/></w:rPr><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:rPr><w:b/><w:color w:val="` + hexMuted + `"/><w:sz w:val="15"/></w:rPr><w:t>1</w:t></w:r><w:r><w:rPr><w:b/><w:sz w:val="15"/></w:rPr><w:fldChar w:fldCharType="end"/></w:r>` +
		run(" of ", true, 15, hexMuted) +
		`<w:r><w:rPr><w:b/><w:color w:val="` + hexMuted + `"/><w:sz w:val="15"/></w:rPr><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:rPr><w:b/><w:sz w:val="15"/></w:rPr><w:instrText xml:space="preserve"> NUMPAGES </w:instrText></w:r><w:r><w:rPr><w:b/><w:sz w:val="15"/></w:rPr><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:rPr><w:b/><w:color w:val="` + hexMuted + `"/><w:sz w:val="15"/></w:rPr><w:t>1</w:t></w:r><w:r><w:rPr><w:b/><w:sz w:val="15"/></w:rPr><w:fldChar w:fldCharType="end"/></w:r>` +
		`</w:p></w:ftr>`

	styles := `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Nyala" w:eastAsia="Calibri"/><w:color w:val="` + hexInk + `"/><w:sz w:val="20"/><w:szCs w:val="20"/><w:lang w:val="en-GB"/></w:rPr></w:rPrDefault>
<w:pPrDefault><w:pPr><w:spacing w:after="80" w:line="264" w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>
<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:before="120" w:after="60"/></w:pPr><w:rPr><w:rFonts w:ascii="Georgia" w:hAnsi="Georgia"/><w:b/><w:color w:val="` + hexInk + `"/><w:sz w:val="40"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:basedOn w:val="Normal"/><w:rPr><w:color w:val="` + hexMuted + `"/><w:sz w:val="20"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="240" w:after="80"/><w:pBdr><w:bottom w:val="single" w:sz="4" w:space="2" w:color="` + hexLine + `"/></w:pBdr><w:outlineLvl w:val="1"/></w:pPr><w:rPr><w:rFonts w:ascii="Georgia" w:hAnsi="Georgia"/><w:b/><w:color w:val="` + hexGreen + `"/><w:sz w:val="26"/></w:rPr></w:style>
<w:style w:type="paragraph" w:styleId="Label"><w:name w:val="Label"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="0"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Cell"><w:name w:val="Table cell"/><w:basedOn w:val="Normal"/><w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto"/></w:pPr></w:style>
<w:style w:type="table" w:styleId="SerkTable"><w:name w:val="SERK table"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:color="` + hexLine + `"/><w:bottom w:val="single" w:sz="4" w:color="` + hexLine + `"/><w:insideH w:val="single" w:sz="4" w:color="` + hexLine + `"/></w:tblBorders><w:tblCellMar><w:top w:w="50" w:type="dxa"/><w:left w:w="90" w:type="dxa"/><w:bottom w:w="50" w:type="dxa"/><w:right w:w="90" w:type="dxa"/></w:tblCellMar></w:tblPr></w:style>
</w:styles>`

	files := [][2]string{
		{"[Content_Types].xml", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>
<Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>`},
		{"_rels/.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>`},
		{"word/_rels/document.xml.rels", `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
<Relationship Id="rIdHeader" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header1.xml"/>
<Relationship Id="rIdFooter" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer1.xml"/></Relationships>`},
		{"word/document.xml", document},
		{"word/styles.xml", styles},
		{"word/header1.xml", header},
		{"word/footer1.xml", footer},
		{"docProps/core.xml", coreProps(d)},
		{"docProps/app.xml", appProps(d)},
	}
	return zipFiles(w, files)
}

func wmPara(d Doc) string {
	if d.Watermark == "" {
		return ""
	}
	return `<w:p><w:pPr><w:jc w:val="right"/></w:pPr>` + run(d.Watermark, false, 14, hexMuted) + `</w:p>`
}
