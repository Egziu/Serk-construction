package export

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"strings"
)

// A minimal, dependency-free PDF 1.4 writer: A4, the standard Helvetica and
// Times fonts in WinAnsi encoding, letterhead band, wrapped tables with
// repeated headers, and "page n of N" footers. Characters outside WinAnsi
// (for example Ethiopic) print as "?"; the DOCX and XLSX exports keep them.

// Brand colours (RGB 0..1).
var (
	pdfGreen = [3]float64{0.106, 0.290, 0.200} // #1b4a33
	pdfInk   = [3]float64{0.063, 0.161, 0.114} // #10291d
	pdfCream = [3]float64{0.953, 0.925, 0.851} // #f3ecd9
	pdfPaper = [3]float64{0.984, 0.969, 0.925} // #fbf7ec
	pdfStrip = [3]float64{0.937, 0.902, 0.812} // #efe6cf
	pdfMuted = [3]float64{0.290, 0.353, 0.306} // #4a5a4e
	pdfBrass = [3]float64{0.541, 0.392, 0.125} // #8a6420
	pdfLine  = [3]float64{0.847, 0.804, 0.690} // #d8cdb0
)

type pdfFont int

const (
	fReg   pdfFont = iota // Helvetica
	fBold                 // Helvetica-Bold
	fTitle                // Times-Bold
)

// Advance widths (1/1000 em) of WinAnsi 32..126 (Adobe core font metrics).
var helvW = [95]int{278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
	278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944,
	667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556,
	500, 722, 500, 500, 500, 334, 260, 334, 584}
var helvBW = [95]int{278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556,
	333, 333, 584, 584, 584, 611, 975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944,
	667, 667, 611, 333, 278, 333, 584, 556, 333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611, 611, 611, 389, 556, 333, 611,
	556, 778, 556, 556, 500, 389, 280, 389, 584}
var timesBW = [95]int{250, 333, 555, 500, 500, 1000, 833, 278, 333, 333, 500, 570, 250, 333, 250, 278, 500, 500, 500, 500, 500, 500, 500, 500, 500, 500,
	333, 333, 570, 570, 570, 500, 930, 722, 667, 722, 722, 667, 611, 778, 778, 389, 500, 778, 667, 944, 722, 778, 611, 778, 722, 556, 667, 722, 722, 1000,
	722, 722, 667, 333, 278, 333, 581, 500, 333, 500, 556, 444, 556, 444, 333, 500, 556, 278, 333, 556, 278, 833, 556, 500, 556, 556, 444, 389, 333, 556,
	500, 722, 500, 500, 444, 394, 220, 394, 520}

// winAnsi maps a rune to its WinAnsi byte ('?' when unrepresentable).
func winAnsi(r rune) byte {
	switch {
	case r >= 32 && r <= 126:
		return byte(r)
	case r >= 0xA0 && r <= 0xFF:
		return byte(r)
	}
	switch r {
	case '€':
		return 0x80
	case '‚':
		return 0x82
	case '„':
		return 0x84
	case '…':
		return 0x85
	case '‘':
		return 0x91
	case '’':
		return 0x92
	case '“':
		return 0x93
	case '”':
		return 0x94
	case '•':
		return 0x95
	case '–':
		return 0x96
	case '—':
		return 0x97
	case '™':
		return 0x99
	case '\t', '\n', '\r':
		return ' '
	}
	return '?'
}

func charW(f pdfFont, b byte) int {
	var t *[95]int
	switch f {
	case fBold:
		t = &helvBW
	case fTitle:
		t = &timesBW
	default:
		t = &helvW
	}
	if b >= 32 && b <= 126 {
		return t[b-32]
	}
	switch b {
	case 0x96:
		return 556
	case 0x97:
		return 1000
	case 0x95:
		return 350
	case 0x85:
		return 1000
	case 0xB7:
		return 278
	}
	return 556
}

func textWidth(f pdfFont, size float64, s string) float64 {
	w := 0
	for _, r := range s {
		if isEthiopic(r) {
			w += ethiopic().width(r)
			continue
		}
		w += charW(f, winAnsi(r))
	}
	return float64(w) * size / 1000
}

// wrap breaks s into lines no wider than width.
func wrap(f pdfFont, size, width float64, s string) []string {
	if s == "" {
		return []string{""}
	}
	var lines []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		cur := ""
		for _, w := range words {
			for textWidth(f, size, w) > width && len([]rune(w)) > 1 {
				// Break an over-long word.
				rs := []rune(w)
				n := len(rs) - 1
				for n > 1 && textWidth(f, size, string(rs[:n])) > width {
					n--
				}
				if cur != "" {
					lines = append(lines, cur)
					cur = ""
				}
				lines = append(lines, string(rs[:n]))
				w = string(rs[n:])
			}
			try := w
			if cur != "" {
				try = cur + " " + w
			}
			if textWidth(f, size, try) <= width || cur == "" {
				cur = try
			} else {
				lines = append(lines, cur)
				cur = w
			}
		}
		lines = append(lines, cur)
	}
	return lines
}

func pdfStr(s string) string {
	var b strings.Builder
	b.WriteByte('(')
	for _, r := range s {
		c := winAnsi(r)
		switch c {
		case '(', ')', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			if c < 32 || c > 126 {
				fmt.Fprintf(&b, "\\%03o", c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte(')')
	return b.String()
}

type pdfPage struct{ ops bytes.Buffer }

type pdfLayout struct {
	eth        map[uint16]rune // Ethiopic glyphs used (embedded font F4)
	d          Doc
	w, h       float64
	margin     float64
	y          float64
	pages      []*pdfPage
	cur        *pdfPage
	contentTop float64
}

func (l *pdfLayout) color(c [3]float64, stroke bool) {
	op := "rg"
	if stroke {
		op = "RG"
	}
	fmt.Fprintf(&l.cur.ops, "%.3f %.3f %.3f %s\n", c[0], c[1], c[2], op)
}

func (l *pdfLayout) rect(x, y, w, h float64, c [3]float64) {
	l.color(c, false)
	fmt.Fprintf(&l.cur.ops, "%.2f %.2f %.2f %.2f re f\n", x, y, w, h)
}

func (l *pdfLayout) line(x1, y1, x2, y2 float64, c [3]float64, width float64) {
	l.color(c, true)
	fmt.Fprintf(&l.cur.ops, "%.2f w %.2f %.2f m %.2f %.2f l S\n", width, x1, y1, x2, y2)
}

func (l *pdfLayout) text(f pdfFont, size, x, y float64, c [3]float64, s string) {
	l.color(c, false)
	fmt.Fprintf(&l.cur.ops, "BT %.2f %.2f Td ", x, y)
	// Runs: standard-font text, or Ethiopic glyphs from the embedded font.
	rs := []rune(s)
	for i := 0; i < len(rs); {
		j := i
		eth := isEthiopic(rs[i])
		for j < len(rs) && isEthiopic(rs[j]) == eth {
			j++
		}
		if eth {
			if l.eth == nil {
				l.eth = map[uint16]rune{}
			}
			var hex strings.Builder
			for _, r := range rs[i:j] {
				g := ethiopic().cmap[r]
				l.eth[g] = r
				fmt.Fprintf(&hex, "%04X", g)
			}
			fmt.Fprintf(&l.cur.ops, "/F4 %.2f Tf <%s> Tj ", size, hex.String())
		} else {
			fmt.Fprintf(&l.cur.ops, "/F%d %.2f Tf %s Tj ", int(f)+1, size, pdfStr(string(rs[i:j])))
		}
		i = j
	}
	l.cur.ops.WriteString("ET\n")
}

func (l *pdfLayout) newPage() {
	l.cur = &pdfPage{}
	l.pages = append(l.pages, l.cur)
	// Letterhead band.
	l.rect(0, l.h-54, l.w, 54, pdfGreen)
	l.rect(0, l.h-57, l.w, 3, pdfBrass)
	// Mark: a small house-and-door glyph.
	x0, y0 := l.margin, l.h-42
	l.color(pdfCream, false)
	fmt.Fprintf(&l.cur.ops, "%.2f %.2f m %.2f %.2f l %.2f %.2f l %.2f %.2f l %.2f %.2f l %.2f %.2f l %.2f %.2f l %.2f %.2f l %.2f %.2f l %.2f %.2f l h f\n",
		x0, y0, x0, y0+18, x0+12, y0+24, x0+24, y0+18, x0+24, y0, x0+19, y0, x0+19, y0+15, x0+12, y0+18.5, x0+5, y0+15, x0+5, y0)
	l.rect(x0+8, y0, 8, 12, pdfBrass)
	company := l.d.Company
	maxW := l.w - 2*l.margin - 34 - textWidth(fBold, 8, strings.ToUpper(l.d.Brand)) - 20
	for textWidth(fTitle, 15, company) > maxW && len([]rune(company)) > 4 {
		rs := []rune(company)
		company = string(rs[:len(rs)-2]) + "…"
	}
	l.text(fTitle, 15, x0+34, l.h-30, pdfCream, company)
	l.text(fReg, 8, x0+34, l.h-44, pdfStrip, l.d.Title)
	bw := textWidth(fBold, 8, strings.ToUpper(l.d.Brand))
	l.text(fBold, 8, l.w-l.margin-bw, l.h-33, pdfStrip, strings.ToUpper(l.d.Brand))
	l.y = l.h - 57 - 22
}

func (l *pdfLayout) need(h float64) bool {
	if l.y-h < l.margin+24 {
		l.newPage()
		return true
	}
	return false
}

func writePDF(w io.Writer, d Doc) error {
	wide := 0
	for _, s := range d.Sections {
		if s.Table != nil && len(s.Table.Columns) > wide {
			wide = len(s.Table.Columns)
		}
	}
	l := &pdfLayout{d: d, w: 595.28, h: 841.89, margin: 40}
	if wide > 6 {
		l.w, l.h = 841.89, 595.28
	}
	l.newPage()
	inner := l.w - 2*l.margin

	// Title block.
	for _, ln := range wrap(fTitle, 20, inner, d.Title) {
		l.need(26)
		l.text(fTitle, 20, l.margin, l.y-18, pdfInk, ln)
		l.y -= 25
	}
	if d.Subtitle != "" {
		for _, ln := range wrap(fReg, 10, inner, d.Subtitle) {
			l.text(fReg, 10, l.margin, l.y-10, pdfMuted, ln)
			l.y -= 14
		}
	}
	l.y -= 6
	l.kvBlock(d.Meta, inner)

	for _, s := range d.Sections {
		l.y -= 8
		if s.Title != "" {
			l.need(40)
			l.text(fTitle, 13, l.margin, l.y-12, pdfGreen, s.Title)
			l.line(l.margin, l.y-17, l.margin+inner, l.y-17, pdfLine, 0.6)
			l.y -= 26
		}
		l.kvBlock(s.Meta, inner)
		if s.Table != nil {
			l.table(s.Table, inner)
		}
	}
	return l.emit(w)
}

func (l *pdfLayout) kvBlock(kvs []KV, inner float64) {
	if len(kvs) == 0 {
		return
	}
	labelW := 0.0
	for _, kv := range kvs {
		if w := textWidth(fBold, 8.5, kv.K); w > labelW {
			labelW = w
		}
	}
	if labelW > inner*0.35 {
		labelW = inner * 0.35
	}
	labelW += 14
	for _, kv := range kvs {
		lab := wrap(fBold, 8.5, labelW-14, kv.K)
		val := wrap(fReg, 9.5, inner-labelW, kv.V)
		n := len(lab)
		if len(val) > n {
			n = len(val)
		}
		h := float64(n)*12.5 + 3
		l.need(h)
		for i, s := range lab {
			l.text(fBold, 8.5, l.margin, l.y-10-float64(i)*12.5, pdfMuted, s)
		}
		for i, s := range val {
			l.text(fReg, 9.5, l.margin+labelW, l.y-10-float64(i)*12.5, pdfInk, s)
		}
		l.y -= h
	}
	l.y -= 4
}

func (l *pdfLayout) table(t *Table, inner float64) {
	const size, hsize, pad, lh = 8.0, 7.5, 5.0, 10.5
	n := len(t.Columns)
	if n == 0 {
		return
	}
	// Natural widths, capped, then scaled to the page.
	nat := make([]float64, n)
	for i, c := range t.Columns {
		nat[i] = textWidth(fBold, hsize, strings.ToUpper(c.Label))
		if nat[i] > 110 {
			nat[i] = 110
		}
	}
	for _, r := range t.Rows {
		for i := range r {
			if wv := textWidth(fReg, size, r[i].Text); wv > nat[i] {
				nat[i] = wv
			}
		}
	}
	total := 0.0
	for i := range nat {
		if nat[i] > 220 {
			nat[i] = 220
		}
		if nat[i] < 28 {
			nat[i] = 28
		}
		nat[i] += 2 * pad
		total += nat[i]
	}
	widths := make([]float64, n)
	for i := range nat {
		widths[i] = nat[i] * inner / total
	}
	header := func() {
		hl := make([][]string, n)
		rows := 1
		for i, c := range t.Columns {
			hl[i] = wrap(fBold, hsize, widths[i]-2*pad, strings.ToUpper(c.Label))
			if len(hl[i]) > rows {
				rows = len(hl[i])
			}
		}
		h := float64(rows)*lh + 2*pad
		l.need(h + lh + 2*pad)
		l.rect(l.margin, l.y-h, inner, h, pdfGreen)
		x := l.margin
		for i, c := range t.Columns {
			for j, s := range hl[i] {
				tx := x + pad
				if c.Numeric {
					tx = x + widths[i] - pad - textWidth(fBold, hsize, s)
				}
				l.text(fBold, hsize, tx, l.y-pad-8-float64(j)*lh, pdfCream, s)
			}
			x += widths[i]
		}
		l.y -= h
	}
	header()
	for ri, r := range t.Rows {
		cl := make([][]string, n)
		rows := 1
		for i := range r {
			cl[i] = wrap(fReg, size, widths[i]-2*pad, r[i].Text)
			if len(cl[i]) > rows {
				rows = len(cl[i])
			}
		}
		h := float64(rows)*lh + 2*pad - 2
		if l.need(h) {
			header()
		}
		if ri%2 == 1 {
			l.rect(l.margin, l.y-h, inner, h, pdfPaper)
		}
		x := l.margin
		for i, c := range t.Columns {
			for j, s := range cl[i] {
				tx := x + pad
				if c.Numeric {
					tx = x + widths[i] - pad - textWidth(fReg, size, s)
				}
				l.text(fReg, size, tx, l.y-pad-7-float64(j)*lh, pdfInk, s)
			}
			x += widths[i]
		}
		l.line(l.margin, l.y-h, l.margin+inner, l.y-h, pdfLine, 0.4)
		l.y -= h
	}
	if len(t.Rows) == 0 {
		l.need(18)
		l.text(fReg, size, l.margin+pad, l.y-12, pdfMuted, "No rows.")
		l.y -= 18
	}
	l.y -= 10
}

func (l *pdfLayout) emit(w io.Writer) error {
	// Footers, now that the page count is known.
	total := len(l.pages)
	foot := footerLine(l.d)
	for i, p := range l.pages {
		l.cur = p
		l.line(l.margin, l.margin+6, l.w-l.margin, l.margin+6, pdfLine, 0.5)
		l.text(fReg, 7.5, l.margin, l.margin-6, pdfMuted, foot)
		pg := fmt.Sprintf("Page %d of %d", i+1, total)
		l.text(fBold, 7.5, l.w-l.margin-textWidth(fBold, 7.5, pg), l.margin-6, pdfMuted, pg)
		if l.d.Watermark != "" {
			// Faint diagonal watermark: a copy carries its recipient.
			wm := l.d.Watermark
			size := 26.0
			tw := textWidth(fBold, size, wm)
			fmt.Fprintf(&l.cur.ops, "q 0.72 0.70 0.62 rg BT /F2 %.2f Tf 0.7071 0.7071 -0.7071 0.7071 %.2f %.2f Tm %s Tj ET Q\n", size, l.w/2-tw/2*0.7071, l.h/2-tw/2*0.7071, pdfStr(wm))
		}
	}

	var out bytes.Buffer
	var offsets []int
	obj := func(body string) int {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", len(offsets), body)
		return len(offsets)
	}
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	// 1 catalog, 2 pages, 3-5 fonts, then per page: content + page.
	obj("<< /Type /Catalog /Pages 2 0 R >>")
	offsets = append(offsets, 0) // placeholder for Pages (object 2), written last
	pagesIdx := len(offsets) - 1
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
	obj("<< /Type /Font /Subtype /Type1 /BaseFont /Times-Bold /Encoding /WinAnsiEncoding >>")
	fonts := "/F1 3 0 R /F2 4 0 R /F3 5 0 R"
	if len(l.eth) > 0 {
		id, err := l.embedEthiopic(&out, &offsets, obj)
		if err != nil {
			return err
		}
		fonts += fmt.Sprintf(" /F4 %d 0 R", id)
	}
	var kids []string
	for _, p := range l.pages {
		var z bytes.Buffer
		zw := zlib.NewWriter(&z)
		if _, err := zw.Write(p.ops.Bytes()); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
		offsets = append(offsets, out.Len())
		cid := len(offsets)
		fmt.Fprintf(&out, "%d 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n", cid, z.Len())
		out.Write(z.Bytes())
		out.WriteString("\nendstream\nendobj\n")
		pid := obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << %s >> >> /Contents %d 0 R >>",
			l.w, l.h, fonts, cid))
		kids = append(kids, fmt.Sprintf("%d 0 R", pid))
	}
	offsets[pagesIdx] = out.Len()
	fmt.Fprintf(&out, "2 0 obj\n<< /Type /Pages /Kids [%s] /Count %d >>\nendobj\n", strings.Join(kids, " "), len(kids))
	info := obj(fmt.Sprintf("<< /Title %s /Author %s /Creator %s /Producer %s /CreationDate (D:%s) >>",
		pdfStr(l.d.Title), pdfStr(l.d.Company), pdfStr(l.d.Brand), pdfStr(l.d.Brand), l.d.GeneratedAt.UTC().Format("20060102150405Z")))
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, o := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, info, xref)
	_, err := w.Write(out.Bytes())
	return err
}

// embedEthiopic writes the Type0 font (with its CID font, descriptor, font
// program and ToUnicode map) and returns the Type0 object number.
func (l *pdfLayout) embedEthiopic(out *bytes.Buffer, offsets *[]int, obj func(string) int) (int, error) {
	stream := func(dict string, data []byte) (int, error) {
		var z bytes.Buffer
		zw := zlib.NewWriter(&z)
		if _, err := zw.Write(data); err != nil {
			return 0, err
		}
		if err := zw.Close(); err != nil {
			return 0, err
		}
		*offsets = append(*offsets, out.Len())
		id := len(*offsets)
		fmt.Fprintf(out, "%d 0 obj\n<< /Length %d /Filter /FlateDecode %s >>\nstream\n", id, z.Len(), dict)
		out.Write(z.Bytes())
		out.WriteString("\nendstream\nendobj\n")
		return id, nil
	}
	ff, err := stream(fmt.Sprintf("/Length1 %d", len(ethiopicTTF)), ethiopicTTF)
	if err != nil {
		return 0, err
	}
	tu, err := stream("", []byte(toUnicodeCMap(l.eth)))
	if err != nil {
		return 0, err
	}
	desc := obj(fmt.Sprintf("<< /Type /FontDescriptor /FontName /NotoSansEthiopic /Flags 4 /FontBBox [-600 -400 1600 1100] /ItalicAngle 0 "+
		"/Ascent 1069 /Descent -293 /CapHeight 714 /StemV 80 /FontFile2 %d 0 R >>", ff))
	var w strings.Builder
	f := ethiopic()
	for _, g := range sortedGIDs(l.eth) {
		fmt.Fprintf(&w, "%d [%d] ", g, f.width(l.eth[g]))
	}
	cid := obj(fmt.Sprintf("<< /Type /Font /Subtype /CIDFontType2 /BaseFont /NotoSansEthiopic /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> "+
		"/FontDescriptor %d 0 R /CIDToGIDMap /Identity /DW 1000 /W [%s] >>", desc, w.String()))
	return obj(fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /NotoSansEthiopic /Encoding /Identity-H /DescendantFonts [%d 0 R] /ToUnicode %d 0 R >>", cid, tu)), nil
}
