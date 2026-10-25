package export

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// Ethiopic script in PDFs. The standard PDF fonts have no Ge'ez glyphs, so
// when a document contains Ethiopic text the PDF embeds Noto Sans Ethiopic
// (SIL OFL 1.1, fonts/OFL-NotoSansEthiopic.txt) as a CID font with
// Identity-H encoding and a ToUnicode map (text stays searchable and
// copyable). Documents without Ethiopic text do not carry the font.

//go:embed fonts/NotoSansEthiopic-Regular.ttf
var ethiopicTTF []byte

type ttFont struct {
	unitsPerEm int
	cmap       map[rune]uint16
	advance    []uint16
}

var (
	ethOnce sync.Once
	ethFont *ttFont
)

func ethiopic() *ttFont {
	ethOnce.Do(func() {
		f, err := parseTTF(ethiopicTTF)
		if err == nil {
			ethFont = f
		}
	})
	return ethFont
}

// isEthiopic reports whether r is printed with the embedded font.
func isEthiopic(r rune) bool {
	if !((r >= 0x1200 && r <= 0x139F) || (r >= 0x2D80 && r <= 0x2DDF) || (r >= 0xAB00 && r <= 0xAB2F) || (r >= 0x1E7E0 && r <= 0x1E7FF)) {
		return false
	}
	f := ethiopic()
	if f == nil {
		return false
	}
	_, ok := f.cmap[r]
	return ok
}

// width in 1/1000 em.
func (f *ttFont) width(r rune) int {
	g := f.cmap[r]
	if int(g) >= len(f.advance) {
		if len(f.advance) == 0 {
			return 1000
		}
		g = uint16(len(f.advance) - 1)
	}
	return int(f.advance[g]) * 1000 / f.unitsPerEm
}

func parseTTF(b []byte) (*ttFont, error) {
	if len(b) < 12 {
		return nil, errors.New("ttf: short")
	}
	n := int(binary.BigEndian.Uint16(b[4:]))
	tables := map[string][]byte{}
	for i := 0; i < n; i++ {
		e := 12 + 16*i
		if e+16 > len(b) {
			return nil, errors.New("ttf: directory")
		}
		tag := string(b[e : e+4])
		off, ln := int(binary.BigEndian.Uint32(b[e+8:])), int(binary.BigEndian.Uint32(b[e+12:]))
		if off < 0 || ln < 0 || off+ln > len(b) {
			return nil, fmt.Errorf("ttf: table %s out of range", tag)
		}
		tables[tag] = b[off : off+ln]
	}
	head, hhea, hmtx, cmap := tables["head"], tables["hhea"], tables["hmtx"], tables["cmap"]
	if len(head) < 54 || len(hhea) < 36 || cmap == nil {
		return nil, errors.New("ttf: missing tables")
	}
	f := &ttFont{unitsPerEm: int(binary.BigEndian.Uint16(head[18:])), cmap: map[rune]uint16{}}
	if f.unitsPerEm == 0 {
		return nil, errors.New("ttf: unitsPerEm")
	}
	nh := int(binary.BigEndian.Uint16(hhea[34:]))
	for i := 0; i < nh && 4*i+2 <= len(hmtx); i++ {
		f.advance = append(f.advance, binary.BigEndian.Uint16(hmtx[4*i:]))
	}
	// cmap: a Windows Unicode BMP (3,1) format-4 subtable.
	nsub := int(binary.BigEndian.Uint16(cmap[2:]))
	for i := 0; i < nsub; i++ {
		e := 4 + 8*i
		if e+8 > len(cmap) {
			break
		}
		pid, eid := binary.BigEndian.Uint16(cmap[e:]), binary.BigEndian.Uint16(cmap[e+2:])
		off := int(binary.BigEndian.Uint32(cmap[e+4:]))
		if pid != 3 || eid != 1 || off+14 > len(cmap) || binary.BigEndian.Uint16(cmap[off:]) != 4 {
			continue
		}
		t := cmap[off:]
		segX2 := int(binary.BigEndian.Uint16(t[6:]))
		ends, starts, deltas, ros := 14, 14+segX2+2, 14+2*segX2+2, 14+3*segX2+2
		if ros+segX2 > len(t) {
			return nil, errors.New("ttf: cmap")
		}
		for s := 0; s < segX2/2; s++ {
			end := int(binary.BigEndian.Uint16(t[ends+2*s:]))
			start := int(binary.BigEndian.Uint16(t[starts+2*s:]))
			delta := int(int16(binary.BigEndian.Uint16(t[deltas+2*s:])))
			ro := int(binary.BigEndian.Uint16(t[ros+2*s:]))
			for c := start; c <= end && c != 0xFFFF; c++ {
				var g int
				if ro == 0 {
					g = (c + delta) & 0xFFFF
				} else {
					p := ros + 2*s + ro + 2*(c-start)
					if p+2 > len(t) {
						continue
					}
					g = int(binary.BigEndian.Uint16(t[p:]))
					if g != 0 {
						g = (g + delta) & 0xFFFF
					}
				}
				if g != 0 {
					f.cmap[rune(c)] = uint16(g)
				}
			}
		}
		break
	}
	if len(f.cmap) == 0 {
		return nil, errors.New("ttf: no usable cmap")
	}
	return f, nil
}

// toUnicodeCMap maps the glyphs used back to their characters.
func toUnicodeCMap(used map[uint16]rune) string {
	var b strings.Builder
	b.WriteString("/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n" +
		"/CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n")
	gids := sortedGIDs(used)
	for i := 0; i < len(gids); i += 100 {
		j := min(i+100, len(gids))
		fmt.Fprintf(&b, "%d beginbfchar\n", j-i)
		for _, g := range gids[i:j] {
			r := used[g]
			if r > 0xFFFF {
				r -= 0x10000
				fmt.Fprintf(&b, "<%04X> <%04X%04X>\n", g, 0xD800+(r>>10), 0xDC00+(r&0x3FF))
			} else {
				fmt.Fprintf(&b, "<%04X> <%04X>\n", g, r)
			}
		}
		b.WriteString("endbfchar\n")
	}
	b.WriteString("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n")
	return b.String()
}

func sortedGIDs(used map[uint16]rune) []uint16 {
	gids := make([]uint16, 0, len(used))
	for g := range used {
		gids = append(gids, g)
	}
	for i := 1; i < len(gids); i++ {
		for j := i; j > 0 && gids[j] < gids[j-1]; j-- {
			gids[j], gids[j-1] = gids[j-1], gids[j]
		}
	}
	return gids
}
