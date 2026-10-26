package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/serk-group/serk-construction/internal/export"
	"github.com/serk-group/serk-construction/internal/kernel"
)

// Exports (PDF, DOCX, XLSX) of any read the console shows.
//
//	GET /v1/export?src=<GET path under /v1/>&format=pdf|docx|xlsx&title=<text>
//
// The export re-issues src as an internal GET carrying the caller's own
// bearer token, so it passes exactly the same authentication, revocation,
// rate limits, permission, project scope and row-level security as the
// screen: an export can never contain more than the person may read. Only
// reads are exportable; the document is rendered from that response and
// stamped with the company, the person and the time.

const maxExportSource = 16 << 20

// exportable lists the read routes that may be exported (prefix match).
var exportable = []string{"/v1/p2p/", "/v1/journals", "/v1/projects/", "/v1/entities/", "/v1/contracts/", "/v1/reports/",
	"/v1/workflow/instances", "/v1/workflow/tasks", "/v1/site/devices"}

type bufWriter struct {
	h    http.Header
	code int
	buf  bytes.Buffer
}

func (b *bufWriter) Header() http.Header { return b.h }
func (b *bufWriter) WriteHeader(c int) {
	if b.code == 0 {
		b.code = c
	}
}
func (b *bufWriter) Write(p []byte) (int, error) {
	if b.code == 0 {
		b.code = http.StatusOK
	}
	if b.buf.Len()+len(p) > maxExportSource {
		return 0, http.ErrContentLength
	}
	return b.buf.Write(p)
}

// internalGET runs a read through the full handler chain as the caller.
func (s *Server) internalGET(r *http.Request, path string) (int, []byte) {
	sub, err := http.NewRequestWithContext(r.Context(), http.MethodGet, path, nil)
	if err != nil {
		return http.StatusBadRequest, nil
	}
	sub.Header.Set("Authorization", r.Header.Get("Authorization"))
	sub.RemoteAddr = r.RemoteAddr
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		sub.Header.Set("X-Forwarded-For", xff)
	}
	w := &bufWriter{h: http.Header{}}
	s.mux.ServeHTTP(w, sub)
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.code, w.buf.Bytes()
}

func cleanTitle(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if r := []rune(s); len(r) > 120 {
		s = string(r[:120])
	}
	return s
}

func (s *Server) registerExport() {
	s.mux.Handle("GET /v1/export", s.authed(s.exportDoc))
}

func (s *Server) exportDoc(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := export.Format(q.Get("format"))
	if f != export.PDF && f != export.DOCX && f != export.XLSX {
		writeErr(w, http.StatusUnprocessableEntity, "validation", export.ErrFormat.Error())
		return
	}
	src := q.Get("src")
	u, err := url.Parse(src)
	ok := err == nil && u.Scheme == "" && u.Host == "" && u.User == nil && len(src) <= 2048 && !strings.Contains(u.Path, "..") &&
		!strings.HasPrefix(u.Path, "/v1/export")
	if ok {
		ok = false
		for _, p := range exportable {
			if strings.HasPrefix(u.Path, p) {
				ok = true
				break
			}
		}
	}
	if !ok {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "src must be an exportable read under /v1/")
		return
	}
	code, body := s.internalGET(r, u.RequestURI())
	if code != http.StatusOK {
		// Pass the read's own refusal through unchanged.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(code)
		_, _ = w.Write(body)
		return
	}
	title := cleanTitle(q.Get("title"))
	if title == "" {
		title = "Export"
	}
	d, err := export.FromJSON(title, body)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the data to export")
		return
	}
	p := principalFrom(r.Context())
	// Anti-exfiltration: the person's daily export budget (tenant setting).
	if s.cfg.Kernel != nil {
		if err := s.cfg.Kernel.RecordExport(r.Context(), p, u.Path, int64(len(body))); err != nil {
			if errors.Is(err, kernel.ErrExportBudget) {
				s.cfg.Logger.Warn("security", "event", "export_budget_exceeded", "tenant", p.TenantID, "sub", p.UserID)
				w.Header().Set("Retry-After", "3600")
				writeErr(w, http.StatusTooManyRequests, "export_budget", "daily export limit reached; security has been notified")
				return
			}
			s.fail(w, err)
			return
		}
	}
	d.Company, d.Brand = s.companyName(r, q.Get("entity")), s.cfg.Brand
	d.Watermark = "Confidential · prepared for " + p.UserID
	d.Subtitle = cleanTitle(q.Get("subtitle"))
	d.GeneratedBy, d.GeneratedAt = p.UserID, time.Now()
	var out bytes.Buffer
	if err := export.Write(&out, f, d); err != nil {
		s.cfg.Logger.Error("export", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not render the export")
		return
	}
	s.cfg.Logger.Info("audit", "event", "export", "tenant", p.TenantID, "sub", p.UserID, "src", u.Path, "format", string(f), "bytes", out.Len())
	h := w.Header()
	h.Set("Content-Type", f.ContentType())
	h.Set("Content-Disposition", `attachment; filename="`+export.FileName(d, f)+`"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out.Bytes())
}

// companyName is the letterhead: the configured company name, otherwise the
// legal entity the export concerns (or the person's first entity).
func (s *Server) companyName(r *http.Request, entity string) string {
	if s.cfg.CompanyName != "" {
		return s.cfg.CompanyName
	}
	if s.cfg.Kernel != nil {
		if st, err := s.cfg.Kernel.TenantSettings(r.Context(), principalFrom(r.Context())); err == nil && st.LetterheadName != "" {
			return st.LetterheadName
		}
	}
	code, body := s.internalGET(r, "/v1/p2p-reference")
	if code != http.StatusOK {
		return ""
	}
	var ref struct {
		Entities []struct{ ID, Name string } `json:"legal_entities"`
	}
	if json.Unmarshal(body, &ref) != nil || len(ref.Entities) == 0 {
		return ""
	}
	for _, e := range ref.Entities {
		if e.ID == entity {
			return e.Name
		}
	}
	return ref.Entities[0].Name
}
