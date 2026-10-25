package httpapi

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Financial reports (read-only; tenant-wide scope):
//
//	GET /v1/reports/trial-balance?entity=<uuid>&as_of=YYYY-MM-DD
//	GET /v1/reports/ap-aging?entity=<uuid>&as_of=YYYY-MM-DD
//	GET /v1/reports/ar-aging?entity=<uuid>&as_of=YYYY-MM-DD
func (s *Server) registerReports() {
	s.mux.Handle("GET /v1/reports/trial-balance", s.authed(s.reportTB))
	s.mux.Handle("GET /v1/reports/ap-aging", s.authed(s.reportAging(false)))
	s.mux.Handle("GET /v1/reports/ar-aging", s.authed(s.reportAging(true)))
}

func reportParams(w http.ResponseWriter, r *http.Request) (string, time.Time, bool) {
	entity := r.URL.Query().Get("entity")
	if _, err := uuid.Parse(entity); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "entity must be a legal entity id")
		return "", time.Time{}, false
	}
	asOf := time.Now().UTC()
	if v := r.URL.Query().Get("as_of"); v != "" {
		t, err := time.Parse("2006-01-02", v)
		if err != nil || t.Year() < 1900 || t.Year() > 2200 {
			writeErr(w, http.StatusUnprocessableEntity, "validation", "as_of must be a date (YYYY-MM-DD)")
			return "", time.Time{}, false
		}
		asOf = t
	}
	return entity, asOf, true
}

func (s *Server) reportTB(w http.ResponseWriter, r *http.Request) {
	entity, asOf, ok := reportParams(w, r)
	if !ok {
		return
	}
	out, err := s.cfg.Kernel.TrialBalanceReport(r.Context(), principalFrom(r.Context()), entity, asOf)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) reportAging(receivables bool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		entity, asOf, ok := reportParams(w, r)
		if !ok {
			return
		}
		p := principalFrom(r.Context())
		fn := s.cfg.Kernel.PayablesAging
		if receivables {
			fn = s.cfg.Kernel.ReceivablesAging
		}
		out, err := fn(r.Context(), p, entity, asOf)
		if err != nil {
			s.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}
