package httpapi

// Planning routes (migration 0027, ADR 0013): schedule versions computed by
// the critical path method, baseline approval, progress reports and earned
// value. Thin adapters over the kernel; the database verifies every date.

import (
	"context"
	"net/http"
	"time"

	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/pkg/auth"
)

func (s *Server) registerSchedule() {
	m := s.mux
	k := func() *kernel.Service { return s.cfg.Kernel }
	decide := func(fn func(context.Context, auth.Principal, string, decisionBody) (any, error)) http.Handler {
		return s.authed(s.p2pDecision(fn))
	}
	m.Handle("POST /v1/projects/{id}/schedules", s.authed(s.createSchedule))
	m.Handle("POST /v1/schedules/{id}/submit", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().SubmitSchedule(ctx, p, id)
	}))
	m.Handle("POST /v1/schedules/{id}/approve", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().DecideSchedule(ctx, p, id, true, "")
	}))
	m.Handle("POST /v1/schedules/{id}/reject", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().DecideSchedule(ctx, p, id, false, b.Reason)
	}))
	m.Handle("POST /v1/projects/{id}/progress", s.authed(s.recordProgress))
	m.Handle("POST /v1/progress/{id}/approve", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().DecideProgress(ctx, p, id, true, "")
	}))
	m.Handle("POST /v1/progress/{id}/reject", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().DecideProgress(ctx, p, id, false, b.Reason)
	}))
	m.Handle("GET /v1/projects/{id}/evm", s.authed(s.projectEVM))
}

func (s *Server) createSchedule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b struct {
		kernel.ScheduleInput
		StartDate      day   `json:"start_date"`
		Holidays       []day `json:"holidays"`
		RequiredFinish *day  `json:"required_finish"`
	}
	if !decode(w, r, &b) {
		return
	}
	for _, a := range b.Activities {
		if a.CostCodeID != "" && !canonicalUUID(a.CostCodeID) {
			writeErr(w, http.StatusUnprocessableEntity, "validation", "cost_code_id must be a canonical UUID")
			return
		}
	}
	in := b.ScheduleInput
	in.ProjectID = id
	in.StartDate = b.StartDate.Time
	for _, h := range b.Holidays {
		in.Holidays = append(in.Holidays, h.Time)
	}
	if b.RequiredFinish != nil {
		t := b.RequiredFinish.Time
		in.RequiredFinish = &t
	}
	v, err := s.cfg.Kernel.CreateSchedule(r.Context(), principalFrom(r.Context()), in)
	s.created(w, v, err)
}

func (s *Server) recordProgress(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b struct {
		StatusDate day `json:"status_date"`
		Lines      []struct {
			ActivityCode    string          `json:"activity_code"`
			PercentComplete decimal.Decimal `json:"percent_complete"`
			ActualStart     *day            `json:"actual_start"`
			ActualFinish    *day            `json:"actual_finish"`
		} `json:"lines"`
	}
	if !decode(w, r, &b) {
		return
	}
	lines := make([]kernel.ProgressLine, 0, len(b.Lines))
	for _, l := range b.Lines {
		pl := kernel.ProgressLine{ActivityCode: l.ActivityCode, PercentComplete: l.PercentComplete}
		if l.ActualStart != nil {
			t := l.ActualStart.Time
			pl.ActualStart = &t
		}
		if l.ActualFinish != nil {
			t := l.ActualFinish.Time
			pl.ActualFinish = &t
		}
		lines = append(lines, pl)
	}
	p, err := s.cfg.Kernel.RecordProgress(r.Context(), principalFrom(r.Context()), id, b.StatusDate.Time, lines)
	s.created(w, p, err)
}

func (s *Server) projectEVM(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	at := time.Now().UTC()
	if q := r.URL.Query().Get("status_date"); q != "" {
		t, err := time.Parse("2006-01-02", q)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, "validation", "status_date is YYYY-MM-DD")
			return
		}
		at = t
	}
	out, err := s.cfg.Kernel.ScheduleEVM(r.Context(), principalFrom(r.Context()), id, at)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
