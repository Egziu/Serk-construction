package httpapi

// Site operations and offline capture (migration 0037, GATED-01, ADR 0017): field
// devices, site diaries and the offline sync endpoint. Thin adapters over the
// kernel; the database enforces every rule again.

import (
	"context"
	"net/http"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// Device credentials of /v1/sync travel in headers, never in the body that
// is logged or hashed.
const (
	headerDeviceID  = "X-Serk-Device-Id"
	headerDeviceKey = "X-Serk-Device-Key"
)

func (s *Server) registerSite() {
	m := s.mux
	k := func() *kernel.Service { return s.cfg.Kernel }
	decide := func(fn func(context.Context, auth.Principal, string, decisionBody) (any, error)) http.Handler {
		return s.authed(s.p2pDecision(fn))
	}
	m.Handle("POST /v1/site/devices", s.authed(s.registerDevice))
	m.Handle("GET /v1/site/devices", s.authed(s.listDevices))
	m.Handle("POST /v1/site/devices/{id}/revoke", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().RevokeDevice(ctx, p, id, b.Reason)
	}))
	m.Handle("POST /v1/site/diaries", s.authed(s.saveDiary))
	m.Handle("POST /v1/site/diaries/{id}/submit", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().SubmitDiary(ctx, p, id, 0)
	}))
	m.Handle("POST /v1/site/diaries/{id}/approve", decide(func(ctx context.Context, p auth.Principal, id string, _ decisionBody) (any, error) {
		return nil, k().DecideDiary(ctx, p, id, true, "")
	}))
	m.Handle("POST /v1/site/diaries/{id}/reject", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().DecideDiary(ctx, p, id, false, b.Reason)
	}))
	m.Handle("POST /v1/site/diaries/{id}/cancel", decide(func(ctx context.Context, p auth.Principal, id string, b decisionBody) (any, error) {
		return nil, k().CancelDiary(ctx, p, id, b.Reason)
	}))
	m.Handle("POST /v1/sync", s.authed(s.sync))
}

func (s *Server) registerDevice(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Label string `json:"label"`
	}
	if !decode(w, r, &b) {
		return
	}
	reg, err := s.cfg.Kernel.RegisterDevice(r.Context(), principalFrom(r.Context()), b.Label)
	if err != nil {
		s.fail(w, err)
		return
	}
	// The secret is shown once; never cache this response.
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, reg)
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Kernel.ListDevices(r.Context(), principalFrom(r.Context()))
	if err != nil {
		s.fail(w, err)
		return
	}
	if out == nil {
		out = []kernel.Device{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) saveDiary(w http.ResponseWriter, r *http.Request) {
	var b struct {
		kernel.DiaryInput
		DiaryDate day `json:"diary_date"`
	}
	if !decode(w, r, &b) {
		return
	}
	in := b.DiaryInput
	in.DiaryDate = b.DiaryDate.Time
	res, err := s.cfg.Kernel.SaveDiary(r.Context(), principalFrom(r.Context()), in)
	if err != nil {
		s.fail(w, err)
		return
	}
	status := http.StatusOK
	if res.Version == 1 {
		status = http.StatusCreated
	}
	writeJSON(w, status, res)
}

func (s *Server) sync(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Ops []kernel.SyncOp `json:"ops"`
	}
	if !decode(w, r, &b) {
		return
	}
	res, err := s.cfg.Kernel.Sync(r.Context(), principalFrom(r.Context()), r.Header.Get(headerDeviceID), r.Header.Get(headerDeviceKey), b.Ops)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": res})
}
