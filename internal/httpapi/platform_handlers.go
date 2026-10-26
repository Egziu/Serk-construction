package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// Platform routes (0038): company settings, notifications, automation rules,
// intelligence (risks, cash outlook, control review, assistant).
func (s *Server) registerPlatform() {
	m := s.mux
	m.Handle("GET /v1/tenant/settings", s.authed(s.getTenantSettings))
	m.Handle("PUT /v1/tenant/settings", s.authed(s.putTenantSettings))
	m.Handle("GET /v1/notifications", s.authed(s.listNotifications))
	m.Handle("POST /v1/notifications/{id}/read", s.authed(s.readNotification))
	m.Handle("GET /v1/automation/catalogue", s.authed(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"conditions": kernel.RuleCatalogue(),
			"actions": []string{"notify_role", "notify_user"}, "note": "Rules inform and escalate. They never approve, post, pay or release."})
	}))
	m.Handle("GET /v1/automation/rules", s.authed(s.listRules))
	m.Handle("POST /v1/automation/rules", s.authed(s.proposeRule))
	m.Handle("PUT /v1/automation/rules/{id}", s.authed(s.updateRule))
	m.Handle("POST /v1/automation/rules/{id}/activate", s.authed(s.decideRule(true)))
	m.Handle("POST /v1/automation/rules/{id}/retire", s.authed(s.decideRule(false)))
	m.Handle("GET /v1/intelligence/portfolio", s.authed(s.portfolioRisks))
	m.Handle("GET /v1/intelligence/projects/{id}/risks", s.authed(s.projectRisks))
	m.Handle("GET /v1/intelligence/cash", s.authed(s.cashOutlook))
	m.Handle("GET /v1/intelligence/controls", s.authed(s.controlReview))
	m.Handle("POST /v1/assistant/ask", s.authed(s.ask))
}

func (s *Server) getTenantSettings(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Kernel.TenantSettings(r.Context(), principalFrom(r.Context()))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) putTenantSettings(w http.ResponseWriter, r *http.Request) {
	var in postgres.TenantSettings
	if !decode(w, r, &in) {
		return
	}
	out, err := s.cfg.Kernel.SaveTenantSettings(r.Context(), principalFrom(r.Context()), in)
	if errors.Is(err, postgres.ErrConflict) {
		writeErr(w, http.StatusConflict, "conflict", "the settings changed since you loaded them; reload and try again")
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) listNotifications(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("include_resolved") == "true"
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	out, err := s.cfg.Kernel.Notifications(r.Context(), principalFrom(r.Context()), all, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	unread := 0
	for _, n := range out {
		if n.ReadAt == nil {
			unread++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out, "unread": unread})
}

func (s *Server) readNotification(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "notification not found")
		return
	}
	if err := s.cfg.Kernel.MarkNotificationRead(r.Context(), principalFrom(r.Context()), id); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "ok": true})
}

type ruleBody struct {
	Code        string          `json:"code"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Body        json.RawMessage `json:"body"`
}

func (s *Server) listRules(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Kernel.ListRules(r.Context(), principalFrom(r.Context()), r.URL.Query().Get("status"))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) proposeRule(w http.ResponseWriter, r *http.Request) {
	var b ruleBody
	if !decode(w, r, &b) {
		return
	}
	out, err := s.cfg.Kernel.ProposeRule(r.Context(), principalFrom(r.Context()), kernel.RuleInput{Code: b.Code, Name: b.Name, Description: b.Description, Body: b.Body})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) updateRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var b ruleBody
	if !decode(w, r, &b) {
		return
	}
	out, err := s.cfg.Kernel.UpdateRule(r.Context(), principalFrom(r.Context()), id, kernel.RuleInput{Name: b.Name, Description: b.Description, Body: b.Body})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) decideRule(activate bool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		var b decisionBody
		if r.ContentLength != 0 && !decode(w, r, &b) {
			return
		}
		out, err := s.cfg.Kernel.DecideRule(r.Context(), principalFrom(r.Context()), id, activate, b.Reason)
		if err != nil {
			s.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func (s *Server) portfolioRisks(w http.ResponseWriter, r *http.Request) {
	out, err := s.cfg.Kernel.PortfolioRisks(r.Context(), principalFrom(r.Context()))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": out, "algorithm": kernel.IntelligenceAlgorithm})
}

func (s *Server) projectRisks(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	out, err := s.cfg.Kernel.ProjectRisks(r.Context(), principalFrom(r.Context()), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) cashOutlook(w http.ResponseWriter, r *http.Request) {
	entity := r.URL.Query().Get("entity")
	if _, err := uuid.Parse(entity); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "entity must be a legal entity id")
		return
	}
	out, err := s.cfg.Kernel.CashOutlookOf(r.Context(), principalFrom(r.Context()), entity)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) controlReview(w http.ResponseWriter, r *http.Request) {
	entity := r.URL.Query().Get("entity")
	if _, err := uuid.Parse(entity); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "entity must be a legal entity id")
		return
	}
	out, err := s.cfg.Kernel.ControlAnomalies(r.Context(), principalFrom(r.Context()), entity)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) ask(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Question string `json:"question"`
	}
	if !decode(w, r, &b) {
		return
	}
	p := principalFrom(r.Context())
	// AI principals may ask (read-only) but never decide; this endpoint
	// changes nothing, so no extra gate is needed beyond the permission.
	out, err := s.cfg.Kernel.Ask(r.Context(), p, b.Question)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.cfg.Logger.Info("audit", "event", "assistant.ask", "tenant", p.TenantID, "sub", p.UserID, "intent", out.Intent)
	writeJSON(w, http.StatusOK, out)
}

// unused guard: the kernel's permission constants are referenced so a rename
// is caught at compile time.
var _ = auth.PermIntelligenceRead
