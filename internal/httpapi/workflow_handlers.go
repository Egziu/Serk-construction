package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/serk-group/serk-construction/internal/store/postgres"
)

// Workflow console and decision endpoints. Every decision is made by the
// authenticated person; there is no endpoint through which automation can
// approve anything.

func validUUID(w http.ResponseWriter, v, name string) bool {
	if _, err := uuid.Parse(v); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", name+" must be a UUID")
		return false
	}
	return true
}

func (s *Server) proposeWorkflowDefinition(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if !decode(w, r, &raw) {
		return
	}
	d, err := s.cfg.Kernel.ProposeWorkflowDefinition(r.Context(), principalFrom(r.Context()), raw)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, d)
}

func (s *Server) listWorkflowDefinitions(w http.ResponseWriter, r *http.Request) {
	defs, err := s.cfg.Kernel.ListWorkflowDefinitions(r.Context(), principalFrom(r.Context()))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"definitions": defs})
}

func (s *Server) decideWorkflowDefinition(publish bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !validUUID(w, id, "id") {
			return
		}
		var body reasonBody
		if r.ContentLength != 0 && !decode(w, r, &body) {
			return
		}
		if err := s.cfg.Kernel.DecideWorkflowDefinition(r.Context(), principalFrom(r.Context()), id, publish, body.Reason); err != nil {
			s.fail(w, err)
			return
		}
		status := "REJECTED"
		if publish {
			status = "PUBLISHED"
		}
		writeJSON(w, http.StatusOK, map[string]string{"definition_id": id, "status": status})
	}
}

func (s *Server) simulateWorkflow(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		SubjectID string `json:"subject_id"`
	}
	if !validUUID(w, id, "id") || !decode(w, r, &body) || !validUUID(w, body.SubjectID, "subject_id") {
		return
	}
	route, err := s.cfg.Kernel.SimulateWorkflow(r.Context(), principalFrom(r.Context()), id, body.SubjectID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "steps": route})
}

func (s *Server) startWorkflow(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DefinitionKey string `json:"definition_key"`
		SubjectID     string `json:"subject_id"`
	}
	if !decode(w, r, &body) || !validUUID(w, body.SubjectID, "subject_id") {
		return
	}
	inst, err := s.cfg.Kernel.StartWorkflow(r.Context(), principalFrom(r.Context()), body.DefinitionKey, body.SubjectID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, inst)
}

func (s *Server) listWorkflowInstances(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := postgres.InstanceFilter{Status: q.Get("status"), SubjectType: q.Get("subject_type"), SubjectID: q.Get("subject_id"), Overdue: q.Get("overdue") == "true"}
	if f.SubjectID != "" && !validUUID(w, f.SubjectID, "subject_id") {
		return
	}
	list, err := s.cfg.Kernel.ListWorkflowInstances(r.Context(), principalFrom(r.Context()), f)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"instances": list})
}

func (s *Server) getWorkflowInstance(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !validUUID(w, id, "id") {
		return
	}
	d, err := s.cfg.Kernel.GetWorkflowInstance(r.Context(), principalFrom(r.Context()), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) decideWorkflow(approve bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !validUUID(w, id, "id") {
			return
		}
		var body reasonBody
		if r.ContentLength != 0 && !decode(w, r, &body) {
			return
		}
		res, err := s.cfg.Kernel.DecideWorkflow(r.Context(), principalFrom(r.Context()), id, approve, body.Reason)
		if err != nil {
			s.fail(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"instance": res.Instance, "step_completed": res.StepCompleted,
			"effect_executed": res.EffectExecuted, "approvals": res.Approvals, "approvals_needed": res.Needed})
	}
}

func (s *Server) cancelWorkflow(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body reasonBody
	if !validUUID(w, id, "id") || !decode(w, r, &body) {
		return
	}
	if err := s.cfg.Kernel.CancelWorkflow(r.Context(), principalFrom(r.Context()), id, body.Reason); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"instance_id": id, "status": "CANCELLED"})
}

func (s *Server) workflowTasks(w http.ResponseWriter, r *http.Request) {
	tasks, err := s.cfg.Kernel.ListWorkflowTasks(r.Context(), principalFrom(r.Context()))
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tasks": tasks})
}

func (s *Server) workflowMetrics(w http.ResponseWriter, r *http.Request) {
	since := time.Now().UTC().AddDate(0, 0, -30)
	if v := r.URL.Query().Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeErr(w, http.StatusUnprocessableEntity, "validation", "since must be RFC 3339")
			return
		}
		since = t
	}
	m, err := s.cfg.Kernel.WorkflowMetrics(r.Context(), principalFrom(r.Context()), since)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"since": since, "metrics": m})
}
