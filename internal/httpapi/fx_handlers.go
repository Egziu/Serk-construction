package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/fx"
	"github.com/serk-group/serk-construction/pkg/money"
)

type reasonBody struct {
	Reason string `json:"reason"`
}

func (s *Server) registerSource(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SourceID             string `json:"source_id"`
		SourceType           string `json:"source_type"`
		Description          string `json:"description"`
		RequiresDocumentHash *bool  `json:"requires_document_hash"`
		MaxVariance          string `json:"max_variance"`
	}
	if !decode(w, r, &body) {
		return
	}
	mv := decimal.RequireFromString("0.05")
	if body.MaxVariance != "" {
		var err error
		if mv, err = parseDecimal(body.MaxVariance); err != nil {
			writeErr(w, http.StatusUnprocessableEntity, "validation", "max_variance must be a decimal string")
			return
		}
	}
	req := true
	if body.RequiresDocumentHash != nil {
		req = *body.RequiresDocumentHash
	}
	err := s.cfg.Kernel.RegisterFXSource(r.Context(), principalFrom(r.Context()), postgres.FXSource{
		SourceID: body.SourceID, SourceType: body.SourceType, Description: body.Description, RequiresDocumentHash: req, MaxVariance: mv})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"source_id": body.SourceID, "status": "PENDING"})
}

func (s *Server) approveSource(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.cfg.Kernel.ApproveFXSource(r.Context(), principalFrom(r.Context()), id); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"source_id": id, "status": "APPROVED"})
}

func (s *Server) proposePolicy(w http.ResponseWriter, r *http.Request) {
	var body struct {
		LegalEntityID     string   `json:"legal_entity_id"`
		Purpose           string   `json:"purpose"`
		RateType          string   `json:"rate_type"`
		SourcePriority    []string `json:"source_priority"`
		MaxStalenessHours int      `json:"max_staleness_hours"`
		AllowInverse      bool     `json:"allow_inverse"`
	}
	if !decode(w, r, &body) {
		return
	}
	if _, err := uuid.Parse(body.LegalEntityID); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "legal_entity_id must be a UUID")
		return
	}
	if body.Purpose == "" {
		body.Purpose = postgres.PurposeTransaction
	}
	pol, err := s.cfg.Kernel.ProposeFXPolicy(r.Context(), principalFrom(r.Context()), body.LegalEntityID, body.Purpose, fx.Policy{
		RateType: fx.RateType(body.RateType), SourcePriority: body.SourcePriority, AllowInverse: body.AllowInverse,
		MaxStaleness: time.Duration(body.MaxStalenessHours) * time.Hour})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"policy_id": pol.ID, "version": pol.Version, "status": pol.Status})
}

func (s *Server) decidePolicy(approve bool) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if _, err := uuid.Parse(id); err != nil {
			writeErr(w, http.StatusNotFound, "not_found", "not found")
			return
		}
		var body reasonBody
		if !decode(w, r, &body) {
			return
		}
		if err := s.cfg.Kernel.DecideFXPolicy(r.Context(), principalFrom(r.Context()), id, approve, body.Reason); err != nil {
			s.fail(w, err)
			return
		}
		status := "REJECTED"
		if approve {
			status = "APPROVED"
		}
		writeJSON(w, http.StatusOK, map[string]string{"policy_id": id, "status": status})
	}
}

func (s *Server) recordSnapshot(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SourceID           string    `json:"source_id"`
		SourceType         string    `json:"source_type"`
		BaseCurrency       string    `json:"base_currency"`
		QuoteCurrency      string    `json:"quote_currency"`
		Rate               string    `json:"rate"`
		RateType           string    `json:"rate_type"`
		EffectiveFromUTC   time.Time `json:"effective_from_utc"`
		PublishedAtUTC     time.Time `json:"published_at_utc"`
		SourceDocumentHash string    `json:"source_document_hash"`
	}
	// Note: the 0.1.0 "approve" field is gone. Strict decoding rejects it,
	// so no client can believe it self-approved a rate (SC-03).
	if !decode(w, r, &body) {
		return
	}
	rate, err := parseDecimal(body.Rate)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, "validation", "rate must be a decimal string")
		return
	}
	snap := fx.Snapshot{SourceID: body.SourceID, SourceType: body.SourceType, BaseCurrency: money.Currency(body.BaseCurrency), QuoteCurrency: money.Currency(body.QuoteCurrency),
		Rate: rate, RateType: fx.RateType(body.RateType), EffectiveFromUTC: body.EffectiveFromUTC, PublishedAtUTC: body.PublishedAtUTC,
		CapturedAtUTC: time.Now().UTC(), SourceDocumentHash: body.SourceDocumentHash}
	id, err := s.cfg.Kernel.RecordFXSnapshot(r.Context(), principalFrom(r.Context()), snap)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"snapshot_id": id, "status": string(fx.StatusPending)})
}

func (s *Server) snapshotID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "not found")
		return "", false
	}
	return id, true
}

func (s *Server) approveSnapshot(w http.ResponseWriter, r *http.Request) {
	id, ok := s.snapshotID(w, r)
	if !ok {
		return
	}
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	res, err := s.cfg.Kernel.ApproveFXSnapshot(r.Context(), principalFrom(r.Context()), id, body.Reason)
	if err != nil {
		s.fail(w, err)
		return
	}
	out := map[string]any{"snapshot_id": id, "status": string(fx.StatusApproved), "variance_exception": res.VarianceException}
	if res.Deviation != nil {
		out["deviation"] = res.Deviation.String()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) rejectSnapshot(w http.ResponseWriter, r *http.Request) {
	s.negativeDecision(w, r, s.cfg.Kernel.RejectFXSnapshot, fx.StatusRejected)
}

func (s *Server) withdrawSnapshot(w http.ResponseWriter, r *http.Request) {
	s.negativeDecision(w, r, s.cfg.Kernel.WithdrawFXSnapshot, fx.StatusDisputed)
}

type decisionFunc func(ctx context.Context, p auth.Principal, id, reason string) error

func (s *Server) negativeDecision(w http.ResponseWriter, r *http.Request, fn decisionFunc, status fx.ApprovalStatus) {
	id, ok := s.snapshotID(w, r)
	if !ok {
		return
	}
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	if err := fn(r.Context(), principalFrom(r.Context()), id, body.Reason); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"snapshot_id": id, "status": string(status)})
}

func (s *Server) convert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Amount          money.Money `json:"amount"`
		Target          string      `json:"target_currency"`
		EventAt         time.Time   `json:"business_event_at"`
		LegalEntityID   string      `json:"legal_entity_id"`
		Purpose         string      `json:"purpose"`
		KnowledgeCutoff time.Time   `json:"knowledge_cutoff"`
		RateType        string      `json:"rate_type"`
		SourcePriority  []string    `json:"source_priority"`
		AllowInverse    bool        `json:"allow_inverse"`
		MaxStalenessH   int         `json:"max_staleness_hours"`
		Rounding        string      `json:"rounding"`
	}
	if !decode(w, r, &body) {
		return
	}
	res, err := s.cfg.Kernel.Convert(r.Context(), principalFrom(r.Context()), kernel.ConvertRequest{
		Amount: body.Amount, Target: money.Currency(body.Target), EventAt: body.EventAt, LegalEntityID: body.LegalEntityID, Purpose: body.Purpose,
		KnowledgeCutoff: body.KnowledgeCutoff,
		Policy: fx.Policy{RateType: fx.RateType(body.RateType), SourcePriority: body.SourcePriority, AllowInverse: body.AllowInverse,
			MaxStaleness: time.Duration(body.MaxStalenessH) * time.Hour},
		Rounding: money.RoundingPolicy(body.Rounding),
	})
	if err != nil {
		s.fail(w, err)
		return
	}
	out := map[string]any{
		"from": res.From, "to": res.To, "snapshot_id": res.SnapshotID, "applied_rate": res.AppliedRate.String(),
		"derived_inverse": res.DerivedInverse, "rounding": res.RoundingPolicy, "algorithm_version": res.AlgorithmVersion,
		"binding": res.Binding,
	}
	if res.Binding {
		out["fx_policy_id"], out["fx_policy_version"] = res.PolicyID, res.PolicyVersion
	}
	writeJSON(w, 200, out)
}

func (s *Server) closePeriod(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	var body struct {
		Lock bool `json:"lock"`
	}
	if !decode(w, r, &body) {
		return
	}
	res, err := s.cfg.Kernel.ClosePeriod(r.Context(), principalFrom(r.Context()), id, body.Lock)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"period_id": id, "action": res.Record.Action, "journal_count": res.Record.JournalCount,
		"tb_debits": res.Record.TBDebits, "tb_credits": res.Record.TBCredits, "tb_hash": res.Record.TBHash})
}

func (s *Server) reopenPeriod(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, err := uuid.Parse(id); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	var body reasonBody
	if !decode(w, r, &body) {
		return
	}
	if err := s.cfg.Kernel.ReopenPeriod(r.Context(), principalFrom(r.Context()), id, body.Reason); err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"period_id": id, "status": "OPEN"})
}
