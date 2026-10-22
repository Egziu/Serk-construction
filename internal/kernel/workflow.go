package kernel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/money"
	"github.com/serk-group/serk-construction/pkg/workflow"
)

// Workflow errors.
var (
	// ErrWorkflowRequired: a mandatory workflow governs this transition.
	ErrWorkflowRequired = errors.New("kernel: this transition is governed by a mandatory approval workflow")
	// ErrWorkflowState: the instance is not in a state that allows the action.
	ErrWorkflowState = errors.New("kernel: workflow state does not allow this action")
	// ErrSubjectChanged: the subject no longer matches what was routed.
	ErrSubjectChanged = errors.New("kernel: the workflow subject changed after the workflow started; cancel and restart it")
)

// SystemTimerActor is the audit identity of the workflow timer worker. It
// escalates and expires; it never approves anything.
const SystemTimerActor = "system:workflow-timer"

// WorkflowCatalog is the set of effects workflows may execute. Every effect
// runs through the same kernel command a person would call, as the approving
// person, so permissions, SoD, step-up MFA and database invariants apply.
func (s *Service) WorkflowCatalog() workflow.Catalog {
	return workflow.Catalog{
		Actions: map[string]workflow.Action{
			"journal.approve": {Name: "journal.approve", Subject: "journal", Sensitive: true, Permission: auth.PermJournalApprove},
			"journal.post":    {Name: "journal.post", Subject: "journal", Sensitive: true, Permission: auth.PermJournalPost},
			"journal.cancel":  {Name: "journal.cancel", Subject: "journal", Permission: auth.PermJournalApprove},
			"fx.approve":      {Name: "fx.approve", Subject: "fx_snapshot", Sensitive: true, Permission: auth.PermFXApprove},
			"fx.reject":       {Name: "fx.reject", Subject: "fx_snapshot", Permission: auth.PermFXApprove},
			"period.close":    {Name: "period.close", Subject: "fiscal_period", Sensitive: true, Permission: auth.PermPeriodClose},
		},
		Permissions: s.authz.KnownPermissions(),
		Subjects:    map[string]bool{"journal": true, "fx_snapshot": true, "fiscal_period": true},
	}
}

// parseStored re-validates a stored definition and checks its body hash.
// The hash covers the canonical encoding of the parsed definition (jsonb
// does not preserve byte layout), so it detects any change of content.
func (s *Service) parseStored(d postgres.WorkflowDefinitionRow) (workflow.Definition, error) {
	def, err := workflow.Parse(d.Body, s.WorkflowCatalog())
	if err != nil {
		return workflow.Definition{}, err
	}
	canonical, err := json.Marshal(def)
	if err != nil {
		return workflow.Definition{}, err
	}
	// Since 0012 body_hash is the database digest of the stored jsonb text,
	// which is exactly the bytes PostgreSQL returns for the body column.
	// Definitions stored before 0012 carry the hash of the Go canonical
	// encoding; both are accepted, nothing else is.
	stored := sha256.Sum256(d.Body)
	sum := sha256.Sum256(canonical)
	if "sha256:"+hex.EncodeToString(stored[:]) != d.BodyHash && "sha256:"+hex.EncodeToString(sum[:]) != d.BodyHash {
		return workflow.Definition{}, fmt.Errorf("%w: stored definition does not match its hash", workflow.ErrInvalid)
	}
	return def, nil
}

func refuseIfMandatory(ctx context.Context, tx pgx.Tx, subject string) error {
	d, ok, err := postgres.MandatoryWorkflowFor(ctx, tx, subject)
	if err != nil {
		return err
	}
	if ok {
		return fmt.Errorf("%w: start workflow %q (v%d)", ErrWorkflowRequired, d.Key, d.Version)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Definitions
// ---------------------------------------------------------------------------

// ProposeWorkflowDefinition validates and stores a new DRAFT version.
func (s *Service) ProposeWorkflowDefinition(ctx context.Context, p auth.Principal, body []byte) (postgres.WorkflowDefinitionRow, error) {
	if err := s.authz.Require(p, auth.PermWorkflowDefine, p.TenantID); err != nil {
		return postgres.WorkflowDefinitionRow{}, err
	}
	def, err := workflow.Parse(body, s.WorkflowCatalog())
	if err != nil {
		return postgres.WorkflowDefinitionRow{}, err
	}
	canonical, err := json.Marshal(def) // canonical form; the database digests it as stored
	if err != nil {
		return postgres.WorkflowDefinitionRow{}, err
	}
	var out postgres.WorkflowDefinitionRow
	err = s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		// The attestation names the SQL digest of exactly the body that will be
		// stored; the database recomputes it from the inserted row (0010).
		digest, err := postgres.WorkflowBodyDigest(ctx, tx, canonical)
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "workflow.define", "workflow_definition_body", digest, def.Key); err != nil {
			return err
		}
		out, err = postgres.InsertWorkflowDefinition(ctx, tx, postgres.WorkflowDefinitionRow{TenantID: p.TenantID, Key: def.Key,
			Subject: def.Subject, Mandatory: def.Mandatory, Body: canonical, BodyHash: digest, ProposedBy: p.UserID})
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, "workflow.definition.propose", "workflow_definition", out.ID, "workflow.definition.proposed",
			map[string]any{"definition_id": out.ID, "key": out.Key, "version": out.Version, "mandatory": out.Mandatory, "body_hash": out.BodyHash})
	})
	return out, err
}

// DecideWorkflowDefinition publishes or rejects a DRAFT definition. A
// published definition changes the organization's controls, so publishing
// requires a different person than the author and a recent MFA.
func (s *Service) DecideWorkflowDefinition(ctx context.Context, p auth.Principal, id string, publish bool, reason string) error {
	if err := s.authz.Require(p, auth.PermWorkflowPublish, p.TenantID); err != nil {
		return err
	}
	if publish {
		if err := s.authz.RequireStepUp(p); err != nil {
			return err
		}
	} else if err := requireReason(reason); err != nil {
		return err
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		d, err := postgres.GetWorkflowDefinition(ctx, tx, id, false) // the database function locks (gate first)
		if err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.ProposedBy, "workflow definition"); err != nil {
			return err
		}
		if d.Status != "DRAFT" {
			return fmt.Errorf("%w: definition is %s", ErrWorkflowState, d.Status)
		}
		// Re-validate against today's catalog: a permission or effect may
		// have been withdrawn since the draft was proposed.
		if _, err := s.parseStored(d); err != nil {
			return err
		}
		status, ev := "REJECTED", "workflow.definition.rejected"
		if publish {
			status, ev = "PUBLISHED", "workflow.definition.published"
		}
		if err := s.authorize(ctx, tx, p, "workflow.decide_definition", "workflow_definition", id, status); err != nil {
			return err
		}
		if err := postgres.DecideWorkflowDefinition(ctx, tx, id, status, p.UserID, reason); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "workflow.definition.decide", "workflow_definition", id, ev,
			map[string]any{"definition_id": id, "key": d.Key, "version": d.Version, "status": status, "mandatory": d.Mandatory,
				"proposed_by": d.ProposedBy, "reason": reason, "body_hash": d.BodyHash})
	})
}

// ListWorkflowDefinitions lists all definition versions.
func (s *Service) ListWorkflowDefinitions(ctx context.Context, p auth.Principal) ([]postgres.WorkflowDefinitionRow, error) {
	if err := s.authz.Require(p, auth.PermWorkflowRead, p.TenantID); err != nil {
		return nil, err
	}
	var out []postgres.WorkflowDefinitionRow
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.ListWorkflowDefinitions(ctx, tx)
		return err
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Subjects: facts are always derived on the server from the stored subject.
// ---------------------------------------------------------------------------

type subjectFacts struct {
	facts  postgres.InstanceFacts
	amount *money.Money
	// resume: a journal that is already APPROVED; its route starts after the
	// step that approves journals.
	resume bool
}

// sameFacts compares routing facts. ApprovedBy is excluded: it legitimately
// changes when the instance's own approval step runs.
func sameFacts(a, b postgres.InstanceFacts) bool {
	a.ApprovedBy, b.ApprovedBy = "", ""
	return a == b
}

func fingerprint(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return "sha256:" + hex.EncodeToString(h[:])
}

func loadSubjectFacts(ctx context.Context, tx pgx.Tx, subjectType, subjectID string) (subjectFacts, error) {
	switch subjectType {
	case "journal":
		rec, err := postgres.GetJournal(ctx, tx, subjectID, false)
		if err != nil {
			return subjectFacts{}, err
		}
		hash := postgres.CommandHash(rec.Journal)
		if hash != rec.CommandHash {
			return subjectFacts{}, fmt.Errorf("%w: journal lines differ from the created command", ErrSubjectChanged)
		}
		debits, _, err := rec.Journal.Totals()
		if err != nil {
			return subjectFacts{}, err
		}
		return subjectFacts{amount: &debits, resume: rec.Status == "APPROVED", facts: postgres.InstanceFacts{Amount: debits.AmountString(),
			Currency: string(debits.Currency()), ProjectID: rec.ProjectID, CreatedBy: rec.CreatedBy, ApprovedBy: rec.ApprovedBy,
			Fingerprint: fingerprint("journal", rec.ID, hash), Label: rec.Description}}, nil
	case "fx_snapshot":
		snap, err := postgres.GetFXSnapshot(ctx, tx, subjectID, false)
		if err != nil {
			return subjectFacts{}, err
		}
		pair := string(snap.BaseCurrency) + "/" + string(snap.QuoteCurrency)
		return subjectFacts{facts: postgres.InstanceFacts{CreatedBy: snap.CreatedBy,
			Fingerprint: fingerprint("fx_snapshot", snap.SnapshotID, pair, snap.Rate.String(), snap.SourceID, string(snap.RateType),
				snap.EffectiveFromUTC.UTC().Format(time.RFC3339Nano), snap.SourceDocumentHash),
			Label: pair + " " + snap.Rate.String() + " (" + snap.SourceID + ")"}}, nil
	case "fiscal_period":
		per, err := postgres.GetFiscalPeriod(ctx, tx, subjectID, false)
		if err != nil {
			return subjectFacts{}, err
		}
		return subjectFacts{facts: postgres.InstanceFacts{
			Fingerprint: fingerprint("fiscal_period", per.ID, per.LegalEntityID, per.StartsOn.Format("2006-01-02"), per.EndsOn.Format("2006-01-02")),
			Label:       per.Name}}, nil
	}
	return subjectFacts{}, fmt.Errorf("%w: unknown subject type %q", workflow.ErrInvalid, subjectType)
}

func subjectReady(ctx context.Context, tx pgx.Tx, subjectType, subjectID string) error {
	switch subjectType {
	case "journal":
		rec, err := postgres.GetJournal(ctx, tx, subjectID, true)
		if err != nil {
			return err
		}
		if rec.Status != "DRAFT" && rec.Status != "APPROVED" {
			return fmt.Errorf("%w: journal is %s", ErrWorkflowState, rec.Status)
		}
	case "fx_snapshot":
		snap, err := postgres.GetFXSnapshot(ctx, tx, subjectID, true)
		if err != nil {
			return err
		}
		if snap.ApprovalStatus != "PENDING" {
			return fmt.Errorf("%w: rate is %s", ErrWorkflowState, snap.ApprovalStatus)
		}
	case "fiscal_period":
		per, err := postgres.GetFiscalPeriod(ctx, tx, subjectID, true)
		if err != nil {
			return err
		}
		if per.Status != "OPEN" {
			return fmt.Errorf("%w: period is %s", ErrWorkflowState, per.Status)
		}
	}
	return nil
}

func freezeRoute(def workflow.Definition, sf subjectFacts) ([]postgres.RouteStepRow, error) {
	sim, err := def.Simulate(workflow.Facts{Amount: sf.amount, ProjectID: sf.facts.ProjectID, CreatedBy: sf.facts.CreatedBy})
	if err != nil {
		return nil, err
	}
	route, err := def.Route(workflow.Facts{Amount: sf.amount})
	if err != nil {
		return nil, err
	}
	if sf.resume { // APPROVED journal: continue after the approval step
		for i, r := range route {
			if r.Effect == "journal.approve" {
				route, sim = route[i+1:], sim[i+1:]
				break
			}
		}
		if len(route) == 0 {
			return nil, fmt.Errorf("%w: nothing left to route for an approved journal", ErrWorkflowState)
		}
	}
	out := make([]postgres.RouteStepRow, len(route))
	for i, r := range route {
		row := postgres.RouteStepRow{ID: r.ID, Title: r.Title, Permission: string(r.Permission), Approvals: r.Approvals,
			DistinctFrom: append([]string{}, r.DistinctFrom...), RequireMFA: r.RequireMFA, Effect: r.Effect,
			EscalateTo: string(r.EscalateTo), Reason: sim[i].Reason}
		if r.SLA != "" {
			d, _ := time.ParseDuration(r.SLA)
			row.SLASeconds = int64(d / time.Second)
		}
		if r.ExpireAfter != "" {
			d, _ := time.ParseDuration(r.ExpireAfter)
			row.ExpireSeconds = int64(d / time.Second)
		}
		out[i] = row
	}
	return out, nil
}

// requireSubjectAccess applies the principal's project scope to the subject.
func (s *Service) requireSubjectAccess(p auth.Principal, perm auth.Permission, f postgres.InstanceFacts) error {
	return s.authz.RequireProject(p, perm, p.TenantID, f.ProjectID)
}

// ---------------------------------------------------------------------------
// Simulation
// ---------------------------------------------------------------------------

// SimulateWorkflow is a side-effect-free dry run of a definition (any
// status, so reviewers can test a draft before publishing it) against a
// real subject: which steps would apply, who may decide them, and why.
func (s *Service) SimulateWorkflow(ctx context.Context, p auth.Principal, definitionID, subjectID string) ([]postgres.RouteStepRow, error) {
	if err := s.authz.Require(p, auth.PermWorkflowRead, p.TenantID); err != nil {
		return nil, err
	}
	var out []postgres.RouteStepRow
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		d, err := postgres.GetWorkflowDefinition(ctx, tx, definitionID, false)
		if err != nil {
			return err
		}
		def, err := s.parseStored(d)
		if err != nil {
			return err
		}
		sf, err := loadSubjectFacts(ctx, tx, def.Subject, subjectID)
		if err != nil {
			return err
		}
		if s.requireSubjectAccess(p, auth.PermWorkflowRead, sf.facts) != nil {
			return ErrNotFound // out-of-scope subjects are indistinguishable from absent ones
		}
		out, err = freezeRoute(def, sf)
		return err
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Instances
// ---------------------------------------------------------------------------

// StartWorkflow starts the published version of a definition for a subject.
func (s *Service) StartWorkflow(ctx context.Context, p auth.Principal, key, subjectID string) (postgres.WorkflowInstance, error) {
	var out postgres.WorkflowInstance
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Lock order (as in the database): gate row first, then definition row.
		peek, err := postgres.PublishedWorkflowDefinition(ctx, tx, key, false)
		if err != nil {
			return err
		}
		if err := postgres.LockWorkflowGate(ctx, tx, p.TenantID, peek.Subject, false); err != nil {
			return err
		}
		// Re-read under the gate lock: the published version is now stable.
		d, err := postgres.PublishedWorkflowDefinition(ctx, tx, key, false)
		if err != nil {
			return err // retired between the two reads
		}
		def, err := s.parseStored(d)
		if err != nil {
			return err
		}
		if err := s.authz.Require(p, def.StartPermission, p.TenantID); err != nil {
			return err
		}
		if m, ok, err := postgres.MandatoryWorkflowFor(ctx, tx, def.Subject); err != nil {
			return err
		} else if ok && m.ID != d.ID {
			return fmt.Errorf("%w: %s is governed by %q", ErrWorkflowRequired, def.Subject, m.Key)
		}
		sf, err := loadSubjectFacts(ctx, tx, def.Subject, subjectID)
		if err != nil {
			return err
		}
		if s.requireSubjectAccess(p, def.StartPermission, sf.facts) != nil {
			return ErrNotFound
		}
		if err := subjectReady(ctx, tx, def.Subject, subjectID); err != nil {
			return err
		}
		route, err := freezeRoute(def, sf)
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "workflow.start", def.Subject, subjectID, d.ID); err != nil {
			return err
		}
		out, err = postgres.InsertWorkflowInstance(ctx, tx, postgres.WorkflowInstance{TenantID: p.TenantID, DefinitionID: d.ID,
			SubjectType: def.Subject, SubjectID: subjectID, Facts: sf.facts, Route: route, InitiatedBy: p.UserID})
		if err != nil {
			return err
		}
		zero := 0
		if err := postgres.AppendWorkflowHistory(ctx, tx, p.TenantID, out.ID, postgres.WorkflowHistoryEntry{Kind: "STARTED", Actor: p.UserID,
			StepIndex: &zero, Detail: map[string]any{"definition": d.Key, "version": d.Version, "steps": len(route)}}); err != nil {
			return err
		}
		if err := s.record(ctx, tx, p, "workflow.start", "workflow_instance", out.ID, "workflow.started",
			map[string]any{"instance_id": out.ID, "definition": d.Key, "version": d.Version, "subject_type": def.Subject, "subject_id": subjectID,
				"amount": sf.facts.Amount, "currency": sf.facts.Currency}); err != nil {
			return err
		}
		return s.notifyOpenStep(ctx, tx, p, out)
	})
	return out, err
}

func (s *Service) notifyOpenStep(ctx context.Context, tx pgx.Tx, p auth.Principal, w postgres.WorkflowInstance) error {
	step, ok := w.OpenStep()
	if !ok {
		return nil
	}
	return postgres.Outbox(ctx, tx, postgres.OutboxEvent{TenantID: p.TenantID, AggregateType: "workflow_instance", AggregateID: w.ID,
		EventType: "workflow.task_opened", Payload: map[string]any{"instance_id": w.ID, "step": step.ID, "permission": step.Permission,
			"approvals": step.Approvals, "require_mfa": step.RequireMFA, "subject_type": w.SubjectType, "subject_id": w.SubjectID,
			"sla_due_at": w.SLADueAt, "expires_at": w.ExpiresAt}})
}

// excludedFor computes the SoD exclusions of the open step (the database
// computes the same set independently).
// prior lists approvers of earlier instances of the same subject.
func excludedFor(w postgres.WorkflowInstance, decisions []postgres.WorkflowDecision, prior []string) map[string]string {
	out := map[string]string{}
	step, ok := w.OpenStep()
	if !ok {
		return out
	}
	for _, ref := range step.DistinctFrom {
		switch {
		case ref == workflow.RefInitiator:
			out[w.InitiatedBy] = "initiated this workflow"
		case ref == workflow.RefSubjectCreator && w.Facts.CreatedBy != "":
			out[w.Facts.CreatedBy] = "created the subject"
		case strings.HasPrefix(ref, workflow.RefStepPrefix):
			id := strings.TrimPrefix(ref, workflow.RefStepPrefix)
			inRoute := false
			for _, r := range w.Route {
				inRoute = inRoute || r.ID == id
			}
			if !inRoute {
				// The step is not in this route (it ran before a resumed
				// instance, or was skipped): exclude whoever approved the
				// journal and everyone who approved earlier instances.
				if w.Facts.ApprovedBy != "" {
					out[w.Facts.ApprovedBy] = "approved this journal before the workflow resumed"
				}
				for _, u := range prior {
					out[u] = "approved an earlier workflow of this subject"
				}
			}
			for i := 0; i < w.CurrentStep; i++ {
				if w.Route[i].ID != id {
					continue
				}
				for _, d := range decisions {
					if d.StepIndex == i && d.Decision == "APPROVE" {
						out[d.DecidedBy] = "approved step " + id
					}
				}
			}
		}
	}
	return out
}

// assertGoverning: an instance acts only while its definition version is the
// published one and no other mandatory definition governs the subject type
// (the database enforces the same rule under an advisory lock).
func (s *Service) assertGoverning(ctx context.Context, tx pgx.Tx, w postgres.WorkflowInstance) error {
	d, err := postgres.GetWorkflowDefinition(ctx, tx, w.DefinitionID, false)
	if err != nil {
		return err
	}
	if d.Status != "PUBLISHED" {
		return fmt.Errorf("%w: definition %s v%d is %s; cancel this instance and start the current version", ErrWorkflowState, d.Key, d.Version, d.Status)
	}
	m, ok, err := postgres.MandatoryWorkflowFor(ctx, tx, w.SubjectType)
	if err != nil {
		return err
	}
	if ok && m.ID != d.ID {
		return fmt.Errorf("%w: %s is governed by %q; cancel this instance", ErrWorkflowRequired, w.SubjectType, m.Key)
	}
	return nil
}

// DecisionResult reports the outcome of a decision.
type DecisionResult struct {
	Instance       postgres.WorkflowInstance
	StepCompleted  bool
	EffectExecuted string
	Approvals      int
	Needed         int
}

// DecideWorkflow records the principal's decision on the open step. When
// the step reaches its quorum its effect executes in the same transaction,
// as this principal, through the kernel command (all-or-nothing: if the
// effect is refused, the decision is not recorded and the failure is
// logged on the instance for the console).
func (s *Service) DecideWorkflow(ctx context.Context, p auth.Principal, instanceID string, approve bool, reason string) (DecisionResult, error) {
	if !approve {
		if err := requireReason(reason); err != nil {
			return DecisionResult{}, err
		}
	}
	var res DecisionResult
	var effectErr error
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		w, err := postgres.GetWorkflowInstance(ctx, tx, instanceID, true)
		if err != nil {
			return err
		}
		if !s.authz.ScopeOf(p).Allows(w.Facts.ProjectID) {
			return ErrNotFound // never reveal the state of out-of-scope instances
		}
		step, ok := w.OpenStep()
		if !ok {
			return fmt.Errorf("%w: instance is %s", ErrWorkflowState, w.Status)
		}
		perm := auth.Permission(step.Permission)
		if err := s.authz.Require(p, perm, p.TenantID); err != nil {
			return err
		}
		if err := s.requireSubjectAccess(p, perm, w.Facts); err != nil {
			return err
		}
		if err := s.assertGoverning(ctx, tx, w); err != nil {
			return err
		}
		now, err := postgres.DBNow(ctx, tx)
		if err != nil {
			return err
		}
		if w.ExpiresAt != nil && !w.ExpiresAt.After(now) {
			return fmt.Errorf("%w: the open step expired at %s", ErrWorkflowState, w.ExpiresAt.UTC().Format(time.RFC3339))
		}
		stepUp := s.authz.RequireStepUp(p)
		if step.RequireMFA && stepUp != nil {
			return stepUp
		}
		decisions, err := postgres.WorkflowDecisions(ctx, tx, w.ID)
		if err != nil {
			return err
		}
		prior, err := postgres.PriorSubjectApprovers(ctx, tx, w)
		if err != nil {
			return err
		}
		if why, bad := excludedFor(w, decisions, prior)[p.UserID]; bad {
			return fmt.Errorf("%w: you %s and may not decide step %q", auth.ErrSoD, why, step.ID)
		}
		approvals := 0
		for _, d := range decisions {
			if d.StepIndex != w.CurrentStep {
				continue
			}
			if d.DecidedBy == p.UserID {
				return fmt.Errorf("%w: you already decided step %q", ErrWorkflowState, step.ID)
			}
			if d.Decision == "APPROVE" {
				approvals++
			}
		}
		// The subject must still be exactly what was routed.
		sf, err := loadSubjectFacts(ctx, tx, w.SubjectType, w.SubjectID)
		if err != nil {
			return err
		}
		if !sameFacts(sf.facts, w.Facts) {
			return ErrSubjectChanged
		}
		decision := "REJECT"
		if approve {
			decision = "APPROVE"
		}
		if err := s.authorize(ctx, tx, p, "workflow.decide", "workflow_instance", w.ID, fmt.Sprintf("%d:%s", w.CurrentStep, decision)); err != nil {
			return err
		}
		if err := postgres.InsertWorkflowDecision(ctx, tx, p.TenantID, w.ID, postgres.WorkflowDecision{StepIndex: w.CurrentStep, StepID: step.ID,
			DecidedBy: p.UserID, Decision: decision, Reason: reason, MFA: stepUp == nil}); err != nil {
			return err
		}
		idx := w.CurrentStep
		if err := postgres.AppendWorkflowHistory(ctx, tx, p.TenantID, w.ID, postgres.WorkflowHistoryEntry{Kind: "DECIDED", Actor: p.UserID,
			StepIndex: &idx, Detail: map[string]any{"step": step.ID, "decision": decision, "reason": reason, "mfa": stepUp == nil}}); err != nil {
			return err
		}
		if err := s.record(ctx, tx, p, "workflow.decide", "workflow_instance", w.ID, "workflow.decided",
			map[string]any{"instance_id": w.ID, "step": step.ID, "decision": decision, "reason": reason, "subject_type": w.SubjectType, "subject_id": w.SubjectID}); err != nil {
			return err
		}
		res.Needed = step.Approvals
		if !approve {
			return s.rejectInstance(ctx, tx, p, w, step, reason, &res)
		}
		approvals++
		res.Approvals = approvals
		if approvals < step.Approvals {
			res.Instance = w
			return nil // quorum not reached yet; waits for more approvers
		}
		if step.Effect != "" {
			if err := postgres.InsertWorkflowEffect(ctx, tx, w, step.Effect, p.UserID); err != nil {
				return err
			}
			if err := s.executeEffect(ctx, tx, p, step.Effect, w.SubjectID, reason); err != nil {
				effectErr = err
				return err
			}
			res.EffectExecuted = step.Effect
			if err := postgres.AppendWorkflowHistory(ctx, tx, p.TenantID, w.ID, postgres.WorkflowHistoryEntry{Kind: "EFFECT", Actor: p.UserID,
				StepIndex: &idx, Detail: map[string]any{"effect": step.Effect}}); err != nil {
				return err
			}
		}
		completed, err := postgres.AdvanceWorkflow(ctx, tx, w)
		if err != nil {
			return err
		}
		res.StepCompleted = true
		if err := postgres.AppendWorkflowHistory(ctx, tx, p.TenantID, w.ID, postgres.WorkflowHistoryEntry{Kind: "STEP_COMPLETED", Actor: p.UserID,
			StepIndex: &idx, Detail: map[string]any{"step": step.ID, "approvals": approvals}}); err != nil {
			return err
		}
		w, err = postgres.GetWorkflowInstance(ctx, tx, w.ID, false)
		if err != nil {
			return err
		}
		res.Instance = w
		if completed {
			if err := postgres.AppendWorkflowHistory(ctx, tx, p.TenantID, w.ID, postgres.WorkflowHistoryEntry{Kind: "COMPLETED", Actor: p.UserID}); err != nil {
				return err
			}
			return postgres.Outbox(ctx, tx, postgres.OutboxEvent{TenantID: p.TenantID, AggregateType: "workflow_instance", AggregateID: w.ID,
				EventType: "workflow.completed", Payload: map[string]any{"instance_id": w.ID, "subject_type": w.SubjectType, "subject_id": w.SubjectID}})
		}
		return s.notifyOpenStep(ctx, tx, p, w)
	})
	if err != nil && effectErr != nil {
		s.recordEffectFailure(ctx, p, instanceID, effectErr)
	}
	return res, err
}

var uuidPattern = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// consoleError is the failure text shown to approvers: no SQLSTATE, no
// identifiers, bounded length.
func consoleError(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, " (SQLSTATE"); i > 0 {
		msg = msg[:i]
	}
	msg = strings.TrimPrefix(msg, postgres.ErrInvariant.Error()+": ")
	msg = uuidPattern.ReplaceAllString(msg, "<id>")
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// recordEffectFailure logs a refused effect in its own transaction so the
// console can show it (the decision itself was rolled back).
func (s *Service) recordEffectFailure(ctx context.Context, p auth.Principal, instanceID string, cause error) {
	msg := consoleError(cause)
	_ = s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		w, err := postgres.GetWorkflowInstance(ctx, tx, instanceID, true)
		if err != nil || w.Status != "ACTIVE" {
			return err
		}
		if err := postgres.RecordWorkflowEffectFailure(ctx, tx, instanceID, msg); err != nil {
			return err
		}
		idx := w.CurrentStep
		if err := postgres.AppendWorkflowHistory(ctx, tx, p.TenantID, instanceID, postgres.WorkflowHistoryEntry{Kind: "EFFECT_FAILED", Actor: p.UserID,
			StepIndex: &idx, Detail: map[string]any{"error": msg}}); err != nil {
			return err
		}
		return postgres.Outbox(ctx, tx, postgres.OutboxEvent{TenantID: p.TenantID, AggregateType: "workflow_instance", AggregateID: instanceID,
			EventType: "workflow.effect_failed", Payload: map[string]any{"instance_id": instanceID, "step_index": idx, "by": p.UserID, "error": msg}})
	})
}

func (s *Service) rejectInstance(ctx context.Context, tx pgx.Tx, p auth.Principal, w postgres.WorkflowInstance, step postgres.RouteStepRow, reason string, res *DecisionResult) error {
	d, err := postgres.GetWorkflowDefinition(ctx, tx, w.DefinitionID, false)
	if err != nil {
		return err
	}
	def, err := s.parseStored(d)
	if err != nil {
		return err
	}
	idx := w.CurrentStep
	if def.OnReject != "" {
		// Compensation is best effort and never blocks the rejection: it runs
		// in a savepoint as the rejecting person.
		sp, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		if cerr := s.executeEffect(ctx, sp, p, def.OnReject, w.SubjectID, reason); cerr != nil {
			_ = sp.Rollback(ctx)
			if err := postgres.AppendWorkflowHistory(ctx, tx, p.TenantID, w.ID, postgres.WorkflowHistoryEntry{Kind: "EFFECT_FAILED", Actor: p.UserID,
				StepIndex: &idx, Detail: map[string]any{"effect": def.OnReject, "error": consoleError(cerr), "compensation": true}}); err != nil {
				return err
			}
		} else {
			if err := sp.Commit(ctx); err != nil {
				return err
			}
			res.EffectExecuted = def.OnReject
			if err := postgres.AppendWorkflowHistory(ctx, tx, p.TenantID, w.ID, postgres.WorkflowHistoryEntry{Kind: "EFFECT", Actor: p.UserID,
				StepIndex: &idx, Detail: map[string]any{"effect": def.OnReject, "compensation": true}}); err != nil {
				return err
			}
		}
	}
	if err := postgres.EndWorkflow(ctx, tx, w, "REJECTED", p.UserID, reason); err != nil {
		return err
	}
	if err := postgres.AppendWorkflowHistory(ctx, tx, p.TenantID, w.ID, postgres.WorkflowHistoryEntry{Kind: "REJECTED", Actor: p.UserID,
		StepIndex: &idx, Detail: map[string]any{"step": step.ID, "reason": reason}}); err != nil {
		return err
	}
	w, err = postgres.GetWorkflowInstance(ctx, tx, w.ID, false)
	if err != nil {
		return err
	}
	res.Instance = w
	return postgres.Outbox(ctx, tx, postgres.OutboxEvent{TenantID: p.TenantID, AggregateType: "workflow_instance", AggregateID: w.ID,
		EventType: "workflow.rejected", Payload: map[string]any{"instance_id": w.ID, "step": step.ID, "by": p.UserID, "reason": reason,
			"subject_type": w.SubjectType, "subject_id": w.SubjectID}})
}

// executeEffect runs a catalog effect as principal p inside tx.
func (s *Service) executeEffect(ctx context.Context, tx pgx.Tx, p auth.Principal, effect, subjectID, reason string) error {
	switch effect {
	case "journal.approve":
		return s.approveJournalTx(ctx, tx, p, subjectID)
	case "journal.post":
		return s.postJournalTx(ctx, tx, p, subjectID)
	case "journal.cancel":
		return s.cancelJournalTx(ctx, tx, p, subjectID, reason)
	case "fx.approve":
		_, err := s.approveFXSnapshotTx(ctx, tx, p, subjectID, reason)
		return err
	case "fx.reject":
		return s.decideNegativeTx(ctx, tx, p, subjectID, reason, "PENDING", "REJECTED", "fx.snapshot.reject", "fx.snapshot.rejected")
	case "period.close":
		_, err := s.closePeriodTx(ctx, tx, p, subjectID, false)
		return err
	}
	return fmt.Errorf("%w: unknown effect %q", workflow.ErrInvalid, effect)
}

// CancelWorkflow ends an ACTIVE instance (console operation). Cancelling
// never changes the subject; it releases it for a new workflow.
func (s *Service) CancelWorkflow(ctx context.Context, p auth.Principal, instanceID, reason string) error {
	if err := s.authz.Require(p, auth.PermWorkflowAdmin, p.TenantID); err != nil {
		return err
	}
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		w, err := postgres.GetWorkflowInstance(ctx, tx, instanceID, true)
		if err != nil {
			return err
		}
		if s.requireSubjectAccess(p, auth.PermWorkflowAdmin, w.Facts) != nil {
			return ErrNotFound
		}
		if w.Status != "ACTIVE" {
			return fmt.Errorf("%w: instance is %s", ErrWorkflowState, w.Status)
		}
		if err := s.authorize(ctx, tx, p, "workflow.cancel", "workflow_instance", w.ID, ""); err != nil {
			return err
		}
		if err := postgres.EndWorkflow(ctx, tx, w, "CANCELLED", p.UserID, reason); err != nil {
			return err
		}
		idx := w.CurrentStep
		if err := postgres.AppendWorkflowHistory(ctx, tx, p.TenantID, w.ID, postgres.WorkflowHistoryEntry{Kind: "CANCELLED", Actor: p.UserID,
			StepIndex: &idx, Detail: map[string]any{"reason": reason}}); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "workflow.cancel", "workflow_instance", w.ID, "workflow.cancelled",
			map[string]any{"instance_id": w.ID, "reason": reason, "subject_type": w.SubjectType, "subject_id": w.SubjectID})
	})
}

// ---------------------------------------------------------------------------
// Timers: SLA escalation and expiry. Durable (all state is in the database),
// safe to run on several workers (SKIP LOCKED), idempotent.
// ---------------------------------------------------------------------------

// TimerResult reports one timer pass.
type TimerResult struct {
	Escalated int
	Expired   int
}

// RunWorkflowTimers processes due instances of one tenant. Escalation
// notifies holders of the step's escalate_to permission; it does not let
// them approve without the step's own permission. Expiry ends the instance;
// it runs no effect, because only people run effects.
func (s *Service) RunWorkflowTimers(ctx context.Context, tenantID string, limit int) (TimerResult, error) {
	if limit <= 0 {
		limit = 100
	}
	sys := auth.Principal{UserID: SystemTimerActor, TenantID: tenantID, Kind: auth.KindService} // records only; never signs a decision
	var res TimerResult
	var first error
	err := s.store.WithTenant(ctx, tenantID, func(ctx context.Context, tx pgx.Tx) error {
		now, err := postgres.DBNow(ctx, tx) // same now() the database guards use
		if err != nil {
			return err
		}
		due, err := postgres.DueWorkflowInstances(ctx, tx, limit)
		if err != nil {
			return err
		}
		for _, w := range due {
			// One savepoint per instance: a failing instance is skipped (and
			// retried next pass) without undoing the others.
			sp, err := tx.Begin(ctx)
			if err != nil {
				return err
			}
			r, err := s.timerOne(ctx, sp, sys, tenantID, w, now)
			if err != nil {
				_ = sp.Rollback(ctx)
				if first == nil {
					first = fmt.Errorf("instance %s: %w", w.ID, err)
				}
				continue
			}
			if err := sp.Commit(ctx); err != nil {
				return err
			}
			res.Escalated += r.Escalated
			res.Expired += r.Expired
		}
		return nil
	})
	if err == nil {
		err = first
	}
	return res, err
}

// timerOne escalates or expires one due instance.
func (s *Service) timerOne(ctx context.Context, tx pgx.Tx, sys auth.Principal, tenantID string, w postgres.WorkflowInstance, now time.Time) (TimerResult, error) {
	var res TimerResult
	err := func() error {
		{
			idx := w.CurrentStep
			step, _ := w.OpenStep()
			if w.ExpiresAt != nil && !w.ExpiresAt.After(now) {
				if err := postgres.EndWorkflow(ctx, tx, w, "EXPIRED", SystemTimerActor, "deadline passed"); err != nil {
					return err
				}
				if err := postgres.AppendWorkflowHistory(ctx, tx, tenantID, w.ID, postgres.WorkflowHistoryEntry{Kind: "EXPIRED", Actor: SystemTimerActor,
					StepIndex: &idx, Detail: map[string]any{"step": step.ID, "expires_at": w.ExpiresAt}}); err != nil {
					return err
				}
				if err := s.record(ctx, tx, sys, "workflow.expire", "workflow_instance", w.ID, "workflow.expired",
					map[string]any{"instance_id": w.ID, "step": step.ID, "subject_type": w.SubjectType, "subject_id": w.SubjectID}); err != nil {
					return err
				}
				res.Expired++
				return nil
			}
			if w.SLADueAt != nil && !w.SLADueAt.After(now) && w.EscalatedAt == nil {
				if err := postgres.MarkWorkflowEscalated(ctx, tx, w); err != nil {
					return err
				}
				if err := postgres.AppendWorkflowHistory(ctx, tx, tenantID, w.ID, postgres.WorkflowHistoryEntry{Kind: "ESCALATED", Actor: SystemTimerActor,
					StepIndex: &idx, Detail: map[string]any{"step": step.ID, "escalate_to": step.EscalateTo, "sla_due_at": w.SLADueAt}}); err != nil {
					return err
				}
				if err := s.record(ctx, tx, sys, "workflow.escalate", "workflow_instance", w.ID, "workflow.escalated",
					map[string]any{"instance_id": w.ID, "step": step.ID, "escalate_to": step.EscalateTo, "permission": step.Permission,
						"subject_type": w.SubjectType, "subject_id": w.SubjectID}); err != nil {
					return err
				}
				res.Escalated++
			}
		}
		return nil
	}()
	return res, err
}

// ---------------------------------------------------------------------------
// Console
// ---------------------------------------------------------------------------

// WorkflowTask is an open step the principal may decide now.
type WorkflowTask struct {
	InstanceID   string     `json:"instance_id"`
	Definition   string     `json:"definition"`
	SubjectType  string     `json:"subject_type"`
	SubjectID    string     `json:"subject_id"`
	Label        string     `json:"label,omitempty"`
	Amount       string     `json:"amount,omitempty"`
	Currency     string     `json:"currency,omitempty"`
	Step         string     `json:"step"`
	StepTitle    string     `json:"step_title"`
	Approvals    int        `json:"approvals_needed"`
	Received     int        `json:"approvals_received"`
	RequireMFA   bool       `json:"require_mfa"`
	SLADueAt     *time.Time `json:"sla_due_at,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Overdue      bool       `json:"overdue"`
	Escalated    bool       `json:"escalated"`
	FailedTries  int        `json:"effect_failures"`
	LastError    string     `json:"last_error,omitempty"`
	WaitingSince time.Time  `json:"waiting_since"`
}

// ListWorkflowTasks returns the open steps this principal is eligible to
// decide: holds the permission and project scope, is not excluded by SoD and
// has not decided yet.
func (s *Service) ListWorkflowTasks(ctx context.Context, p auth.Principal) ([]WorkflowTask, error) {
	if err := s.authz.Require(p, auth.PermWorkflowRead, p.TenantID); err != nil {
		return nil, err
	}
	var out []WorkflowTask
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		now, err := postgres.DBNow(ctx, tx)
		if err != nil {
			return err
		}
		var perms []string
		for _, perm := range s.authz.Permissions(p) {
			perms = append(perms, string(perm))
		}
		active, err := postgres.ActiveInstancesAwaiting(ctx, tx, perms, 2000)
		if err != nil {
			return err
		}
		for _, w := range active {
			step, ok := w.OpenStep()
			if !ok || s.authz.RequireProject(p, auth.Permission(step.Permission), p.TenantID, w.Facts.ProjectID) != nil {
				continue
			}
			decisions, err := postgres.WorkflowDecisions(ctx, tx, w.ID)
			if err != nil {
				return err
			}
			prior, err := postgres.PriorSubjectApprovers(ctx, tx, w)
			if err != nil {
				return err
			}
			if _, excluded := excludedFor(w, decisions, prior)[p.UserID]; excluded {
				continue
			}
			received, mine := 0, false
			for _, d := range decisions {
				if d.StepIndex == w.CurrentStep {
					mine = mine || d.DecidedBy == p.UserID
					if d.Decision == "APPROVE" {
						received++
					}
				}
			}
			if mine {
				continue
			}
			out = append(out, WorkflowTask{InstanceID: w.ID, Definition: w.DefinitionKey, SubjectType: w.SubjectType, SubjectID: w.SubjectID,
				Label: w.Facts.Label, Amount: w.Facts.Amount, Currency: w.Facts.Currency, Step: step.ID, StepTitle: step.Title,
				Approvals: step.Approvals, Received: received, RequireMFA: step.RequireMFA, SLADueAt: w.SLADueAt, ExpiresAt: w.ExpiresAt,
				Overdue: w.SLADueAt != nil && !w.SLADueAt.After(now), Escalated: w.EscalatedAt != nil,
				FailedTries: w.EffectFailures, LastError: w.LastError, WaitingSince: w.StepStartedAt})
		}
		return nil
	})
	return out, err
}

// InstanceDetail is the console view of one instance.
type InstanceDetail struct {
	Instance  postgres.WorkflowInstance       `json:"instance"`
	Decisions []postgres.WorkflowDecision     `json:"decisions"`
	History   []postgres.WorkflowHistoryEntry `json:"history"`
}

// GetWorkflowInstance returns an instance with its decisions and history.
func (s *Service) GetWorkflowInstance(ctx context.Context, p auth.Principal, id string) (InstanceDetail, error) {
	if err := s.authz.Require(p, auth.PermWorkflowRead, p.TenantID); err != nil {
		return InstanceDetail{}, err
	}
	var out InstanceDetail
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		if out.Instance, err = postgres.GetWorkflowInstance(ctx, tx, id, false); err != nil {
			return err
		}
		if err := s.requireSubjectAccess(p, auth.PermWorkflowRead, out.Instance.Facts); err != nil {
			return ErrNotFound // never reveal out-of-scope instances
		}
		if out.Decisions, err = postgres.WorkflowDecisions(ctx, tx, id); err != nil {
			return err
		}
		out.History, err = postgres.WorkflowHistory(ctx, tx, id)
		return err
	})
	return out, err
}

// ListWorkflowInstances lists instances visible to the principal.
func (s *Service) ListWorkflowInstances(ctx context.Context, p auth.Principal, f postgres.InstanceFilter) ([]postgres.WorkflowInstance, error) {
	if err := s.authz.Require(p, auth.PermWorkflowRead, p.TenantID); err != nil {
		return nil, err
	}
	var out []postgres.WorkflowInstance
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		all, err := postgres.ListWorkflowInstances(ctx, tx, f)
		if err != nil {
			return err
		}
		for _, w := range all {
			if s.requireSubjectAccess(p, auth.PermWorkflowRead, w.Facts) == nil {
				out = append(out, w)
			}
		}
		return nil
	})
	return out, err
}

// WorkflowMetrics returns console metrics. Tenant-wide figures, so they
// require tenant-wide scope.
func (s *Service) WorkflowMetrics(ctx context.Context, p auth.Principal, since time.Time) (postgres.WorkflowMetrics, error) {
	if err := s.authz.RequireProject(p, auth.PermWorkflowRead, p.TenantID, ""); err != nil {
		return postgres.WorkflowMetrics{}, err
	}
	var out postgres.WorkflowMetrics
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.QueryWorkflowMetrics(ctx, tx, since)
		return err
	})
	return out, err
}

// TenantLister yields tenants with due timers (postgres.DueWorkflowTenants
// on the scheduler login).
type TenantLister func(ctx context.Context) ([]string, error)

// RunDueWorkflowTimers runs one timer pass for every tenant with due work.
// A failing tenant does not stop the others; the first error is returned.
func (s *Service) RunDueWorkflowTimers(ctx context.Context, due TenantLister) (TimerResult, error) {
	tenants, err := due(ctx)
	if err != nil {
		return TimerResult{}, err
	}
	var total TimerResult
	var first error
	for _, t := range tenants {
		r, err := s.RunWorkflowTimers(ctx, t, 100)
		total.Escalated += r.Escalated
		total.Expired += r.Expired
		if err != nil && first == nil {
			first = fmt.Errorf("tenant %s: %w", t, err)
		}
	}
	return total, first
}
