package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// WorkflowDefinitionRow is a stored workflow definition version.
type WorkflowDefinitionRow struct {
	ID, TenantID, Key, Subject, Status    string
	Version                               int
	Mandatory                             bool
	Body                                  json.RawMessage
	BodyHash                              string
	ProposedBy, DecidedBy, DecisionReason string
	ProposedAt                            time.Time
	DecidedAt                             *time.Time
}

const wfDefCols = `id::text, tenant_id::text, key, subject, status, version, mandatory, body, body_hash, proposed_by,
	COALESCE(decided_by,''), COALESCE(decision_reason,''), proposed_at, decided_at`

func scanWFDef(row pgx.Row) (WorkflowDefinitionRow, error) {
	var d WorkflowDefinitionRow
	err := row.Scan(&d.ID, &d.TenantID, &d.Key, &d.Subject, &d.Status, &d.Version, &d.Mandatory, &d.Body, &d.BodyHash,
		&d.ProposedBy, &d.DecidedBy, &d.DecisionReason, &d.ProposedAt, &d.DecidedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

// InsertWorkflowDefinition stores a DRAFT definition as the next version of its key.
func InsertWorkflowDefinition(ctx context.Context, tx pgx.Tx, d WorkflowDefinitionRow) (WorkflowDefinitionRow, error) {
	// Serialize version numbering per key.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('wfdef:' || $1 || ':' || $2, 0))`, d.TenantID, d.Key); err != nil {
		return d, err
	}
	return scanWFDef(tx.QueryRow(ctx, `INSERT INTO workflow_definitions(id,tenant_id,key,version,subject,mandatory,body,body_hash,proposed_by)
		VALUES ($1::uuid,$2::uuid,$3,(SELECT COALESCE(MAX(version),0)+1 FROM workflow_definitions WHERE tenant_id=$2::uuid AND key=$3),
		        $4,$5,$6::jsonb,$7,$8)
		RETURNING `+wfDefCols, newID(), d.TenantID, d.Key, d.Subject, d.Mandatory, string(d.Body), d.BodyHash, d.ProposedBy))
}

// GetWorkflowDefinition loads a definition by id.
func GetWorkflowDefinition(ctx context.Context, tx pgx.Tx, id string, forUpdate bool) (WorkflowDefinitionRow, error) {
	q := `SELECT ` + wfDefCols + ` FROM workflow_definitions WHERE id=$1::uuid`
	if forUpdate {
		q += ` FOR UPDATE`
	}
	return scanWFDef(tx.QueryRow(ctx, q, id))
}

// PublishedWorkflowDefinition returns the published version of a key.
func PublishedWorkflowDefinition(ctx context.Context, tx pgx.Tx, key string) (WorkflowDefinitionRow, error) {
	return scanWFDef(tx.QueryRow(ctx, `SELECT `+wfDefCols+` FROM workflow_definitions WHERE key=$1 AND status='PUBLISHED' FOR SHARE`, key))
}

// MandatoryWorkflowFor returns the published mandatory definition for a subject type, if any.
func MandatoryWorkflowFor(ctx context.Context, tx pgx.Tx, subject string) (WorkflowDefinitionRow, bool, error) {
	d, err := scanWFDef(tx.QueryRow(ctx, `SELECT `+wfDefCols+` FROM workflow_definitions WHERE subject=$1 AND status='PUBLISHED' AND mandatory`, subject))
	if errors.Is(err, ErrNotFound) {
		return d, false, nil
	}
	return d, err == nil, err
}

// DecideWorkflowDefinition publishes or rejects a DRAFT definition.
func DecideWorkflowDefinition(ctx context.Context, tx pgx.Tx, id, status, by, reason string) error {
	ct, err := tx.Exec(ctx, `UPDATE workflow_definitions SET status=$2, decided_by=$3, decision_reason=NULLIF($4,'') WHERE id=$1::uuid AND status='DRAFT'`,
		id, status, by, reason)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	return nil
}

// ListWorkflowDefinitions lists definitions, newest first.
func ListWorkflowDefinitions(ctx context.Context, tx pgx.Tx) ([]WorkflowDefinitionRow, error) {
	rows, err := tx.Query(ctx, `SELECT `+wfDefCols+` FROM workflow_definitions ORDER BY key, version DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WorkflowDefinitionRow
	for rows.Next() {
		d, err := scanWFDef(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RouteStepRow is one step of an instance route as frozen at start.
type RouteStepRow struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Permission    string   `json:"permission"`
	Approvals     int      `json:"approvals"`
	DistinctFrom  []string `json:"distinct_from"`
	RequireMFA    bool     `json:"require_mfa"`
	Effect        string   `json:"effect,omitempty"`
	SLASeconds    int64    `json:"sla_seconds,omitempty"`
	ExpireSeconds int64    `json:"expire_seconds,omitempty"`
	EscalateTo    string   `json:"escalate_to,omitempty"`
	Reason        string   `json:"reason"`
}

// InstanceFacts are the routing inputs and subject fingerprint.
type InstanceFacts struct {
	Amount      string `json:"amount,omitempty"`
	Currency    string `json:"currency,omitempty"`
	ProjectID   string `json:"project_id,omitempty"`
	CreatedBy   string `json:"created_by"`
	Fingerprint string `json:"fingerprint"`
	Label       string `json:"label,omitempty"`
}

// WorkflowInstance is a running or finished instance.
type WorkflowInstance struct {
	ID, TenantID, DefinitionID, DefinitionKey string
	DefinitionVersion                         int
	SubjectType, SubjectID, Status            string
	Facts                                     InstanceFacts
	Route                                     []RouteStepRow
	CurrentStep                               int
	InitiatedBy                               string
	StartedAt, StepStartedAt                  time.Time
	SLADueAt, ExpiresAt, EscalatedAt, EndedAt *time.Time
	EndedBy, EndReason, LastError             string
	EffectFailures, Version                   int
}

// OpenStep returns the step awaiting decisions, if any.
func (w WorkflowInstance) OpenStep() (RouteStepRow, bool) {
	if w.Status != "ACTIVE" || w.CurrentStep >= len(w.Route) {
		return RouteStepRow{}, false
	}
	return w.Route[w.CurrentStep], true
}

const wfInstCols = `i.id::text, i.tenant_id::text, i.definition_id::text, d.key, d.version, i.subject_type, i.subject_id::text, i.status,
	i.facts, i.route, i.current_step, i.initiated_by, i.started_at, i.step_started_at, i.sla_due_at, i.expires_at, i.escalated_at,
	i.ended_at, COALESCE(i.ended_by,''), COALESCE(i.end_reason,''), COALESCE(i.last_error,''), i.effect_failures, i.version`

func scanWFInst(row pgx.Row) (WorkflowInstance, error) {
	var w WorkflowInstance
	var facts, route []byte
	err := row.Scan(&w.ID, &w.TenantID, &w.DefinitionID, &w.DefinitionKey, &w.DefinitionVersion, &w.SubjectType, &w.SubjectID, &w.Status,
		&facts, &route, &w.CurrentStep, &w.InitiatedBy, &w.StartedAt, &w.StepStartedAt, &w.SLADueAt, &w.ExpiresAt, &w.EscalatedAt,
		&w.EndedAt, &w.EndedBy, &w.EndReason, &w.LastError, &w.EffectFailures, &w.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return w, ErrNotFound
	}
	if err != nil {
		return w, err
	}
	if err := json.Unmarshal(facts, &w.Facts); err != nil {
		return w, err
	}
	return w, json.Unmarshal(route, &w.Route)
}

// InsertWorkflowInstance starts an instance. The database derives deadlines
// and refuses a second ACTIVE instance for the same subject.
func InsertWorkflowInstance(ctx context.Context, tx pgx.Tx, w WorkflowInstance) (WorkflowInstance, error) {
	facts, err := json.Marshal(w.Facts)
	if err != nil {
		return w, err
	}
	route, err := json.Marshal(w.Route)
	if err != nil {
		return w, err
	}
	id := newID()
	if _, err := tx.Exec(ctx, `INSERT INTO workflow_instances(id,tenant_id,definition_id,subject_type,subject_id,facts,route,initiated_by)
		VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5::uuid,$6::jsonb,$7::jsonb,$8)`,
		id, w.TenantID, w.DefinitionID, w.SubjectType, w.SubjectID, string(facts), string(route), w.InitiatedBy); err != nil {
		return w, err
	}
	return GetWorkflowInstance(ctx, tx, id, false)
}

// GetWorkflowInstance loads an instance; forUpdate locks it.
func GetWorkflowInstance(ctx context.Context, tx pgx.Tx, id string, forUpdate bool) (WorkflowInstance, error) {
	q := `SELECT ` + wfInstCols + ` FROM workflow_instances i JOIN workflow_definitions d ON d.id=i.definition_id WHERE i.id=$1::uuid`
	if forUpdate {
		q += ` FOR UPDATE OF i`
	}
	return scanWFInst(tx.QueryRow(ctx, q, id))
}

// InstanceFilter selects instances for the console.
type InstanceFilter struct {
	Status      string // "" = any
	SubjectType string
	SubjectID   string
	Overdue     bool
	Limit       int
}

// ListWorkflowInstances lists instances newest first.
func ListWorkflowInstances(ctx context.Context, tx pgx.Tx, f InstanceFilter) ([]WorkflowInstance, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	rows, err := tx.Query(ctx, `SELECT `+wfInstCols+` FROM workflow_instances i JOIN workflow_definitions d ON d.id=i.definition_id
		WHERE ($1='' OR i.status=$1) AND ($2='' OR i.subject_type=$2) AND ($3='' OR i.subject_id::text=$3)
		  AND (NOT $4 OR (i.status='ACTIVE' AND i.sla_due_at <= now()))
		ORDER BY i.started_at DESC LIMIT $5`, f.Status, f.SubjectType, f.SubjectID, f.Overdue, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WorkflowInstance
	for rows.Next() {
		w, err := scanWFInst(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// WorkflowDecision is one recorded decision.
type WorkflowDecision struct {
	StepIndex int       `json:"step_index"`
	StepID    string    `json:"step_id"`
	DecidedBy string    `json:"decided_by"`
	Decision  string    `json:"decision"`
	Reason    string    `json:"reason,omitempty"`
	MFA       bool      `json:"mfa"`
	DecidedAt time.Time `json:"decided_at"`
}

// InsertWorkflowDecision records a decision on the open step.
func InsertWorkflowDecision(ctx context.Context, tx pgx.Tx, tenantID, instanceID string, d WorkflowDecision) error {
	_, err := tx.Exec(ctx, `INSERT INTO workflow_decisions(tenant_id,instance_id,step_index,step_id,decided_by,decision,reason,mfa)
		VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,NULLIF($7,''),$8)`, tenantID, instanceID, d.StepIndex, d.StepID, d.DecidedBy, d.Decision, d.Reason, d.MFA)
	return err
}

// WorkflowDecisions lists an instance's decisions in order.
func WorkflowDecisions(ctx context.Context, tx pgx.Tx, instanceID string) ([]WorkflowDecision, error) {
	rows, err := tx.Query(ctx, `SELECT step_index, step_id, decided_by, decision, COALESCE(reason,''), mfa, decided_at
		FROM workflow_decisions WHERE instance_id=$1::uuid ORDER BY decided_at, id`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WorkflowDecision
	for rows.Next() {
		var d WorkflowDecision
		if err := rows.Scan(&d.StepIndex, &d.StepID, &d.DecidedBy, &d.Decision, &d.Reason, &d.MFA, &d.DecidedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// InsertWorkflowEffect records that the open step's effect is executing in
// this transaction (the subject gate checks for it).
func InsertWorkflowEffect(ctx context.Context, tx pgx.Tx, w WorkflowInstance, action, by string) error {
	_, err := tx.Exec(ctx, `INSERT INTO workflow_effects(tenant_id,instance_id,step_index,action,subject_type,subject_id,executed_by)
		VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6::uuid,$7)`, w.TenantID, w.ID, w.CurrentStep, action, w.SubjectType, w.SubjectID, by)
	return err
}

// AdvanceWorkflow moves past the open step; completes the instance after the last one.
func AdvanceWorkflow(ctx context.Context, tx pgx.Tx, w WorkflowInstance) (completed bool, err error) {
	next := w.CurrentStep + 1
	status := "ACTIVE"
	if next >= len(w.Route) {
		status = "COMPLETED"
	}
	ct, err := tx.Exec(ctx, `UPDATE workflow_instances SET current_step=$2, status=$3 WHERE id=$1::uuid AND version=$4`, w.ID, next, status, w.Version)
	if err != nil {
		return false, err
	}
	if ct.RowsAffected() == 0 {
		return false, ErrVersionConflict
	}
	return status == "COMPLETED", nil
}

// EndWorkflow moves an ACTIVE instance to a final state.
func EndWorkflow(ctx context.Context, tx pgx.Tx, w WorkflowInstance, status, by, reason string) error {
	ct, err := tx.Exec(ctx, `UPDATE workflow_instances SET status=$2, ended_by=NULLIF($3,''), end_reason=NULLIF($4,'')
		WHERE id=$1::uuid AND version=$5 AND status='ACTIVE'`, w.ID, status, by, reason, w.Version)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	return nil
}

// MarkWorkflowEscalated records the one-time SLA escalation of the open step.
func MarkWorkflowEscalated(ctx context.Context, tx pgx.Tx, w WorkflowInstance) error {
	ct, err := tx.Exec(ctx, `UPDATE workflow_instances SET escalated_at=now() WHERE id=$1::uuid AND version=$2`, w.ID, w.Version)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	return nil
}

// RecordWorkflowEffectFailure counts a failed effect attempt (separate transaction).
func RecordWorkflowEffectFailure(ctx context.Context, tx pgx.Tx, instanceID, msg string) error {
	if len(msg) > 500 {
		msg = msg[:500]
	}
	_, err := tx.Exec(ctx, `UPDATE workflow_instances SET effect_failures=effect_failures+1, last_error=$2 WHERE id=$1::uuid AND status='ACTIVE'`, instanceID, msg)
	return err
}

// WorkflowHistoryEntry is one history event.
type WorkflowHistoryEntry struct {
	At        time.Time      `json:"at"`
	Kind      string         `json:"kind"`
	Actor     string         `json:"actor"`
	StepIndex *int           `json:"step_index,omitempty"`
	Detail    map[string]any `json:"detail,omitempty"`
}

// AppendWorkflowHistory appends a history event.
func AppendWorkflowHistory(ctx context.Context, tx pgx.Tx, tenantID, instanceID string, e WorkflowHistoryEntry) error {
	detail, err := json.Marshal(e.Detail)
	if err != nil {
		return err
	}
	if e.Detail == nil {
		detail = []byte("{}")
	}
	_, err = tx.Exec(ctx, `INSERT INTO workflow_history(tenant_id,instance_id,kind,actor,step_index,detail) VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6::jsonb)`,
		tenantID, instanceID, e.Kind, e.Actor, e.StepIndex, string(detail))
	return err
}

// WorkflowHistory lists an instance's history in order.
func WorkflowHistory(ctx context.Context, tx pgx.Tx, instanceID string) ([]WorkflowHistoryEntry, error) {
	rows, err := tx.Query(ctx, `SELECT at, kind, actor, step_index, detail FROM workflow_history WHERE instance_id=$1::uuid ORDER BY id`, instanceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WorkflowHistoryEntry
	for rows.Next() {
		var e WorkflowHistoryEntry
		var detail []byte
		if err := rows.Scan(&e.At, &e.Kind, &e.Actor, &e.StepIndex, &detail); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(detail, &e.Detail); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DueWorkflowInstances locks ACTIVE instances whose SLA or expiry has passed
// (by database time). SKIP LOCKED lets several workers share the queue and
// keeps a worker from waiting on an instance a human is deciding right now.
func DueWorkflowInstances(ctx context.Context, tx pgx.Tx, limit int) ([]WorkflowInstance, error) {
	rows, err := tx.Query(ctx, `SELECT `+wfInstCols+` FROM workflow_instances i JOIN workflow_definitions d ON d.id=i.definition_id
		WHERE i.status='ACTIVE' AND ((i.expires_at <= now()) OR (i.sla_due_at <= now() AND i.escalated_at IS NULL))
		ORDER BY LEAST(i.sla_due_at, i.expires_at) LIMIT $1 FOR UPDATE OF i SKIP LOCKED`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WorkflowInstance
	for rows.Next() {
		w, err := scanWFInst(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// WorkflowMetrics are console metrics over a window.
type WorkflowMetrics struct {
	Started          int      `json:"started"`
	Active           int      `json:"active"`
	Completed        int      `json:"completed"`
	Rejected         int      `json:"rejected"`
	Expired          int      `json:"expired"`
	Cancelled        int      `json:"cancelled"`
	Overdue          int      `json:"overdue"`
	WithFailures     int      `json:"with_effect_failures"`
	Escalated        int      `json:"escalated"`
	AvgCycleSeconds  *float64 `json:"avg_cycle_seconds,omitempty"`
	P90CycleSeconds  *float64 `json:"p90_cycle_seconds,omitempty"`
	FirstPassRate    *float64 `json:"first_pass_rate,omitempty"`
	ExceptionRate    *float64 `json:"exception_rate,omitempty"`
	DecisionsPerItem *float64 `json:"decisions_per_completed,omitempty"`
}

// QueryWorkflowMetrics computes metrics for instances started since `since`.
//
// first_pass_rate: completed with no effect failure and no escalation ÷ ended.
// exception_rate: instances with an effect failure, escalation or expiry ÷ started.
// "Touchless" in the automation sense does not exist here by design — every
// sensitive step has a human decision.
func QueryWorkflowMetrics(ctx context.Context, tx pgx.Tx, since time.Time) (WorkflowMetrics, error) {
	var m WorkflowMetrics
	err := tx.QueryRow(ctx, `WITH w AS (SELECT * FROM workflow_instances WHERE started_at >= $1),
		ended AS (SELECT * FROM w WHERE status <> 'ACTIVE'),
		hist AS (SELECT DISTINCT instance_id FROM workflow_history h WHERE kind='ESCALATED' AND h.instance_id IN (SELECT id FROM w))
		SELECT (SELECT COUNT(*) FROM w),
		       (SELECT COUNT(*) FROM w WHERE status='ACTIVE'),
		       (SELECT COUNT(*) FROM w WHERE status='COMPLETED'),
		       (SELECT COUNT(*) FROM w WHERE status='REJECTED'),
		       (SELECT COUNT(*) FROM w WHERE status='EXPIRED'),
		       (SELECT COUNT(*) FROM w WHERE status='CANCELLED'),
		       (SELECT COUNT(*) FROM w WHERE status='ACTIVE' AND sla_due_at <= now()),
		       (SELECT COUNT(*) FROM w WHERE effect_failures > 0),
		       (SELECT COUNT(*) FROM hist),
		       (SELECT AVG(EXTRACT(EPOCH FROM ended_at - started_at))::float8 FROM w WHERE status='COMPLETED'),
		       (SELECT percentile_cont(0.9) WITHIN GROUP (ORDER BY EXTRACT(EPOCH FROM ended_at - started_at))::float8 FROM w WHERE status='COMPLETED'),
		       (SELECT CASE WHEN COUNT(*)=0 THEN NULL ELSE
		          (COUNT(*) FILTER (WHERE status='COMPLETED' AND effect_failures=0 AND id NOT IN (SELECT instance_id FROM hist)))::float8 / COUNT(*) END FROM ended),
		       (SELECT CASE WHEN COUNT(*)=0 THEN NULL ELSE
		          (COUNT(*) FILTER (WHERE effect_failures > 0 OR status='EXPIRED' OR id IN (SELECT instance_id FROM hist)))::float8 / COUNT(*) END FROM w),
		       (SELECT CASE WHEN COUNT(*)=0 THEN NULL ELSE
		          (SELECT COUNT(*) FROM workflow_decisions dd WHERE dd.instance_id IN (SELECT id FROM w WHERE status='COMPLETED'))::float8 / COUNT(*) END
		          FROM w WHERE status='COMPLETED')`, since).
		Scan(&m.Started, &m.Active, &m.Completed, &m.Rejected, &m.Expired, &m.Cancelled, &m.Overdue, &m.WithFailures, &m.Escalated,
			&m.AvgCycleSeconds, &m.P90CycleSeconds, &m.FirstPassRate, &m.ExceptionRate, &m.DecisionsPerItem)
	return m, err
}
