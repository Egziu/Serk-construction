package kernel

// Project schedules (migration 0027, ADR 0013, GATED-02): a planner records
// a schedule version (calendar, activities, links); the kernel computes the
// critical path (pkg/schedule) and stores the dates; on submission the
// database re-verifies the computation from local equations; a project
// manager (different person, human) approves it as the BASELINE. Progress
// reports (percent complete, actual dates) are approved the same way, and
// earned value is read from the database (schedule_evm).

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/schedule"
)

// ScheduleActivity is an activity of a schedule version.
type ScheduleActivity struct {
	Code       string          `json:"code"`
	Name       string          `json:"name"`
	Duration   int             `json:"duration"`
	CostCodeID string          `json:"cost_code_id,omitempty"`
	Budget     decimal.Decimal `json:"budget"`
}

// ScheduleLink is a precedence relation between two activities.
type ScheduleLink struct {
	Pred string `json:"pred"`
	Succ string `json:"succ"`
	Type string `json:"type"`
	Lag  int    `json:"lag"`
}

// ScheduleInput is a schedule version to compute.
type ScheduleInput struct {
	ProjectID      string             `json:"project_id"`
	Description    string             `json:"description"`
	StartDate      time.Time          `json:"-"`
	Weekdays       []int              `json:"working_weekdays"` // 0 = Sunday
	Holidays       []time.Time        `json:"-"`
	RequiredFinish *time.Time         `json:"-"`
	Activities     []ScheduleActivity `json:"activities"`
	Links          []ScheduleLink     `json:"links"`
}

func scheduleCalendar(in ScheduleInput) schedule.Calendar {
	c := schedule.Calendar{Start: in.StartDate.UTC().Truncate(24 * time.Hour), Weekdays: map[time.Weekday]bool{}, Holidays: map[string]bool{}}
	for _, w := range in.Weekdays {
		c.Weekdays[time.Weekday(w)] = true
	}
	for _, h := range in.Holidays {
		c.Holidays[h.UTC().Format("2006-01-02")] = true
	}
	return c
}

// CreateSchedule records a DRAFT schedule version with its computed critical path.
func (s *Service) CreateSchedule(ctx context.Context, p auth.Principal, in ScheduleInput) (string, error) {
	if err := s.authz.RequireProject(p, auth.PermScheduleManage, p.TenantID, in.ProjectID); err != nil {
		return "", err
	}
	for _, w := range in.Weekdays {
		if w < 0 || w > 6 {
			return "", fmt.Errorf("%w: working weekdays are 0 (Sunday) to 6", ErrInvalidInput)
		}
	}
	cal := scheduleCalendar(in)
	if err := cal.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	acts := make([]schedule.Activity, 0, len(in.Activities))
	for _, a := range in.Activities {
		acts = append(acts, schedule.Activity{ID: strings.ToUpper(strings.TrimSpace(a.Code)), Duration: a.Duration})
	}
	links := make([]schedule.Link, 0, len(in.Links))
	for _, l := range in.Links {
		links = append(links, schedule.Link{Pred: strings.ToUpper(strings.TrimSpace(l.Pred)), Succ: strings.ToUpper(strings.TrimSpace(l.Succ)),
			Type: schedule.LinkType(strings.ToUpper(l.Type)), Lag: l.Lag})
	}
	net, err := schedule.NewNetwork(acts, links)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	required := -1
	if in.RequiredFinish != nil {
		required = cal.Offset(in.RequiredFinish.UTC()) + 1
	}
	results, finish, err := net.Compute(required)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	var id string
	err = s.p2pTx(ctx, p, auth.PermScheduleManage, func(ctx context.Context, tx pgx.Tx) error {
		wd := make([]int16, 0, len(in.Weekdays))
		for _, w := range in.Weekdays {
			wd = append(wd, int16(w))
		}
		sort.Slice(wd, func(i, j int) bool { return wd[i] < wd[j] })
		hol := make([]time.Time, 0, len(in.Holidays))
		for _, h := range in.Holidays {
			hol = append(hol, h.UTC().Truncate(24*time.Hour))
		}
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO schedule_versions(legal_entity_id, project_id, version, description, start_date, working_weekdays,
			holidays, required_finish, created_by)
			SELECT pr.legal_entity_id, pr.id, 1, $2, $3, $4, $5, $6, $7 FROM projects pr WHERE pr.id = $1::uuid RETURNING id::text`,
			in.ProjectID, strings.TrimSpace(in.Description), cal.Start, wd, hol, in.RequiredFinish, p.UserID)
		if err != nil {
			return mapNoRows(err)
		}
		for _, a := range in.Activities {
			var cc *string
			if a.CostCodeID != "" {
				cc = &a.CostCodeID
			}
			if _, err := tx.Exec(ctx, `INSERT INTO schedule_activities(version_id, code, name, duration, cost_code_id, budget) VALUES ($1::uuid, $2, $3, $4, $5::uuid, $6)`,
				id, strings.ToUpper(strings.TrimSpace(a.Code)), strings.TrimSpace(a.Name), a.Duration, cc, a.Budget); err != nil {
				return err
			}
		}
		for _, l := range links {
			if _, err := tx.Exec(ctx, `INSERT INTO schedule_links(version_id, pred_code, succ_code, link_type, lag) VALUES ($1::uuid, $2, $3, $4, $5)`,
				id, l.Pred, l.Succ, string(l.Type), l.Lag); err != nil {
				return err
			}
		}
		for _, r := range results {
			// Late dates before the project start (negative float against a
			// required finish) have no calendar date.
			var lateStart, lateFinish *time.Time
			if r.LS >= 0 {
				ls, lf := cal.Date(r.LS), cal.FinishDate(r.LS, r.LF)
				lateStart, lateFinish = &ls, &lf
			}
			ef := cal.FinishDate(r.ES, r.EF)
			if err := postgres.Exec1(ctx, tx, `UPDATE schedule_activities SET es = $3, ef = $4, ls = $5, lf = $6, total_float = $7, free_float = $8, critical = $9,
				early_start = $10, early_finish = $11, late_start = $12, late_finish = $13 WHERE version_id = $1::uuid AND code = $2`,
				id, r.ID, r.ES, r.EF, r.LS, r.LF, r.TotalFloat, r.FreeFloat, r.Critical, cal.Date(r.ES), ef, lateStart, lateFinish); err != nil {
				return err
			}
		}
		finishDate := cal.Date(0)
		if finish > 0 {
			finishDate = cal.Date(finish - 1)
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE schedule_versions SET finish_offset = $2, finish_date = $3, algorithm = $4 WHERE id = $1::uuid`,
			id, finish, finishDate, schedule.AlgorithmVersion); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "schedule.create", "schedule_version", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "schedule.create", "schedule_version", id, "schedule.created",
			map[string]any{"schedule_version_id": id, "project_id": in.ProjectID, "finish": finishDate.Format("2006-01-02"), "algorithm": schedule.AlgorithmVersion})
	})
	return id, err
}

// SubmitSchedule submits the author's DRAFT schedule; the database verifies the critical path.
func (s *Service) SubmitSchedule(ctx context.Context, p auth.Principal, id string) error {
	return s.submitDoc(ctx, p, auth.PermScheduleManage, "schedule_version", "schedule_versions", id, "schedule.submit", "schedule.submitted")
}

// DecideSchedule approves a submitted schedule as the project's BASELINE
// (superseding the previous one) or rejects it with a reason.
func (s *Service) DecideSchedule(ctx context.Context, p auth.Principal, id string, approve bool, reason string) error {
	if !approve {
		if err := requireReason(reason); err != nil {
			return err
		}
	}
	return s.p2pTx(ctx, p, auth.PermScheduleApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermScheduleApprove, "schedule_version", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "SUBMITTED"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "schedule"); err != nil {
			return err
		}
		action, next := "schedule.approve", "BASELINE"
		if !approve {
			action, next = "schedule.reject", "REJECTED"
		}
		if err := s.authorize(ctx, tx, p, action, "schedule_version", id, next); err != nil {
			return err
		}
		if approve {
			err = postgres.Exec1(ctx, tx, `UPDATE schedule_versions SET status = 'BASELINE', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID)
		} else {
			err = postgres.Exec1(ctx, tx, `UPDATE schedule_versions SET status = 'REJECTED', decision_reason = $2 WHERE id = $1::uuid`, id, strings.TrimSpace(reason))
		}
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, action, "schedule_version", id, "schedule."+strings.ToLower(next), map[string]any{"schedule_version_id": id})
	})
}

// ProgressLine is the reported state of one activity.
type ProgressLine struct {
	ActivityCode    string          `json:"activity_code"`
	PercentComplete decimal.Decimal `json:"percent_complete"`
	ActualStart     *time.Time      `json:"-"`
	ActualFinish    *time.Time      `json:"-"`
}

// RecordProgress records a DRAFT progress report against the project's baseline.
func (s *Service) RecordProgress(ctx context.Context, p auth.Principal, projectID string, statusDate time.Time, lines []ProgressLine) (string, error) {
	if err := s.authz.RequireProject(p, auth.PermScheduleManage, p.TenantID, projectID); err != nil {
		return "", err
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("%w: a progress report has at least one activity", ErrInvalidInput)
	}
	var id string
	err := s.p2pTx(ctx, p, auth.PermScheduleManage, func(ctx context.Context, tx pgx.Tx) error {
		var version string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM schedule_versions WHERE project_id = $1::uuid AND status = 'BASELINE'`, projectID).Scan(&version); err != nil {
			return mapNoRows(err)
		}
		num, err := postgres.NextNumber(ctx, tx, "PRG")
		if err != nil {
			return err
		}
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO schedule_progress(version_id, project_id, number, status_date, created_by)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5) RETURNING id::text`, version, projectID, num, statusDate, p.UserID)
		if err != nil {
			return err
		}
		for _, l := range lines {
			if _, err := tx.Exec(ctx, `INSERT INTO schedule_progress_lines(progress_id, version_id, activity_code, percent_complete, actual_start, actual_finish)
				VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6)`, id, version, strings.ToUpper(strings.TrimSpace(l.ActivityCode)), l.PercentComplete, l.ActualStart, l.ActualFinish); err != nil {
				return err
			}
		}
		if err := s.authorize(ctx, tx, p, "schedule.progress.create", "schedule_progress", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "schedule.progress.create", "schedule_progress", id, "schedule.progress_recorded",
			map[string]any{"schedule_progress_id": id, "status_date": statusDate.Format("2006-01-02")})
	})
	return id, err
}

// DecideProgress approves (or rejects with a reason) a DRAFT progress report.
func (s *Service) DecideProgress(ctx context.Context, p auth.Principal, id string, approve bool, reason string) error {
	if !approve {
		if err := requireReason(reason); err != nil {
			return err
		}
	}
	return s.p2pTx(ctx, p, auth.PermScheduleApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermScheduleApprove, "schedule_progress", id)
		if err != nil {
			return err
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "progress report"); err != nil {
			return err
		}
		action, next := "schedule.progress.approve", "APPROVED"
		if !approve {
			action, next = "schedule.progress.reject", "REJECTED"
		}
		if err := s.authorize(ctx, tx, p, action, "schedule_progress", id, next); err != nil {
			return err
		}
		if approve {
			err = postgres.Exec1(ctx, tx, `UPDATE schedule_progress SET status = 'APPROVED', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID)
		} else {
			err = postgres.Exec1(ctx, tx, `UPDATE schedule_progress SET status = 'REJECTED', decision_reason = $2 WHERE id = $1::uuid`, id, strings.TrimSpace(reason))
		}
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, action, "schedule_progress", id, "schedule.progress_"+strings.ToLower(next), map[string]any{"schedule_progress_id": id})
	})
}

// ScheduleEVM reports earned value of a project's baseline at a status date.
func (s *Service) ScheduleEVM(ctx context.Context, p auth.Principal, projectID string, statusDate time.Time) (postgres.EVMReport, error) {
	if err := s.authz.RequireProject(p, auth.PermP2PRead, p.TenantID, projectID); err != nil {
		return postgres.EVMReport{}, err
	}
	var out postgres.EVMReport
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		out, err = postgres.ScheduleEVM(ctx, tx, projectID, statusDate)
		return err
	})
	return out, err
}
