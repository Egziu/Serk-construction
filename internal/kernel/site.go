package kernel

// Site operations and offline field capture (migration 0037, GATED-01, ADR 0017).
//
// A site engineer keeps a daily diary per project (weather, notes, labour
// and equipment hours). It can be prepared on a registered field device
// while offline and synchronised later, or entered online. The device
// prepares commands; the server validates, records and attests them; a
// project manager (another person, a human) approves the submitted diary.
// Nothing here creates financial state (LAW 05).
//
// Offline rules:
//   - A device is registered by its owner with fresh MFA and receives a
//     secret once; only its SHA-256 is stored. Every sync needs both the
//     person's bearer token and the device secret.
//   - A revoked device never syncs again, including commands it queued
//     before the revocation (they are refused when they arrive).
//   - (device, client op id) is unique: a retried command is answered from
//     the command log and never applied twice; a retry with a different
//     payload is refused. The device sequence only moves forward.
//   - A revision states the version it was based on; if the server has a
//     newer version, or the diary has left DRAFT, the command is a CONFLICT
//     and nothing is merged. The client re-bases and sends a new command.
//   - The device clock is evidence (client_time, kept), never authority:
//     the server's date bounds the diary date.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// ErrDeviceRefused is returned when a sync names an unknown, foreign or
// revoked device, or the device secret does not match. The reason is
// audited, not returned.
var ErrDeviceRefused = errors.New("kernel: field device refused")

var canonicalUUIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// DiaryLabour is a labour line: a trade, its headcount and person-hours.
type DiaryLabour struct {
	Trade     string          `json:"trade"`
	Headcount int             `json:"headcount"`
	Hours     decimal.Decimal `json:"hours"`
}

// DiaryEquipment is an equipment line: hours worked and idle in the day.
type DiaryEquipment struct {
	Description string          `json:"description"`
	Hours       decimal.Decimal `json:"hours"`
	IdleHours   decimal.Decimal `json:"idle_hours"`
}

// DiaryInput is a diary to create (BaseVersion 0) or revise (BaseVersion =
// the version the change was based on).
type DiaryInput struct {
	ClientRef   string           `json:"client_ref"`
	ProjectID   string           `json:"project_id"`
	DiaryDate   time.Time        `json:"-"`
	Weather     string           `json:"weather"`
	Notes       string           `json:"notes"`
	Labour      []DiaryLabour    `json:"labour"`
	Equipment   []DiaryEquipment `json:"equipment"`
	BaseVersion int              `json:"base_version"`
}

// DiaryResult describes a diary after a command.
type DiaryResult struct {
	ID      string `json:"id"`
	Number  string `json:"number"`
	Version int    `json:"version"`
	Status  string `json:"status"`
}

// DiaryConflict is the server's state when a command was based on an older
// version (or the diary has left DRAFT).
type DiaryConflict struct {
	DiaryResult
	BaseVersion int `json:"base_version"`
}

func (c *DiaryConflict) Error() string {
	return fmt.Sprintf("diary %s is at version %d (%s); the change was based on version %d", c.Number, c.Version, c.Status, c.BaseVersion)
}

func validDiary(in DiaryInput) error {
	bad := func(msg string) error { return fmt.Errorf("%w: %s", ErrInvalidInput, msg) }
	if !canonicalUUIDRe.MatchString(in.ClientRef) || !canonicalUUIDRe.MatchString(in.ProjectID) {
		return bad("client_ref and project_id are canonical UUIDs")
	}
	if in.DiaryDate.IsZero() {
		return bad("diary_date is required")
	}
	if w := strings.TrimSpace(in.Weather); utf8.RuneCountInString(w) < 2 || utf8.RuneCountInString(w) > 200 {
		return bad("weather is 2 to 200 characters")
	}
	if utf8.RuneCountInString(in.Notes) > 8000 || !utf8.ValidString(in.Notes+in.Weather) {
		return bad("notes are at most 8000 characters of valid text")
	}
	if len(in.Labour) > 200 || len(in.Equipment) > 200 {
		return bad("at most 200 labour and 200 equipment lines")
	}
	if in.BaseVersion < 0 || in.BaseVersion > 10000 {
		return bad("base_version is out of range")
	}
	twoDP := func(d decimal.Decimal) bool { return d.Equal(d.Round(2)) }
	for i, l := range in.Labour {
		if t := strings.TrimSpace(l.Trade); utf8.RuneCountInString(t) < 2 || utf8.RuneCountInString(t) > 100 {
			return bad(fmt.Sprintf("labour line %d: trade is 2 to 100 characters", i+1))
		}
		if l.Headcount < 1 || l.Headcount > 10000 || !l.Hours.IsPositive() || !twoDP(l.Hours) ||
			l.Hours.GreaterThan(decimal.NewFromInt(int64(l.Headcount)*24)) {
			return bad(fmt.Sprintf("labour line %d: headcount 1-10000 and 0 < person-hours <= 24 x headcount, 2 decimals", i+1))
		}
	}
	for i, e := range in.Equipment {
		if d := strings.TrimSpace(e.Description); utf8.RuneCountInString(d) < 2 || utf8.RuneCountInString(d) > 200 {
			return bad(fmt.Sprintf("equipment line %d: description is 2 to 200 characters", i+1))
		}
		sum := e.Hours.Add(e.IdleHours)
		if e.Hours.IsNegative() || e.IdleHours.IsNegative() || !twoDP(e.Hours) || !twoDP(e.IdleHours) ||
			sum.LessThan(decimal.RequireFromString("0.01")) || sum.GreaterThan(decimal.NewFromInt(24)) {
			return bad(fmt.Sprintf("equipment line %d: hours and idle hours are 0 or more, 2 decimals, together at most 24", i+1))
		}
	}
	return nil
}

// SaveDiary creates or revises a DRAFT diary online. A stale BaseVersion is
// a *DiaryConflict (wrapped with postgres.ErrVersionConflict).
func (s *Service) SaveDiary(ctx context.Context, p auth.Principal, in DiaryInput) (DiaryResult, error) {
	if err := validDiary(in); err != nil {
		return DiaryResult{}, err
	}
	if err := s.authz.RequireProject(p, auth.PermSiteDiaryManage, p.TenantID, in.ProjectID); err != nil {
		return DiaryResult{}, err
	}
	var res DiaryResult
	err := s.p2pTx(ctx, p, auth.PermSiteDiaryManage, func(ctx context.Context, tx pgx.Tx) error {
		r, conflict, err := s.saveDiaryTx(ctx, tx, p, in, "", nil)
		if err != nil {
			return err
		}
		if conflict != nil {
			return fmt.Errorf("%w: %w", postgres.ErrVersionConflict, conflict)
		}
		res = r
		return nil
	})
	return res, err
}

func (s *Service) saveDiaryTx(ctx context.Context, tx pgx.Tx, p auth.Principal, in DiaryInput, deviceID string, clientTime *time.Time) (DiaryResult, *DiaryConflict, error) {
	var cur struct {
		id, number, status, createdBy, project string
		version                                int
		date                                   time.Time
	}
	err := tx.QueryRow(ctx, `SELECT id::text, number, status, created_by, project_id::text, version, diary_date FROM site_diaries WHERE client_ref = $1::uuid FOR UPDATE`,
		in.ClientRef).Scan(&cur.id, &cur.number, &cur.status, &cur.createdBy, &cur.project, &cur.version, &cur.date)
	if errors.Is(err, pgx.ErrNoRows) {
		if in.BaseVersion != 0 {
			return DiaryResult{}, nil, fmt.Errorf("%w: no diary with this client_ref exists; create it with base_version 0", ErrInvalidInput)
		}
		return s.createDiaryTx(ctx, tx, p, in, deviceID, clientTime)
	}
	if err != nil {
		return DiaryResult{}, nil, err
	}
	// The diary exists: only its author revises it, within scope, and its
	// project and date never change.
	if !s.canSee(p, "site_diary", cur.project) {
		return DiaryResult{}, nil, ErrNotFound
	}
	if cur.createdBy != p.UserID {
		return DiaryResult{}, nil, fmt.Errorf("%w: only the author revises a diary", auth.ErrForbidden)
	}
	if cur.project != in.ProjectID || !cur.date.Equal(in.DiaryDate) {
		return DiaryResult{}, nil, fmt.Errorf("%w: a diary's project and date never change", ErrInvalidInput)
	}
	if cur.status != "DRAFT" || cur.version != in.BaseVersion {
		return DiaryResult{}, &DiaryConflict{DiaryResult: DiaryResult{ID: cur.id, Number: cur.number, Version: cur.version, Status: cur.status}, BaseVersion: in.BaseVersion}, nil
	}
	next := cur.version + 1
	if err := postgres.Exec1(ctx, tx, `UPDATE site_diaries SET version = $2, weather = $3, notes = $4 WHERE id = $1::uuid`,
		cur.id, next, strings.TrimSpace(in.Weather), in.Notes); err != nil {
		return DiaryResult{}, nil, err
	}
	if err := insertDiaryLines(ctx, tx, cur.id, next, in); err != nil {
		return DiaryResult{}, nil, err
	}
	if err := s.authorize(ctx, tx, p, "site.diary.revision.create", "site_diary", cur.id, ""); err != nil {
		return DiaryResult{}, nil, err
	}
	payload := map[string]any{"site_diary_id": cur.id, "version": next, "device_id": deviceID}
	if err := s.record(ctx, tx, p, "site.diary.revise", "site_diary", cur.id, "site.diary_revised", payload); err != nil {
		return DiaryResult{}, nil, err
	}
	return DiaryResult{ID: cur.id, Number: cur.number, Version: next, Status: "DRAFT"}, nil, nil
}

func (s *Service) createDiaryTx(ctx context.Context, tx pgx.Tx, p auth.Principal, in DiaryInput, deviceID string, clientTime *time.Time) (DiaryResult, *DiaryConflict, error) {
	// One live diary per project and day: report the existing one clearly
	// (the unique index is the guarantee).
	var other string
	err := tx.QueryRow(ctx, `SELECT number FROM site_diaries WHERE project_id = $1::uuid AND diary_date = $2 AND status NOT IN ('REJECTED', 'CANCELLED')`, in.ProjectID, in.DiaryDate).Scan(&other)
	if err == nil {
		return DiaryResult{}, nil, fmt.Errorf("%w: the project already has diary %s for %s", ErrInvalidInput, other, in.DiaryDate.Format("2006-01-02"))
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return DiaryResult{}, nil, err
	}
	num, err := postgres.NextNumber(ctx, tx, "SDY")
	if err != nil {
		return DiaryResult{}, nil, err
	}
	var dev any
	if deviceID != "" {
		dev = deviceID
	}
	id, err := postgres.InsertReturningID(ctx, tx, `INSERT INTO site_diaries(project_id, number, client_ref, diary_date, weather, notes, origin_device_id, client_created_at, created_by)
		VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7::uuid, $8, $9) RETURNING id::text`,
		in.ProjectID, num, in.ClientRef, in.DiaryDate, strings.TrimSpace(in.Weather), in.Notes, dev, clientTime, p.UserID)
	if err != nil {
		return DiaryResult{}, nil, err
	}
	if err := insertDiaryLines(ctx, tx, id, 1, in); err != nil {
		return DiaryResult{}, nil, err
	}
	if err := s.authorize(ctx, tx, p, "site.diary.create", "site_diary", id, ""); err != nil {
		return DiaryResult{}, nil, err
	}
	payload := map[string]any{"site_diary_id": id, "project_id": in.ProjectID, "diary_date": in.DiaryDate.Format("2006-01-02"), "device_id": deviceID}
	if err := s.record(ctx, tx, p, "site.diary.create", "site_diary", id, "site.diary_created", payload); err != nil {
		return DiaryResult{}, nil, err
	}
	return DiaryResult{ID: id, Number: num, Version: 1, Status: "DRAFT"}, nil, nil
}

func insertDiaryLines(ctx context.Context, tx pgx.Tx, id string, version int, in DiaryInput) error {
	for i, l := range in.Labour {
		if _, err := tx.Exec(ctx, `INSERT INTO site_diary_labour(diary_id, version, line_no, trade, headcount, hours) VALUES ($1::uuid, $2, $3, $4, $5, $6)`,
			id, version, i+1, strings.TrimSpace(l.Trade), l.Headcount, l.Hours); err != nil {
			return err
		}
	}
	for i, e := range in.Equipment {
		if _, err := tx.Exec(ctx, `INSERT INTO site_diary_equipment(diary_id, version, line_no, description, hours, idle_hours) VALUES ($1::uuid, $2, $3, $4, $5, $6)`,
			id, version, i+1, strings.TrimSpace(e.Description), e.Hours, e.IdleHours); err != nil {
			return err
		}
	}
	return nil
}

// SubmitDiary submits the author's DRAFT diary for approval. A positive
// baseVersion must match the server's version (offline submits always
// state it).
func (s *Service) SubmitDiary(ctx context.Context, p auth.Principal, id string, baseVersion int) error {
	return s.p2pTx(ctx, p, auth.PermSiteDiaryManage, func(ctx context.Context, tx pgx.Tx) error {
		_, conflict, err := s.submitDiaryTx(ctx, tx, p, id, baseVersion)
		if err == nil && conflict != nil {
			return fmt.Errorf("%w: %w", postgres.ErrVersionConflict, conflict)
		}
		return err
	})
}

func (s *Service) submitDiaryTx(ctx context.Context, tx pgx.Tx, p auth.Principal, id string, baseVersion int) (DiaryResult, *DiaryConflict, error) {
	d, err := s.loadDoc(ctx, tx, p, auth.PermSiteDiaryManage, "site_diary", id)
	if err != nil {
		return DiaryResult{}, nil, err
	}
	if d.CreatedBy != p.UserID {
		return DiaryResult{}, nil, fmt.Errorf("%w: only the author submits a diary", auth.ErrForbidden)
	}
	var version int
	if err := tx.QueryRow(ctx, `SELECT version FROM site_diaries WHERE id = $1::uuid`, id).Scan(&version); err != nil {
		return DiaryResult{}, nil, err
	}
	if d.Status != "DRAFT" || (baseVersion > 0 && baseVersion != version) {
		return DiaryResult{}, &DiaryConflict{DiaryResult: DiaryResult{ID: id, Number: d.Number, Version: version, Status: d.Status}, BaseVersion: baseVersion}, nil
	}
	if err := s.authorize(ctx, tx, p, "site.diary.submit", "site_diary", id, ""); err != nil {
		return DiaryResult{}, nil, err
	}
	if err := postgres.Exec1(ctx, tx, `UPDATE site_diaries SET status = 'SUBMITTED' WHERE id = $1::uuid`, id); err != nil {
		return DiaryResult{}, nil, err
	}
	if err := s.record(ctx, tx, p, "site.diary.submit", "site_diary", id, "site.diary_submitted", map[string]any{"site_diary_id": id, "version": version}); err != nil {
		return DiaryResult{}, nil, err
	}
	return DiaryResult{ID: id, Number: d.Number, Version: version, Status: "SUBMITTED"}, nil, nil
}

// DecideDiary approves (or rejects with a reason) a submitted diary. The
// approver is a human other than the author, within the project's scope.
func (s *Service) DecideDiary(ctx context.Context, p auth.Principal, id string, approve bool, reason string) error {
	if !approve {
		if err := requireReason(reason); err != nil {
			return err
		}
	}
	return s.p2pTx(ctx, p, auth.PermSiteDiaryApprove, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermSiteDiaryApprove, "site_diary", id)
		if err != nil {
			return err
		}
		// Approval needs a submitted diary; rejection also clears a DRAFT that
		// holds a project day (R12-F2).
		if approve {
			err = requireStatus(d, "SUBMITTED")
		} else {
			err = requireStatus(d, "SUBMITTED", "DRAFT")
		}
		if err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, d.CreatedBy, "site diary"); err != nil {
			return err
		}
		action, next := "site.diary.approve", "APPROVED"
		if !approve {
			action, next = "site.diary.reject", "REJECTED"
		}
		if err := s.authorize(ctx, tx, p, action, "site_diary", id, next); err != nil {
			return err
		}
		if approve {
			err = postgres.Exec1(ctx, tx, `UPDATE site_diaries SET status = 'APPROVED', approved_by = $2 WHERE id = $1::uuid`, id, p.UserID)
		} else {
			err = postgres.Exec1(ctx, tx, `UPDATE site_diaries SET status = 'REJECTED', decision_reason = $2, rejected_by = $3 WHERE id = $1::uuid`, id, strings.TrimSpace(reason), p.UserID)
		}
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, action, "site_diary", id, "site.diary_"+strings.ToLower(next), map[string]any{"site_diary_id": id})
	})
}

// CancelDiary withdraws the author's DRAFT diary (it frees the project day).
func (s *Service) CancelDiary(ctx context.Context, p auth.Principal, id, reason string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.p2pTx(ctx, p, auth.PermSiteDiaryManage, func(ctx context.Context, tx pgx.Tx) error {
		d, err := s.loadDoc(ctx, tx, p, auth.PermSiteDiaryManage, "site_diary", id)
		if err != nil {
			return err
		}
		if d.CreatedBy != p.UserID {
			return fmt.Errorf("%w: only the author withdraws a diary", auth.ErrForbidden)
		}
		if err := requireStatus(d, "DRAFT"); err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "site.diary.cancel", "site_diary", id, "CANCELLED"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE site_diaries SET status = 'CANCELLED', decision_reason = $2 WHERE id = $1::uuid`, id, strings.TrimSpace(reason)); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "site.diary.cancel", "site_diary", id, "site.diary_cancelled", map[string]any{"site_diary_id": id})
	})
}

// ---------------------------------------------------------------------------
// Field devices
// ---------------------------------------------------------------------------

// DeviceRegistration is returned once, at registration: the secret is never
// stored or shown again.
type DeviceRegistration struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

// Device is a field device as listed (no key material).
type Device struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	Label        string     `json:"label"`
	Status       string     `json:"status"`
	LastSeq      int64      `json:"last_seq"`
	LastSyncAt   *time.Time `json:"last_sync_at,omitempty"`
	RegisteredAt time.Time  `json:"registered_at"`
	RevokedBy    *string    `json:"revoked_by,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

func deviceKeyHash(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// RegisterDevice registers a field device for the caller (fresh MFA is
// required by the database) and returns its secret once.
func (s *Service) RegisterDevice(ctx context.Context, p auth.Principal, label string) (DeviceRegistration, error) {
	// Offline write capability: a recent multi-factor login (the database
	// requires it in the attestation as well).
	if err := s.authz.RequireStepUp(p); err != nil {
		return DeviceRegistration{}, err
	}
	label = strings.TrimSpace(label)
	if n := utf8.RuneCountInString(label); n < 2 || n > 100 {
		return DeviceRegistration{}, fmt.Errorf("%w: label is 2 to 100 characters", ErrInvalidInput)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return DeviceRegistration{}, err
	}
	secret := "sfd_" + base64.RawURLEncoding.EncodeToString(raw)
	var id string
	err := s.p2pTx(ctx, p, auth.PermSiteDeviceRegister, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		id, err = postgres.InsertReturningID(ctx, tx, `INSERT INTO site_devices(user_id, label, key_hash) VALUES ($1, $2, $3) RETURNING id::text`,
			p.UserID, label, deviceKeyHash(secret))
		if err != nil {
			return err
		}
		if err := s.authorize(ctx, tx, p, "site.device.create", "site_device", id, ""); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "site.device.create", "site_device", id, "site.device_registered", map[string]any{"site_device_id": id, "label": label})
	})
	if err != nil {
		return DeviceRegistration{}, err
	}
	return DeviceRegistration{ID: id, Secret: secret}, nil
}

// loadDevice returns a device's owner and status if the caller may act on
// it: its owner, or a site.device.manage holder. Others get ErrNotFound.
func (s *Service) loadDevice(ctx context.Context, tx pgx.Tx, p auth.Principal, id string, lock bool) (owner, status string, err error) {
	if !canonicalUUIDRe.MatchString(id) {
		return "", "", ErrNotFound
	}
	q := `SELECT user_id, status FROM site_devices WHERE id = $1::uuid`
	if lock {
		q += ` FOR UPDATE`
	}
	if err := tx.QueryRow(ctx, q, id).Scan(&owner, &status); err != nil {
		return "", "", mapNoRows(err)
	}
	if owner != p.UserID && !s.authz.Has(p, auth.PermSiteDeviceManage) {
		return "", "", ErrNotFound
	}
	return owner, status, nil
}

// RevokeDevice revokes a field device (its owner, or a site.device.manage
// holder). Commands it queued and sends later are refused.
func (s *Service) RevokeDevice(ctx context.Context, p auth.Principal, id, reason string) error {
	if err := requireReason(reason); err != nil {
		return err
	}
	if !s.authz.Has(p, auth.PermSiteDeviceRegister) && !s.authz.Has(p, auth.PermSiteDeviceManage) {
		return fmt.Errorf("%w: site.device.register or site.device.manage", auth.ErrForbidden)
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		owner, status, err := s.loadDevice(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		if owner != p.UserID && !s.authz.Has(p, auth.PermSiteDeviceManage) {
			return ErrNotFound
		}
		if status != "ACTIVE" {
			return fmt.Errorf("%w: the device is %s", ErrInvalidInput, status)
		}
		if err := s.authorize(ctx, tx, p, "site.device.revoke", "site_device", id, "REVOKED"); err != nil {
			return err
		}
		if err := postgres.Exec1(ctx, tx, `UPDATE site_devices SET status = 'REVOKED', revoked_by = $2, revoke_reason = $3 WHERE id = $1::uuid`,
			id, p.UserID, strings.TrimSpace(reason)); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "site.device.revoke", "site_device", id, "site.device_revoked", map[string]any{"site_device_id": id, "owner": owner})
	})
}

// ListDevices lists the caller's devices, or every device for a
// site.device.manage holder.
func (s *Service) ListDevices(ctx context.Context, p auth.Principal) ([]Device, error) {
	all := s.authz.Has(p, auth.PermSiteDeviceManage)
	if !all && !s.authz.Has(p, auth.PermSiteDeviceRegister) {
		return nil, fmt.Errorf("%w: site.device.register or site.device.manage", auth.ErrForbidden)
	}
	var out []Device
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text, user_id, label, status, last_seq, last_sync_at, registered_at, revoked_by, revoked_at
			FROM site_devices WHERE $1 OR user_id = $2 ORDER BY status = 'ACTIVE' DESC, registered_at DESC LIMIT 500`, all, p.UserID)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Device, error) {
			var d Device
			err := r.Scan(&d.ID, &d.UserID, &d.Label, &d.Status, &d.LastSeq, &d.LastSyncAt, &d.RegisteredAt, &d.RevokedBy, &d.RevokedAt)
			return d, err
		})
		return err
	})
	return out, err
}

// ---------------------------------------------------------------------------
// Offline synchronisation
// ---------------------------------------------------------------------------

// SyncOp is one queued offline command.
type SyncOp struct {
	OpID       string          `json:"op_id"`
	Seq        int64           `json:"seq"`
	Kind       string          `json:"kind"` // site_diary.save | site_diary.submit
	ClientTime time.Time       `json:"client_time"`
	Payload    json.RawMessage `json:"payload"`
}

// SyncResult is the server's answer to one command. Replayed is true when
// the answer comes from the command log (the command was already applied or
// refused before; nothing was done again).
type SyncResult struct {
	OpID          string `json:"op_id"`
	Seq           int64  `json:"seq"`
	Outcome       string `json:"outcome"` // APPLIED | CONFLICT | REJECTED
	Replayed      bool   `json:"replayed,omitempty"`
	DiaryID       string `json:"diary_id,omitempty"`
	Number        string `json:"number,omitempty"`
	Version       int    `json:"version,omitempty"`
	Status        string `json:"status,omitempty"`
	ServerVersion int    `json:"server_version,omitempty"`
	ServerStatus  string `json:"server_status,omitempty"`
	Error         string `json:"error,omitempty"`
	// Retry is true when nothing was recorded (a temporary failure): the
	// device sends the same command again later.
	Retry bool `json:"retry,omitempty"`
}

type syncDiaryPayload struct {
	ClientRef   string           `json:"client_ref"`
	ProjectID   string           `json:"project_id"`
	DiaryDate   string           `json:"diary_date"`
	Weather     string           `json:"weather"`
	Notes       string           `json:"notes"`
	Labour      []DiaryLabour    `json:"labour"`
	Equipment   []DiaryEquipment `json:"equipment"`
	BaseVersion int              `json:"base_version"`
}

type syncSubmitPayload struct {
	ClientRef   string `json:"client_ref"`
	BaseVersion int    `json:"base_version"`
}

// MaxSyncOps bounds one sync request.
const MaxSyncOps = 100

// Sync applies a device's queued commands in order. The device must be an
// ACTIVE device of the caller and the secret must match; otherwise nothing is
// applied and ErrDeviceRefused is returned (the reason is audited). Each
// command is applied in its own transaction and answered individually.
func (s *Service) Sync(ctx context.Context, p auth.Principal, deviceID, secret string, ops []SyncOp) ([]SyncResult, error) {
	if err := s.authz.Require(p, auth.PermSiteDiaryManage, p.TenantID); err != nil {
		return nil, err
	}
	if len(ops) == 0 || len(ops) > MaxSyncOps {
		return nil, fmt.Errorf("%w: 1 to %d commands per sync", ErrInvalidInput, MaxSyncOps)
	}
	if err := s.checkDevice(ctx, p, deviceID, secret); err != nil {
		return nil, err
	}
	out := make([]SyncResult, 0, len(ops))
	stopped := ""
	for _, op := range ops {
		if stopped != "" {
			// Order matters: after a command that could not be processed,
			// the rest of the batch waits for the retry (R12-F4).
			out = append(out, SyncResult{OpID: op.OpID, Seq: op.Seq, Outcome: "REJECTED", Error: stopped, Retry: true})
			continue
		}
		r := s.syncOne(ctx, p, deviceID, op)
		if r.Retry {
			stopped = "not processed: an earlier command in this batch must be retried first"
		}
		out = append(out, r)
	}
	return out, nil
}

func (s *Service) checkDevice(ctx context.Context, p auth.Principal, deviceID, secret string) error {
	reason := ""
	if !canonicalUUIDRe.MatchString(deviceID) || secret == "" || len(secret) > 200 {
		reason = "malformed device credentials"
	} else {
		var owner, status, hash string
		err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
			return tx.QueryRow(ctx, `SELECT user_id, status, key_hash FROM site_devices WHERE id = $1::uuid`, deviceID).Scan(&owner, &status, &hash)
		})
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			reason = "unknown device"
		case err != nil:
			return err
		case subtle.ConstantTimeCompare([]byte(hash), []byte(deviceKeyHash(secret))) != 1:
			reason = "wrong device secret"
		case owner != p.UserID:
			reason = "device of another person"
		case status != "ACTIVE":
			reason = "device revoked"
		}
	}
	if reason == "" {
		return nil
	}
	s.auditRefusal(ctx, p, "site.sync_refused", "site_device", deviceIDForAudit(deviceID), map[string]any{"reason": reason})
	return ErrDeviceRefused
}

func deviceIDForAudit(id string) string {
	if canonicalUUIDRe.MatchString(id) {
		return id
	}
	return "-"
}

// syncDigest binds a command's kind and payload in a canonical form: the
// JSON is decoded (numbers kept exact) and re-encoded with sorted keys and
// standard escaping, so a retry that differs only in key order, whitespace
// or escape spelling is recognised as the same command (R12-F8). A payload
// with duplicate keys, including keys that differ only in letter case (Go
// matches struct fields case-insensitively), is refused outright, so two
// different readings can never share a digest.
func syncDigest(op SyncOp) (string, error) {
	if err := noDuplicateKeysFold(op.Payload); err != nil {
		return "", err
	}
	dec := json.NewDecoder(bytes.NewReader(op.Payload))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	if dec.More() {
		return "", fmt.Errorf("trailing data")
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(op.Kind))
	h.Write([]byte{0x1f})
	h.Write(canon)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// noDuplicateKeysFold refuses JSON in which an object repeats a key, compared
// case-insensitively.
func noDuplicateKeysFold(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	type frame struct {
		obj  bool
		keys map[string]bool
		key  bool // the next string token in this object is a key
	}
	var stack []*frame
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var top *frame
		if len(stack) > 0 {
			top = stack[len(stack)-1]
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				if top != nil && top.obj {
					top.key = true
				}
				stack = append(stack, &frame{obj: true, keys: map[string]bool{}, key: true})
			case '[':
				if top != nil && top.obj {
					top.key = true
				}
				stack = append(stack, &frame{})
			case '}', ']':
				stack = stack[:len(stack)-1]
			}
		default:
			if top != nil && top.obj {
				if top.key {
					k := strings.ToLower(fmt.Sprint(t))
					if top.keys[k] {
						return fmt.Errorf("duplicate key %q", t)
					}
					top.keys[k] = true
					top.key = false
				} else {
					top.key = true
				}
			}
		}
	}
}

func (s *Service) syncOne(ctx context.Context, p auth.Principal, deviceID string, op SyncOp) SyncResult {
	res := SyncResult{OpID: op.OpID, Seq: op.Seq}
	reject := func(msg string) SyncResult { res.Outcome, res.Error = "REJECTED", msg; return res }
	if !canonicalUUIDRe.MatchString(op.OpID) || op.Seq < 1 {
		return reject("op_id is a canonical UUID and seq is at least 1")
	}
	if op.Kind != "site_diary.save" && op.Kind != "site_diary.submit" {
		return reject("unknown command kind")
	}
	if len(op.Payload) == 0 || len(op.Payload) > 64<<10 {
		return reject("payload is required and at most 64 KiB")
	}
	digest, err := syncDigest(op)
	if err != nil {
		return reject("payload is not valid JSON or repeats a key (" + err.Error() + ")")
	}
	// The device clock is evidence only; absurd values are refused.
	now := time.Now()
	if op.ClientTime.IsZero() || op.ClientTime.After(now.Add(24*time.Hour)) || op.ClientTime.Before(now.AddDate(0, 0, -90)) {
		return reject("client_time is missing or implausible (more than a day ahead or 90 days behind the server)")
	}

	var applied SyncResult
	var applyErr error
	err = s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		// Serialise the device's commands, then answer replays from the log.
		var lastSeq int64
		var status string
		if err := tx.QueryRow(ctx, `SELECT last_seq, status FROM site_devices WHERE id = $1::uuid FOR UPDATE`, deviceID).Scan(&lastSeq, &status); err != nil {
			return mapNoRows(err)
		}
		if status != "ACTIVE" {
			return ErrDeviceRefused
		}
		var prevDigest, prevOutcome string
		var prevResult []byte
		err := tx.QueryRow(ctx, `SELECT payload_sha256, outcome, result FROM site_sync_commands WHERE device_id = $1::uuid AND client_op_id = $2::uuid`,
			deviceID, op.OpID).Scan(&prevDigest, &prevOutcome, &prevResult)
		if err == nil {
			if prevDigest != digest {
				applied = reject("this op_id was already used with a different command")
				return nil
			}
			if err := json.Unmarshal(prevResult, &applied); err != nil {
				return err
			}
			applied.Replayed = true
			return nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if op.Seq <= lastSeq {
			applied = reject(fmt.Sprintf("sequence %d is not after the device's last sequence %d", op.Seq, lastSeq))
			return nil
		}
		if op.Seq > lastSeq+1000 {
			applied = reject(fmt.Sprintf("sequence %d jumps more than 1000 past the device's last sequence %d", op.Seq, lastSeq))
			return nil
		}
		r, diaryID, err := s.applyOp(ctx, tx, p, deviceID, op)
		if err != nil {
			applyErr = err
			return err // roll back; the refusal is recorded below in its own transaction
		}
		applied = r
		return s.recordSync(ctx, tx, p, deviceID, op, digest, r, diaryID)
	})
	if errors.Is(err, ErrDeviceRefused) {
		return reject("the device was revoked")
	}
	if (err != nil && applyErr == nil) || (applyErr != nil && !isDomainRefusal(applyErr)) {
		// A temporary failure (database, signer, timeout, revoked session):
		// nothing recorded; the device retries the same command later and
		// the rest of the batch waits (R12-F4).
		res.Outcome, res.Error, res.Retry = "REJECTED", "not processed; retry the same command", true
		if errors.Is(applyErr, ErrSessionRevoked) || errors.Is(err, ErrSessionRevoked) {
			res.Error = "session revoked; sign in again, then retry"
		}
		return res
	}
	if applyErr != nil {
		// A refused command is still consumed: recorded with its reason, and
		// the sequence moves past it, so it is never applied later.
		r := reject(safeRefusal(applyErr))
		_ = s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
			var status string
			if err := tx.QueryRow(ctx, `SELECT status FROM site_devices WHERE id = $1::uuid FOR UPDATE`, deviceID).Scan(&status); err != nil || status != "ACTIVE" {
				return ErrDeviceRefused
			}
			if exists := tx.QueryRow(ctx, `SELECT 1 FROM site_sync_commands WHERE device_id = $1::uuid AND client_op_id = $2::uuid`, deviceID, op.OpID).Scan(new(int)); exists == nil {
				return nil // recorded concurrently
			}
			return s.recordSync(ctx, tx, p, deviceID, op, digest, r, "")
		})
		return r
	}
	return applied
}

// isDomainRefusal reports whether a command was refused on its merits (so it
// is recorded and consumed) rather than by a temporary failure.
func isDomainRefusal(err error) bool {
	return errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrNotFound) || errors.Is(err, auth.ErrForbidden) ||
		errors.Is(err, auth.ErrTenantMismatch) || errors.Is(err, auth.ErrSoD) || errors.Is(err, postgres.ErrInvariant) ||
		errors.Is(err, postgres.ErrVersionConflict)
}

// safeRefusal turns an apply error into a message for the device: the
// domain reason, never internals.
func safeRefusal(err error) string {
	switch {
	case errors.Is(err, ErrNotFound):
		return "not found"
	case errors.Is(err, auth.ErrForbidden), errors.Is(err, auth.ErrTenantMismatch):
		return "not permitted"
	case errors.Is(err, ErrInvalidInput), errors.Is(err, postgres.ErrInvariant):
		msg := err.Error()
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return canonicalUUIDRe.ReplaceAllString(msg, "<id>")
	case errors.Is(err, ErrSessionRevoked):
		return "session revoked"
	}
	return "refused"
}

func (s *Service) applyOp(ctx context.Context, tx pgx.Tx, p auth.Principal, deviceID string, op SyncOp) (SyncResult, string, error) {
	res := SyncResult{OpID: op.OpID, Seq: op.Seq}
	dec := json.NewDecoder(bytes.NewReader(op.Payload))
	dec.DisallowUnknownFields()
	ct := op.ClientTime.UTC()
	var r DiaryResult
	var conflict *DiaryConflict
	switch op.Kind {
	case "site_diary.save":
		var pl syncDiaryPayload
		if err := dec.Decode(&pl); err != nil {
			return res, "", fmt.Errorf("%w: payload: %v", ErrInvalidInput, err)
		}
		day, err := time.Parse("2006-01-02", pl.DiaryDate)
		if err != nil {
			return res, "", fmt.Errorf("%w: diary_date is YYYY-MM-DD", ErrInvalidInput)
		}
		in := DiaryInput{ClientRef: pl.ClientRef, ProjectID: pl.ProjectID, DiaryDate: day, Weather: pl.Weather, Notes: pl.Notes,
			Labour: pl.Labour, Equipment: pl.Equipment, BaseVersion: pl.BaseVersion}
		if err := validDiary(in); err != nil {
			return res, "", err
		}
		if err := s.authz.RequireProject(p, auth.PermSiteDiaryManage, p.TenantID, in.ProjectID); err != nil {
			return res, "", err
		}
		r, conflict, err = s.saveDiaryTx(ctx, tx, p, in, deviceID, &ct)
		if err != nil {
			return res, "", err
		}
	case "site_diary.submit":
		var pl syncSubmitPayload
		if err := dec.Decode(&pl); err != nil {
			return res, "", fmt.Errorf("%w: payload: %v", ErrInvalidInput, err)
		}
		if !canonicalUUIDRe.MatchString(pl.ClientRef) || pl.BaseVersion < 1 {
			return res, "", fmt.Errorf("%w: client_ref and base_version are required", ErrInvalidInput)
		}
		var id string
		if err := tx.QueryRow(ctx, `SELECT id::text FROM site_diaries WHERE client_ref = $1::uuid`, pl.ClientRef).Scan(&id); err != nil {
			return res, "", mapNoRows(err)
		}
		var err error
		r, conflict, err = s.submitDiaryTx(ctx, tx, p, id, pl.BaseVersion)
		if err != nil {
			return res, "", err
		}
	}
	if conflict != nil {
		res.Outcome, res.DiaryID, res.Number = "CONFLICT", conflict.ID, conflict.Number
		res.ServerVersion, res.ServerStatus = conflict.Version, conflict.Status
		res.Error = conflict.Error()
		return res, "", nil
	}
	res.Outcome, res.DiaryID, res.Number, res.Version, res.Status = "APPLIED", r.ID, r.Number, r.Version, r.Status
	return res, r.ID, nil
}

// recordSync writes the command log row, attested by the device owner for
// this device and op id (R12-F1), and moves the device sequence.
func (s *Service) recordSync(ctx context.Context, tx pgx.Tx, p auth.Principal, deviceID string, op SyncOp, digest string, r SyncResult, diaryID string) error {
	if err := s.authorize(ctx, tx, p, "site.sync.create", "site_device", deviceID, op.OpID); err != nil {
		return err
	}
	stored := r
	stored.Replayed = false
	body, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	var diary any
	if diaryID != "" {
		diary = diaryID
	}
	if _, err := tx.Exec(ctx, `INSERT INTO site_sync_commands(device_id, client_op_id, seq, kind, actor, payload_sha256, client_time, outcome, diary_id, result)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9::uuid, $10::jsonb)`,
		deviceID, op.OpID, op.Seq, op.Kind, p.UserID, digest, op.ClientTime, r.Outcome, diary, string(body)); err != nil {
		return err
	}
	return postgres.Exec1(ctx, tx, `UPDATE site_devices SET last_seq = $2, last_sync_at = now() WHERE id = $1::uuid`, deviceID, op.Seq)
}
