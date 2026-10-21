// Package auth implements the Enterprise Identity and Privilege Engine's
// deterministic authorization core (Pillar 3): role-based permissions,
// explicit data scope (tenant-wide vs project-limited), segregation-of-duties
// (SoD) rules and step-up (MFA) requirements.
//
// Authorization decisions never involve AI (LAW 01) and are evaluated on the
// server for every command.
package auth

import (
	"errors"
	"fmt"
	"sort"
	"time"
)

// Permission is a fine-grained capability string "<resource>.<action>".
type Permission string

const (
	PermJournalCreate  Permission = "journal.create"
	PermJournalApprove Permission = "journal.approve"
	PermJournalPost    Permission = "journal.post"
	PermJournalReverse Permission = "journal.reverse"
	PermJournalRead    Permission = "journal.read"

	PermFXRead          Permission = "fx.read"
	PermFXManage        Permission = "fx.manage"            // maker: record rates, register sources, propose policies
	PermFXApprove       Permission = "fx.approve"           // checker: approve/reject/withdraw rates and sources
	PermFXApproveExcept Permission = "fx.approve_exception" // checker for rates outside the variance tolerance (MFA)
	PermFXPolicyApprove Permission = "fx.policy.approve"    // checker for FX policies

	PermAccountManage Permission = "account.manage"
	PermPeriodClose   Permission = "period.close"
	PermPeriodReopen  Permission = "period.reopen"
	PermAuditRead     Permission = "audit.read"

	// PermScopeTenantWide grants access to records that are not assigned to a
	// project (tenant-wide finance) and to every project. Without it a
	// principal sees only the projects listed in its ProjectIDs (SC-05).
	PermScopeTenantWide Permission = "scope.tenant_wide"

	// Project controls.
	PermWBSManage  Permission = "wbs.manage"  // propose WBS / cost-code versions
	PermWBSApprove Permission = "wbs.approve" // approve them (different person)

	// Workflow engine.
	PermWorkflowDefine  Permission = "workflow.define"  // propose a workflow definition
	PermWorkflowPublish Permission = "workflow.publish" // approve a definition (different person)
	PermWorkflowAdmin   Permission = "workflow.admin"   // console operations: retry effects, cancel instances
	PermWorkflowRead    Permission = "workflow.read"

	// PermApprovalHighValue is the executive sign-off used by workflow
	// threshold steps (e.g. journals at or above a materiality limit).
	PermApprovalHighValue Permission = "approval.high_value"
)

// Role is a named permission bundle. Roles are tenant-scoped data in
// production; the defaults below are the seed set.
type Role struct {
	Name        string
	Permissions []Permission
}

// DefaultRoles is the seed role catalogue. Separation baselines enforced by
// tests: no role holds two of journal create/approve/post; no role holds both
// fx.manage and fx.approve; no role both defines and publishes workflows.
var DefaultRoles = map[string]Role{
	"accountant":       {Name: "accountant", Permissions: []Permission{PermJournalCreate, PermJournalRead, PermFXRead, PermScopeTenantWide, PermWorkflowRead}},
	"treasury_officer": {Name: "treasury_officer", Permissions: []Permission{PermFXManage, PermFXRead, PermScopeTenantWide, PermWorkflowRead}},
	"finance_manager": {Name: "finance_manager", Permissions: []Permission{PermJournalApprove, PermJournalRead, PermFXRead, PermFXApprove,
		PermFXPolicyApprove, PermWBSApprove, PermScopeTenantWide, PermWorkflowRead}},
	"controller": {Name: "controller", Permissions: []Permission{PermJournalPost, PermJournalReverse, PermJournalRead, PermPeriodClose,
		PermAccountManage, PermFXRead, PermScopeTenantWide, PermWorkflowRead}},
	"cfo": {Name: "cfo", Permissions: []Permission{PermJournalRead, PermFXRead, PermFXApprove, PermFXApproveExcept, PermFXPolicyApprove,
		PermPeriodReopen, PermAuditRead, PermScopeTenantWide, PermWorkflowRead, PermWorkflowPublish, PermApprovalHighValue}},
	"auditor":            {Name: "auditor", Permissions: []Permission{PermJournalRead, PermAuditRead, PermFXRead, PermScopeTenantWide, PermWorkflowRead}},
	"project_manager":    {Name: "project_manager", Permissions: []Permission{PermJournalRead, PermFXRead, PermWBSManage, PermWorkflowRead}},
	"project_accountant": {Name: "project_accountant", Permissions: []Permission{PermJournalCreate, PermJournalRead, PermFXRead, PermWorkflowRead}},
	"process_owner":      {Name: "process_owner", Permissions: []Permission{PermWorkflowDefine, PermWorkflowRead}},
	"workflow_admin":     {Name: "workflow_admin", Permissions: []Permission{PermWorkflowAdmin, PermWorkflowRead}},
}

// Principal is the authenticated caller bound to exactly one tenant.
type Principal struct {
	UserID   string
	TenantID string
	Roles    []string
	// ProjectIDs lists the projects the principal may act on. Combined with
	// the role entitlement scope.tenant_wide it yields the effective Scope.
	ProjectIDs []string
	// MFA is true when the identity provider asserted a multi-factor
	// authentication method for this session (OIDC "amr").
	MFA bool
	// AuthTime is when the user last actively authenticated (OIDC "auth_time").
	AuthTime time.Time
}

// Errors.
var (
	ErrUnauthenticated = errors.New("auth: unauthenticated")
	ErrForbidden       = errors.New("auth: forbidden")
	ErrTenantMismatch  = errors.New("auth: resource belongs to another tenant")
	ErrSoD             = errors.New("auth: segregation of duties violation")
	ErrStepUpRequired  = errors.New("auth: recent multi-factor authentication required")
)

// Authorizer evaluates permissions against a role catalogue.
type Authorizer struct {
	roles map[string]Role
	// RequireDistinctPoster requires poster != approver in addition to the
	// always-on approver != preparer rule.
	RequireDistinctPoster bool
	// StepUpMaxAge bounds how old an MFA authentication may be for
	// exceptional approvals. Default 10 minutes.
	StepUpMaxAge time.Duration
	now          func() time.Time
}

// NewAuthorizer builds an authorizer over a role catalogue.
func NewAuthorizer(roles map[string]Role, requireDistinctPoster bool) *Authorizer {
	if roles == nil {
		roles = DefaultRoles
	}
	return &Authorizer{roles: roles, RequireDistinctPoster: requireDistinctPoster, StepUpMaxAge: 10 * time.Minute, now: time.Now}
}

// KnownPermissions is every permission some role of the catalogue grants.
// Workflow definitions may only reference these.
func (a *Authorizer) KnownPermissions() map[Permission]bool {
	out := map[Permission]bool{}
	for _, r := range a.roles {
		for _, p := range r.Permissions {
			out[p] = true
		}
	}
	return out
}

// Permissions returns the sorted, de-duplicated permission set of a principal.
func (a *Authorizer) Permissions(p Principal) []Permission {
	set := map[Permission]struct{}{}
	for _, r := range p.Roles {
		if role, ok := a.roles[r]; ok {
			for _, perm := range role.Permissions {
				set[perm] = struct{}{}
			}
		}
	}
	out := make([]Permission, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Has reports whether the principal holds the permission.
func (a *Authorizer) Has(p Principal, perm Permission) bool {
	for _, r := range p.Roles {
		role, ok := a.roles[r]
		if !ok {
			continue
		}
		for _, x := range role.Permissions {
			if x == perm {
				return true
			}
		}
	}
	return false
}

// Require returns ErrForbidden unless the principal holds the permission and
// ErrTenantMismatch if the resource tenant differs from the principal's.
func (a *Authorizer) Require(p Principal, perm Permission, resourceTenant string) error {
	if p.UserID == "" || p.TenantID == "" {
		return ErrUnauthenticated
	}
	if resourceTenant != "" && resourceTenant != p.TenantID {
		// Deliberately indistinguishable from "not found" at the API layer;
		// here we keep the precise cause for audit logging.
		return ErrTenantMismatch
	}
	if !a.Has(p, perm) {
		return fmt.Errorf("%w: %s", ErrForbidden, perm)
	}
	return nil
}

// Scope is a principal's effective data scope.
type Scope struct {
	// TenantWide principals may access unassigned (project-less) records and
	// every project of the tenant.
	TenantWide bool
	// Projects lists the projects a non-tenant-wide principal may access. An
	// empty list with TenantWide=false means no project data at all.
	Projects []string
}

// ScopeOf derives the effective scope. Tenant-wide access is never implied by
// an empty project list: it requires the explicit scope.tenant_wide
// entitlement AND no project restriction on the session. A token that lists
// projects is always restricted to them, whatever its roles (SC-05).
func (a *Authorizer) ScopeOf(p Principal) Scope {
	if len(p.ProjectIDs) == 0 && a.Has(p, PermScopeTenantWide) {
		return Scope{TenantWide: true}
	}
	return Scope{Projects: append([]string(nil), p.ProjectIDs...)}
}

// Allows reports whether the scope admits a record with the given project
// ("" = unassigned, tenant-wide record).
func (s Scope) Allows(projectID string) bool {
	if s.TenantWide {
		return true
	}
	if projectID == "" {
		return false
	}
	for _, id := range s.Projects {
		if id == projectID {
			return true
		}
	}
	return false
}

// RequireProject enforces the permission and the principal's data scope for a
// record belonging to projectID ("" = unassigned).
func (a *Authorizer) RequireProject(p Principal, perm Permission, resourceTenant, projectID string) error {
	if err := a.Require(p, perm, resourceTenant); err != nil {
		return err
	}
	if !a.ScopeOf(p).Allows(projectID) {
		if projectID == "" {
			return fmt.Errorf("%w: tenant-wide (unassigned) records require %s", ErrForbidden, PermScopeTenantWide)
		}
		return fmt.Errorf("%w: project %s is outside the principal's scope", ErrForbidden, projectID)
	}
	return nil
}

// RequireStepUp demands a recent multi-factor authentication.
func (a *Authorizer) RequireStepUp(p Principal) error {
	if !p.MFA || p.AuthTime.IsZero() || a.now().Sub(p.AuthTime) > a.StepUpMaxAge {
		return fmt.Errorf("%w (within %s)", ErrStepUpRequired, a.StepUpMaxAge)
	}
	return nil
}

// JournalActors are the recorded workflow participants of a journal.
type JournalActors struct {
	CreatedBy  string
	ApprovedBy string
}

// CheckSoDApprove enforces that the approver is not the preparer.
func (a *Authorizer) CheckSoDApprove(p Principal, actors JournalActors) error {
	if actors.CreatedBy == p.UserID {
		return fmt.Errorf("%w: preparer cannot approve their own journal", ErrSoD)
	}
	return nil
}

// CheckSoDPost enforces the posting separation rules.
func (a *Authorizer) CheckSoDPost(p Principal, actors JournalActors) error {
	if actors.ApprovedBy == "" {
		return fmt.Errorf("%w: journal has no approver", ErrSoD)
	}
	if a.RequireDistinctPoster && actors.ApprovedBy == p.UserID {
		return fmt.Errorf("%w: approver cannot also post", ErrSoD)
	}
	if actors.CreatedBy == p.UserID && a.RequireDistinctPoster {
		return fmt.Errorf("%w: preparer cannot post their own journal", ErrSoD)
	}
	return nil
}

// CheckMakerChecker enforces that a checker is not the maker of a record.
func CheckMakerChecker(checker Principal, maker, what string) error {
	if checker.UserID == maker {
		return fmt.Errorf("%w: the creator of a %s cannot approve or reject it", ErrSoD, what)
	}
	return nil
}
