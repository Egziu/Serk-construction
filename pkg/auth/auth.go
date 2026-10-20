// Package auth implements the Enterprise Identity and Privilege Engine's
// deterministic authorization core (Pillar 3): role-based permissions,
// tenant binding and segregation-of-duties (SoD) rules.
//
// Authorization decisions never involve AI (LAW 01) and are evaluated on the
// server for every command.
package auth

import (
	"errors"
	"fmt"
	"sort"
)

// Permission is a fine-grained capability string "<resource>.<action>".
type Permission string

const (
	PermJournalCreate  Permission = "journal.create"
	PermJournalApprove Permission = "journal.approve"
	PermJournalPost    Permission = "journal.post"
	PermJournalReverse Permission = "journal.reverse"
	PermJournalRead    Permission = "journal.read"
	PermFXRead         Permission = "fx.read"
	PermFXManage       Permission = "fx.manage"
	PermAccountManage  Permission = "account.manage"
	PermPeriodClose    Permission = "period.close"
	PermAuditRead      Permission = "audit.read"
)

// Role is a named permission bundle. Roles are tenant-scoped data in
// production; the defaults below are the seed set.
type Role struct {
	Name        string
	Permissions []Permission
}

// DefaultRoles is the seed role catalogue. Note that no single default role
// holds create+approve+post for journals: that separation is the SoD baseline.
var DefaultRoles = map[string]Role{
	"accountant":      {Name: "accountant", Permissions: []Permission{PermJournalCreate, PermJournalRead, PermFXRead}},
	"finance_manager": {Name: "finance_manager", Permissions: []Permission{PermJournalApprove, PermJournalRead, PermFXRead, PermFXManage}},
	"controller":      {Name: "controller", Permissions: []Permission{PermJournalPost, PermJournalReverse, PermJournalRead, PermPeriodClose, PermAccountManage, PermFXRead}},
	"auditor":         {Name: "auditor", Permissions: []Permission{PermJournalRead, PermAuditRead, PermFXRead}},
	"project_manager": {Name: "project_manager", Permissions: []Permission{PermJournalRead, PermFXRead}},
}

// Principal is the authenticated caller bound to exactly one tenant.
type Principal struct {
	UserID   string
	TenantID string
	Roles    []string
	// ProjectIDs, when non-empty, restricts the principal to those projects
	// (ABAC attribute). Empty means all projects of the tenant.
	ProjectIDs []string
}

// Errors.
var (
	ErrUnauthenticated = errors.New("auth: unauthenticated")
	ErrForbidden       = errors.New("auth: forbidden")
	ErrTenantMismatch  = errors.New("auth: resource belongs to another tenant")
	ErrSoD             = errors.New("auth: segregation of duties violation")
)

// Authorizer evaluates permissions against a role catalogue.
type Authorizer struct {
	roles map[string]Role
	// RequireDistinctPoster requires poster != approver in addition to the
	// always-on approver != preparer rule.
	RequireDistinctPoster bool
}

// NewAuthorizer builds an authorizer over a role catalogue.
func NewAuthorizer(roles map[string]Role, requireDistinctPoster bool) *Authorizer {
	if roles == nil {
		roles = DefaultRoles
	}
	return &Authorizer{roles: roles, RequireDistinctPoster: requireDistinctPoster}
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

// RequireProject additionally enforces the principal's project attribute.
func (a *Authorizer) RequireProject(p Principal, perm Permission, resourceTenant, projectID string) error {
	if err := a.Require(p, perm, resourceTenant); err != nil {
		return err
	}
	if projectID == "" || len(p.ProjectIDs) == 0 {
		return nil
	}
	for _, id := range p.ProjectIDs {
		if id == projectID {
			return nil
		}
	}
	return fmt.Errorf("%w: project %s", ErrForbidden, projectID)
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
