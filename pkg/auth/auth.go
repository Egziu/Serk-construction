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
	"strings"
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

	// PermIdentityRevoke revokes other people's sessions (termination, role
	// removal, suspected compromise). Everyone may revoke their own.
	PermIdentityRevoke Permission = "identity.revoke_sessions"

	// Procure-to-pay (Journey A). Every pair maker/checker below is held by
	// different seed roles (TestDefaultRolesSeparateDuties).
	PermP2PRead             Permission = "p2p.read"
	PermP2PPolicyManage     Permission = "p2p.policy.manage"
	PermP2PPolicyApprove    Permission = "p2p.policy.approve"
	PermSupplierManage      Permission = "supplier.manage"
	PermSupplierApprove     Permission = "supplier.approve"
	PermSupplierBankApprove Permission = "supplier.bank.approve"
	PermBankAcctManage      Permission = "bankacct.manage"
	PermBankAcctApprove     Permission = "bankacct.approve"
	PermBOQManage           Permission = "boq.manage"
	PermBOQApprove          Permission = "boq.approve"
	PermPRCreate            Permission = "pr.create"
	PermPRApprove           Permission = "pr.approve"
	PermRFQManage           Permission = "rfq.manage"
	PermRFQEvaluate         Permission = "rfq.evaluate"
	PermRFQAward            Permission = "rfq.award"
	PermPOManage            Permission = "po.manage"
	PermPOApprove           Permission = "po.approve"
	PermBudgetOverride      Permission = "budget.override"
	PermGRNCreate           Permission = "grn.create"
	PermGRNConfirm          Permission = "grn.confirm"
	PermAPEnter             Permission = "ap.enter"
	PermAPApprove           Permission = "ap.approve"
	PermAPApproveException  Permission = "ap.approve_exception"
	PermPaymentPrepare      Permission = "payment.prepare"
	PermPaymentApprove      Permission = "payment.approve"
	PermPaymentRelease      Permission = "payment.release"
	PermBankImport          Permission = "bank.import"
	PermBankReconcile       Permission = "bank.reconcile"
	// PermBankDetailsReveal shows a full bank account number (with fresh MFA,
	// a stated purpose and an audit record). Everyone else sees it masked.
	PermBankDetailsReveal Permission = "bank.details.reveal"

	// Contract to cash (Journey B). Maker/checker pairs are held by
	// different seed roles (TestDefaultRolesSeparateDuties).
	PermCustomerManage        Permission = "customer.manage"
	PermCustomerApprove       Permission = "customer.approve"
	PermContractPolicyManage  Permission = "contract.policy.manage"
	PermContractPolicyApprove Permission = "contract.policy.approve"
	PermContractManage        Permission = "contract.manage"
	PermContractApprove       Permission = "contract.approve"
	PermMeasureCreate         Permission = "measure.create"
	PermMeasureVerify         Permission = "measure.verify"
	PermIPCPrepare            Permission = "ipc.prepare"
	PermIPCCertify            Permission = "ipc.certify"
	PermARInvoiceCreate       Permission = "ar.invoice.create"
	PermARInvoiceApprove      Permission = "ar.invoice.approve"
	PermARReceiptCreate       Permission = "ar.receipt.create"
	PermARReceiptConfirm      Permission = "ar.receipt.confirm"
	PermARCreditCreate        Permission = "ar.credit.create"
	PermARCreditApprove       Permission = "ar.credit.approve"

	// Stock valuation (Journey C). Maker/checker pairs are held by different
	// seed roles (TestDefaultRolesSeparateDuties).
	PermStockItemManage    Permission = "stock.item.manage"
	PermStockItemApprove   Permission = "stock.item.approve"
	PermWarehouseManage    Permission = "warehouse.manage"
	PermStockReceive       Permission = "stock.receive"
	PermStockIssue         Permission = "stock.issue"
	PermStockIssueApprove  Permission = "stock.issue.approve"
	PermStockCount         Permission = "stock.count"
	PermStockAdjustApprove Permission = "stock.adjust.approve"
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
	"accountant": {Name: "accountant", Permissions: []Permission{PermJournalCreate, PermJournalRead, PermFXRead, PermScopeTenantWide, PermWorkflowRead,
		PermBankReconcile, PermP2PRead}},
	// Treasury prepares and releases payments (two different officers: the
	// database refuses release by the preparer). It does not import bank
	// statements: the evidence that settles a payment comes from someone
	// independent of the payment (review 3, H2).
	"treasury_officer": {Name: "treasury_officer", Permissions: []Permission{PermFXManage, PermFXRead, PermScopeTenantWide, PermWorkflowRead,
		PermPaymentPrepare, PermPaymentRelease, PermBankAcctManage, PermP2PRead}},
	"bank_statement_officer": {Name: "bank_statement_officer", Permissions: []Permission{PermBankImport, PermScopeTenantWide, PermP2PRead}},
	"finance_manager": {Name: "finance_manager", Permissions: []Permission{PermJournalApprove, PermJournalRead, PermFXRead, PermFXApprove,
		PermFXPolicyApprove, PermWBSApprove, PermScopeTenantWide, PermWorkflowRead, PermAPApproveException, PermPaymentApprove,
		PermSupplierBankApprove, PermBankDetailsReveal, PermCustomerApprove, PermStockItemApprove, PermP2PRead}},
	"controller": {Name: "controller", Permissions: []Permission{PermJournalPost, PermJournalReverse, PermJournalRead, PermPeriodClose,
		PermAccountManage, PermFXRead, PermScopeTenantWide, PermWorkflowRead, PermP2PPolicyManage, PermContractPolicyManage, PermP2PRead}},
	"cfo": {Name: "cfo", Permissions: []Permission{PermJournalRead, PermFXRead, PermFXApprove, PermFXApproveExcept, PermFXPolicyApprove,
		PermPeriodReopen, PermAuditRead, PermScopeTenantWide, PermWorkflowRead, PermWorkflowPublish, PermApprovalHighValue,
		PermPaymentApprove, PermP2PPolicyApprove, PermBudgetOverride, PermBankAcctApprove, PermBankDetailsReveal, PermContractApprove, PermContractPolicyApprove, PermP2PRead}},
	"auditor":            {Name: "auditor", Permissions: []Permission{PermJournalRead, PermAuditRead, PermFXRead, PermScopeTenantWide, PermWorkflowRead, PermP2PRead}},
	"project_manager":    {Name: "project_manager", Permissions: []Permission{PermJournalRead, PermFXRead, PermWBSManage, PermWorkflowRead, PermPRApprove, PermStockIssueApprove, PermP2PRead}},
	"project_accountant": {Name: "project_accountant", Permissions: []Permission{PermJournalCreate, PermJournalRead, PermFXRead, PermWorkflowRead}},
	"process_owner":      {Name: "process_owner", Permissions: []Permission{PermWorkflowDefine, PermWorkflowRead}},
	"workflow_admin":     {Name: "workflow_admin", Permissions: []Permission{PermWorkflowAdmin, PermWorkflowRead, PermScopeTenantWide}},
	// Identity administration holds no financial permission at all.
	"security_admin": {Name: "security_admin", Permissions: []Permission{PermIdentityRevoke, PermAuditRead}},
	// Journey A operational roles.
	"estimator":           {Name: "estimator", Permissions: []Permission{PermBOQManage, PermP2PRead}},
	"commercial_manager":  {Name: "commercial_manager", Permissions: []Permission{PermBOQApprove, PermContractManage, PermIPCCertify, PermARCreditApprove, PermP2PRead}},
	"site_engineer":       {Name: "site_engineer", Permissions: []Permission{PermPRCreate, PermGRNConfirm, PermRFQEvaluate, PermMeasureVerify, PermStockIssueApprove, PermP2PRead}},
	"storekeeper":         {Name: "storekeeper", Permissions: []Permission{PermGRNCreate, PermStockReceive, PermStockIssue, PermStockCount, PermP2PRead}},
	"procurement_officer": {Name: "procurement_officer", Permissions: []Permission{PermSupplierManage, PermRFQManage, PermPOManage, PermStockItemManage, PermP2PRead}},
	"procurement_manager": {Name: "procurement_manager", Permissions: []Permission{PermSupplierApprove, PermRFQAward, PermPOApprove, PermWarehouseManage, PermP2PRead}},
	"ap_clerk":            {Name: "ap_clerk", Permissions: []Permission{PermAPEnter, PermP2PRead}},
	"ap_supervisor":       {Name: "ap_supervisor", Permissions: []Permission{PermAPApprove, PermP2PRead}},
	// Journey B operational roles.
	"quantity_surveyor": {Name: "quantity_surveyor", Permissions: []Permission{PermMeasureCreate, PermIPCPrepare, PermP2PRead}},
	"ar_clerk": {Name: "ar_clerk", Permissions: []Permission{PermCustomerManage, PermARInvoiceCreate, PermARReceiptCreate, PermARCreditCreate, PermScopeTenantWide,
		PermP2PRead}},
	// Approves stock count adjustments. Separate from the journal chain: the
	// adjustment journal it generates is approved by finance and posted by a
	// controller, and its preparer may do neither.
	"inventory_controller": {Name: "inventory_controller", Permissions: []Permission{PermStockAdjustApprove, PermScopeTenantWide, PermP2PRead}},
	"ar_supervisor":        {Name: "ar_supervisor", Permissions: []Permission{PermARInvoiceApprove, PermARReceiptConfirm, PermScopeTenantWide, PermP2PRead}},
}

// Principal kinds, as asserted by the identity provider (token claim
// "pkind"). Only KindHuman principals may approve or release payments; an
// absent or unknown kind is never treated as human.
const (
	KindHuman   = "human"
	KindService = "service"
	KindAI      = "ai"
)

// DraftActions are the attested actions a principal that is not asserted
// human (an AI assistant, an integration service, or an unknown kind) may
// perform: preparing and submitting drafts, recording received quotes,
// importing bank statements and starting workflows. Every other action
// approves, certifies, verifies, confirms, posts, releases, closes or
// configures something and is reserved to people; new actions are therefore
// human-only by default. The database applies the same rule to every
// attestation (migration 0019, approval_is_draft_action).
func IsDraftAction(action string) bool {
	switch action {
	case "rfq.quote.record", "bank.import", "workflow.start":
		return true
	}
	return strings.HasSuffix(action, ".create") || strings.HasSuffix(action, ".submit")
}

// ReservedPermissionPrefix marks permissions that only the platform derives
// from verified identity attributes (e.g. "principal.human"); a role can never
// grant them.
const ReservedPermissionPrefix = "principal."

// Principal is the authenticated caller bound to exactly one tenant.
type Principal struct {
	// Kind is the identity provider's assertion of what the principal is
	// (KindHuman, KindService, KindAI); "" means unknown.
	Kind     string
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
	// SessionID is the token identifier (JWT "jti"); IssuedAt is the token's
	// "iat". Both are checked against the shared revocation list on every
	// request and inside every approval transaction.
	SessionID string
	IssuedAt  time.Time
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
				if strings.HasPrefix(string(perm), ReservedPermissionPrefix) {
					continue // never grantable through a role
				}
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
			if x == perm && !strings.HasPrefix(string(x), ReservedPermissionPrefix) {
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
