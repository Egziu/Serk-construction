package kernel

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/auth"
)

// ProposeWBSVersion submits a complete draft WBS version (nodes and cost
// codes) for a project. Requires wbs.manage within the project scope.
func (s *Service) ProposeWBSVersion(ctx context.Context, p auth.Principal, projectID, description string, nodes []postgres.WBSNode, codes []postgres.CostCode) (postgres.WBSVersion, map[string]string, error) {
	if err := s.authz.RequireProject(p, auth.PermWBSManage, p.TenantID, projectID); err != nil {
		return postgres.WBSVersion{}, nil, err
	}
	if err := requireReason(description); err != nil {
		return postgres.WBSVersion{}, nil, err
	}
	var v postgres.WBSVersion
	var ids map[string]string
	err := s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		v, ids, err = postgres.InsertWBSVersion(ctx, tx, p.TenantID, projectID, description, p.UserID, nodes, codes)
		if err != nil {
			return err
		}
		return s.record(ctx, tx, p, "wbs.propose", "wbs_version", v.ID, "wbs.version.proposed",
			map[string]any{"project_id": projectID, "version": v.Version, "nodes": len(nodes), "cost_codes": len(codes)})
	})
	return v, ids, err
}

// DecideWBSVersion approves or rejects a draft (checker ≠ maker). Approval
// supersedes the previously approved version atomically; codes of a
// superseded version can no longer be posted to.
func (s *Service) DecideWBSVersion(ctx context.Context, p auth.Principal, versionID string, approve bool, reason string) error {
	if err := s.authz.Require(p, auth.PermWBSApprove, p.TenantID); err != nil {
		return err
	}
	if err := requireReason(reason); err != nil {
		return err
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		v, err := postgres.GetWBSVersion(ctx, tx, versionID, true)
		if err != nil {
			return err
		}
		if err := s.authz.RequireProject(p, auth.PermWBSApprove, v.TenantID, v.ProjectID); err != nil {
			return err
		}
		if err := auth.CheckMakerChecker(p, v.CreatedBy, "WBS version"); err != nil {
			return err
		}
		if err := postgres.DecideWBSVersion(ctx, tx, v, approve, p.UserID); err != nil {
			return err
		}
		ev := "wbs.version.rejected"
		if approve {
			ev = "wbs.version.approved"
		}
		return s.record(ctx, tx, p, "wbs.decide", "wbs_version", versionID, ev,
			map[string]any{"project_id": v.ProjectID, "version": v.Version, "approve": approve, "reason": reason})
	})
}

// SetAccountCostCoding sets NONE / OPTIONAL / REQUIRED_ON_PROJECT.
func (s *Service) SetAccountCostCoding(ctx context.Context, p auth.Principal, accountID, policy string) error {
	if err := s.authz.Require(p, auth.PermAccountManage, p.TenantID); err != nil {
		return err
	}
	return s.store.WithTenant(ctx, p.TenantID, func(ctx context.Context, tx pgx.Tx) error {
		if err := postgres.SetAccountCostCoding(ctx, tx, accountID, policy); err != nil {
			return err
		}
		return s.record(ctx, tx, p, "account.cost_coding", "account", accountID, "account.cost_coding_changed", map[string]any{"policy": policy})
	})
}
