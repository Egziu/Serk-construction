package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// WBSNode is a node of a draft WBS version.
type WBSNode struct {
	Code       string
	Name       string
	ParentCode string // "" for a root node
}

// CostCode is a cost code attached to a WBS node.
type CostCode struct {
	ID        string
	NodeCode  string
	Code      string
	Name      string
	CostType  string
	ValidFrom time.Time
	ValidTo   *time.Time
}

// WBSVersion is a version header.
type WBSVersion struct {
	ID, TenantID, LegalEntityID, ProjectID string
	Version                                int
	Status, CreatedBy, ApprovedBy          string
}

// InsertWBSVersion creates a DRAFT version with its nodes and cost codes.
// Parents must appear before children. Returns the version and code ids.
func InsertWBSVersion(ctx context.Context, tx pgx.Tx, tenantID, projectID, description, by string, nodes []WBSNode, codes []CostCode) (WBSVersion, map[string]string, error) {
	v := WBSVersion{ID: newID(), TenantID: tenantID, ProjectID: projectID, Status: "DRAFT", CreatedBy: by}
	err := tx.QueryRow(ctx, `INSERT INTO wbs_versions(id,tenant_id,legal_entity_id,project_id,version,description,created_by)
		SELECT $1::uuid, $2::uuid, p.legal_entity_id, p.id,
		       (SELECT COALESCE(MAX(version),0)+1 FROM wbs_versions WHERE project_id=$3::uuid), $4, $5
		  FROM projects p WHERE p.id=$3::uuid
		RETURNING legal_entity_id::text, version`, v.ID, tenantID, projectID, description, by).Scan(&v.LegalEntityID, &v.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		return WBSVersion{}, nil, ErrNotFound
	}
	if err != nil {
		return WBSVersion{}, nil, err
	}
	nodeIDs := map[string]string{}
	for _, n := range nodes {
		id := newID()
		var parent *string
		if n.ParentCode != "" {
			p, ok := nodeIDs[n.ParentCode]
			if !ok {
				return WBSVersion{}, nil, errors.New("wbs: parent " + n.ParentCode + " must precede " + n.Code)
			}
			parent = &p
		}
		if _, err := tx.Exec(ctx, `INSERT INTO wbs_nodes(id,tenant_id,project_id,version_id,parent_id,code,name) VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5::uuid,$6,$7)`,
			id, tenantID, projectID, v.ID, parent, n.Code, n.Name); err != nil {
			return WBSVersion{}, nil, err
		}
		nodeIDs[n.Code] = id
	}
	codeIDs := map[string]string{}
	for _, c := range codes {
		node, ok := nodeIDs[c.NodeCode]
		if !ok {
			return WBSVersion{}, nil, errors.New("wbs: cost code " + c.Code + " references unknown node " + c.NodeCode)
		}
		id := newID()
		if _, err := tx.Exec(ctx, `INSERT INTO cost_codes(id,tenant_id,project_id,wbs_node_id,code,name,cost_type,valid_from,valid_to,created_by)
			VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6,$7,$8::date,$9::date,$10)`,
			id, tenantID, projectID, node, c.Code, c.Name, c.CostType, c.ValidFrom, c.ValidTo, by); err != nil {
			return WBSVersion{}, nil, err
		}
		codeIDs[c.NodeCode+"/"+c.Code] = id
	}
	return v, codeIDs, nil
}

// GetWBSVersion loads a version header; lock takes a row lock.
func GetWBSVersion(ctx context.Context, tx pgx.Tx, id string, lock bool) (WBSVersion, error) {
	q := `SELECT id::text, tenant_id::text, legal_entity_id::text, project_id::text, version, status, created_by, COALESCE(approved_by,'')
		FROM wbs_versions WHERE id=$1::uuid`
	if lock {
		q += " FOR UPDATE"
	}
	var v WBSVersion
	err := tx.QueryRow(ctx, q, id).Scan(&v.ID, &v.TenantID, &v.LegalEntityID, &v.ProjectID, &v.Version, &v.Status, &v.CreatedBy, &v.ApprovedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return WBSVersion{}, ErrNotFound
	}
	return v, err
}

// DecideWBSVersion approves (superseding the current approved version) or
// rejects a DRAFT version.
func DecideWBSVersion(ctx context.Context, tx pgx.Tx, v WBSVersion, approve bool, by string) error {
	if approve {
		if _, err := tx.Exec(ctx, `UPDATE wbs_versions SET status='SUPERSEDED' WHERE project_id=$1::uuid AND status='APPROVED'`, v.ProjectID); err != nil {
			return err
		}
	}
	to := "REJECTED"
	if approve {
		to = "APPROVED"
	}
	tag, err := tx.Exec(ctx, `UPDATE wbs_versions SET status=$2, approved_by=CASE WHEN $2='APPROVED' THEN $3 END, approved_at=CASE WHEN $2='APPROVED' THEN now() END
		WHERE id=$1::uuid AND status='DRAFT'`, v.ID, to, by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrVersionConflict
	}
	return nil
}

// SetAccountCostCoding sets an account's cost-coding policy.
func SetAccountCostCoding(ctx context.Context, tx pgx.Tx, accountID, policy string) error {
	tag, err := tx.Exec(ctx, `UPDATE accounts SET cost_coding=$2 WHERE id=$1::uuid`, accountID, policy)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
