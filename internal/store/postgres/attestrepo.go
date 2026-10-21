package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// SubjectHash is the database's content hash of an approval subject as it
// is now (approval_subject_hash); "" when the subject does not exist.
func SubjectHash(ctx context.Context, tx pgx.Tx, subjectType, subjectID string) (string, error) {
	var h *string
	if err := tx.QueryRow(ctx, `SELECT approval_subject_hash($1, $2)`, subjectType, subjectID).Scan(&h); err != nil {
		return "", err
	}
	if h == nil {
		return "", nil
	}
	return *h, nil
}

// Authorize hands a signed attestation to PostgreSQL, which verifies it and
// records it as evidence for this transaction (approval_authorize).
func Authorize(ctx context.Context, tx pgx.Tx, attestationJSON string) error {
	_, err := tx.Exec(ctx, `SELECT approval_authorize($1::jsonb)`, attestationJSON)
	return err
}

// InstallApprovalKey installs a tenant's attestation verification key. It
// runs on the schema-owner connection during provisioning.
func InstallApprovalKey(ctx context.Context, admin *pgx.Conn, tenantID, keyID string, key []byte) error {
	if len(key) < 32 {
		return errors.New("postgres: approval key must be at least 32 bytes")
	}
	_, err := admin.Exec(ctx, `SELECT approval_key_install($1::uuid, $2, $3)`, tenantID, keyID, key)
	return err
}
