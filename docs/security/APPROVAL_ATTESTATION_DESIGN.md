# Approval attestation design (GATEA-APPROVAL-01)

Status: implemented in migration 0007 (commit eb8094d), with least privilege tightened in 0008 (commit 1371d63).
Evidence: `docs/security/evidence/approval-forgery-before.txt` shows the attack succeeding on ea3533c, and `approval-forgery-after.txt` shows it denied. `docs/security/ADVERSARIAL_RESULTS.md` lists the attacks.

## 1. Problem

At 0.2.0 Gate A (ea3533c), the SQL layer checked that approval fields such as `approved_by`, `posted_by`, `decided_by`, `mfa` and `approver_mfa` were present and well formed. It did not check who wrote them. Any tenant database login could write those fields directly, and so could:

- approve and post journals as two invented people who both had `mfa=true`;
- fabricate a workflow trail, including decisions and effects;
- insert and publish a workflow definition;
- approve an FX source;
- close a period.

The reproduction is in `approval-forgery-before.txt`. The API was the only real enforcement point, so a leaked tenant credential bypassed it completely.

## 2. Decision

PostgreSQL is the trust boundary for authority, and it trusts exactly one thing: a short-lived, single-use attestation signed by the API's approval key. Each attestation is bound to:

- tenant, actor and action;
- the subject's live content hash;
- the decision context;
- the actor's permissions;
- MFA assurance and when authentication happened.

No row field asserted by the caller counts as evidence.

### 2.1 Who holds the key

| Key | Holder | Storage |
|---|---|---|
| Master approval secret (≥32 bytes) | **API process only** (`serk-api`), and the provisioning job (`serk-migrate provision-tenant`) | `SERK_APPROVAL_SIGNING_KEY` / `_FILE` (Docker secret `approval_signing_key` in prod compose). Must differ from `SERK_TENANT_DB_SECRET`; config refuses to start otherwise. |
| Per-tenant verification key `K_t = HMAC-SHA256(master, "serk-approval:" ‖ tenant)` | PostgreSQL table `approval_keys` | Owner-only: no grant to any runtime role. It is written only by `approval_key_install()`, a definer function with no grants, called by the migrator. |

The relay, the timer, the health probe and tenant logins never see either key. No AI principal exists that could hold one.

### 2.2 Attestation format (`pkg/attest`)

The attestation carries these claims: `v=1`, `kid`, `tenant`, `actor`, `action`, `subject_type`, `subject_id`, `subject_hash`, `ctx`, `perms[]`, `mfa`, `auth_time`, `iat`, `exp`, `nonce` (UUID) and `sig`.

The canonical message joins the fields with U+001F in a fixed order. Perms are sorted bytewise; `COLLATE "C"` gives the same order in SQL. Go refuses any field that contains U+001F, so the separator cannot be injected. `sig = hex(HMAC-SHA256(K_t, canonical))`.

The TTL defaults to 2 minutes and is capped at 5 minutes, enforced both in Go and in SQL (`exp − iat ≤ 300`).

### 2.3 Verification in SQL: `approval_authorize(jsonb)`

This is a SECURITY DEFINER function with `search_path=pg_catalog, public`, executable by `serk_app` only. It checks:

1. A tenant session exists, and `tenant` equals `current_tenant()`, which comes from `session_user` and cannot be changed by GUC.
2. `v=1`, the required fields are present and the nonce is a UUID.
3. The key for (`tenant`, `kid`) is active, and the HMAC matches.
4. `iat ≤ now+60s`, `exp > now`, `exp − iat ≤ 300` and `exp > iat`.
5. `subject_hash` equals `approval_subject_hash(type, id)`, computed **now** over the live row, scoped to the tenant. For a journal this is the header plus every line (account, side, amounts, currencies, FX snapshot, project, cost code, memo) plus `command_hash`. Content edited after signing is therefore refused.
6. The function writes an evidence row into `approval_attestations`. The nonce is the primary key, so a second use is refused as a replay. The row also records the `txid` and `mfa_fresh = mfa ∧ auth_time within 600 s`.

`approval_attestations` is append-only (trigger) and has RLS. The tenant can only SELECT it.

### 2.4 Enforcement: `*_attest` triggers

Each `*_attest` trigger fires BEFORE the existing `*_guard` triggers, because PostgreSQL fires triggers in name order. It calls `approval_require(action, type, id, actor, perms, need_mfa)`. That call finds evidence **in the same transaction** with the same action, subject and actor, an overlapping permission and fresh MFA where required. The triggers cover:

- **Journals:** created only as DRAFT with no approval fields. APPROVED requires `journal.approve` by `approved_by`. POSTED requires `journal.post` by `posted_by`. CANCELLED requires `journal.cancel`. REVERSED requires `journal.post` by `reversed_by`.
- **Fiscal periods:** created only OPEN. Close and lock require `period.close`. Reopen requires `period.reopen` plus MFA.
- **FX:**
  - Sources need `fx.source.approve` or `fx.source.retire`.
  - Policies need `fx.policy.decide`, and a RETIRED policy requires its successor's decision in the same transaction.
  - Snapshots need approve, reject or withdraw. `approver_mfa` is **overwritten from the evidence**. A variance exception requires `fx.approve_exception` plus MFA.
- **WBS versions:** `wbs.decide`; supersede requires the successor's decision.
- **Workflow definitions:**
  - INSERT requires `workflow.define` attested over `body_hash`, with actor equal to `proposed_by`. The API validates the definition before it signs.
  - Publication is possible only through `workflow_decide_definition`, which requires `workflow.decide_definition` with `ctx = status`, and MFA for PUBLISHED.
- **Workflow instances:**
  - Start requires the definition's `start_permission` with `ctx = definition_id`.
  - Cancel requires `workflow.admin`.
  - `ended_by` is derived by the database, not supplied by the caller.
- **Workflow decisions:** `workflow.decide`, with the route step's permission and `ctx = step_index:decision`. Evidence for "step 1 APPROVE" cannot authorise "step 2" or "REJECT". `mfa` comes from the evidence.

The deeper guards from 0002 and 0006 still run after these triggers: segregation of duties, quorum, mandatory workflow gate, balance, period locks and the LOCKED terminal state. The tests use genuine attestations to reach them, so they stay covered.

## 3. Threat model: what each compromise yields

| Compromised | Can | Cannot |
|---|---|---|
| **Tenant DB login** (password, SQL injection in a tenant session) | Read its own tenant's data; create drafts; write the non-authority columns it is granted, such as `name`. | Create evidence. Approve, post, cancel, reverse, close or reopen. Approve FX. Publish, start, decide or cancel workflows. Fake MFA, replay, or reuse evidence for other content, steps or actors. Read keys. Reach another tenant. Delete or rewrite history. All of this is tested; see ADVERSARIAL_RESULTS.md. |
| **Relay / timer / health login** | Their own narrow grants. | Any approval function or business table write; the function boundary is tested. |
| **API process** (RCE, or master secret leaked) | Sign attestations for **any actor in any tenant**, i.e. full authority over workflow and ledger state. Segregation-of-duties guards still require two distinct actor names, but the attacker chooses those names. | Bypass the balance, period, immutability, FX eligibility and workflow-structure guards, which do not depend on identity. |
| **Migrator / schema owner** | Read `approval_keys` and forge evidence for any tenant; disable triggers. | Nothing is technically prevented. |
| **Superuser / DBA** | Everything. | Nothing is technically prevented. |

### Residual risks (accepted for Gate A only with sign-off; tracked in ISSUE_REGISTER)

- **R-SIGNER (High).** The signer is the API process, so API compromise means authority compromise. *Planned:*
  - move signing into a separate approval service that verifies the OIDC token, the step-up MFA claim and the user's role assignment itself, holding the key in an HSM or KMS;
  - switch to asymmetric signatures (Ed25519), so the database holds only public keys and the owner can no longer forge. pgcrypto has no Ed25519 verify, so this needs a vetted extension or a verifier service.
- **R-MFA-SOURCE (High).** `mfa` and `auth_time` come from the principal that the API derived from a JWT. They are only as trustworthy as the IdP integration. Real OIDC, JWKS and step-up are not implemented yet (GATEA-07 is BLOCKED). The SQL layer does enforce freshness and binding to the exact action.
- **R-MAKER (Medium).** Maker-side attribution (`created_by` on drafts, `proposed_by` excepted) is asserted by the tenant login and not attested. A compromised tenant login could create drafts that name someone else as maker. It still cannot approve them, and segregation of duties then works against that invented name. *Planned:* attest creation of financial documents.
- **R-DBA (Medium).** The owner or superuser can disable triggers or read keys. *Mitigations planned:*
  - an off-host evidence copy, exporting the audit chain and attestation table to WORM storage;
  - alerting on `ALTER TABLE … DISABLE TRIGGER` through pgaudit or event triggers;
  - a dedicated non-superuser migrator.
  - Enterprise or high-risk tenants should be evaluated for a dedicated database.
- **R-CLOCK (Low).** `now()` is the transaction start time, so a long transaction can accept an attestation up to its own duration past `exp`. Statement timeouts bound this.
- **R-POLICY-VERSION (Low).** For workflow-governed subjects, the attestation is bound to the definition through `workflow_instance` (definition id) and through `body_hash` for definitions. Ledger approvals carry no explicit "policy version" claim, because the policy is the code at that commit.

## 4. Key rotation

`approval_keys` is keyed by (tenant, `kid`). To rotate:

1. Install a new `kid` for every tenant with `serk-migrate provision-tenant`; that step is idempotent per tenant.
2. Switch the API's `Signer.KeyID`.
3. After the maximum TTL (5 minutes), set `active=false` on the old `kid`.

Steps 2 and 3 are **NOT IMPLEMENTED as a CLI command yet**; today they are manual SQL by the owner. Evidence rows keep their `key_id` permanently.

## 5. Failure behaviour

- If the API has no signer configured, `authorize` returns `ErrApprovalSigning` and nothing is signed; tested in TestAttestation_LegitimateTwoPersonFlowLeavesEvidence.
- Every verification failure raises SQLSTATE 42501 (insufficient_privilege) with a specific message. The transaction rolls back, so no partial approval is possible.
- An attestation is single-use even after a rollback? **No.** A rolled-back transaction also rolls back its evidence row, so the nonce becomes usable again. The attestation is still only valid for 5 minutes, for the same subject content, actor and action, so a retry can repeat only exactly what was authorised. That is the intended idempotent retry behaviour.
