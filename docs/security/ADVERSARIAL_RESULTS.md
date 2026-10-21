# Adversarial results: approval provenance and least privilege

Every result below was **executed** on a disposable, local PostgreSQL 16.15 cluster with Go 1.24.7, using synthetic fixtures only. No production, staging or customer system was touched.

The raw logs are the evidence. This file only indexes them:

| Artifact | What it is |
|---|---|
| `docs/security/evidence/approval-forgery-before.txt` | Vulnerable commit **ea3533c** (0.2.0-gate-a). `go test -count=1 ./internal/kernel -run ApprovalProvenance -v`, connected as the per-tenant login `serk_t_<tenant>` using raw SQL. |
| `docs/security/evidence/approval-forgery-after.txt` | Fixed commit **eb8094d** (migration 0007, sha256 `a1ad3fd9…`). The same suite plus `Attestation`, with 40 denials logged and 10/10 tests PASS. |
| `docs/audit/evidence/final-test-run.log` | Full regression log for the delivered commit. Updated at packaging. |

Attacker model: an ordinary **tenant database credential** with no approval signing key, issuing raw SQL. The compromise of other principals is analysed in APPROVAL_ATTESTATION_DESIGN.md §3.

## 1. Directive §2.3 mandatory attacker tests

| # | Attack (directive §2.3) | Before (ea3533c) | After (eb8094d → 1371d63) | Test |
|---|---|---|---|---|
| 1 | Call `workflow_decide_definition` as another actor without an approval assertion | **SUCCEEDED**: definition became PUBLISHED | DENIED: `workflow.decide_definition … requires a verified approval attestation` | TestApprovalProvenance_WorkflowDefinitionPublication |
| 2 | Insert 2+ fabricated `workflow_decisions` with unrelated identities and `mfa=true` | **SUCCEEDED**: fabricated review decision, effect and approval | DENIED: `workflow.decide of workflow_instance … requires a verified approval attestation` | TestApprovalProvenance_ForgedWorkflowTrail |
| 3 | Insert an apparently authorized `workflow_effect`, then approve or post the protected journal | **SUCCEEDED**: journal APPROVED, then POSTED by two invented people | DENIED at the decision; the journal approve and post each need their own attestation | TestApprovalProvenance_ForgedWorkflowTrail, _DirectJournalApprovalAndPosting |
| 4 | Approve an FX source, snapshot or exception by setting `approved_by` and `approver_mfa` | **SUCCEEDED** for the FX source; the test stopped at the first success, so snapshot and exception were not reached on ea3533c | DENIED for source, policy, rate, and out-of-tolerance rate with `approver_mfa=true` | TestApprovalProvenance_FXApprovals |
| 5 | Publish malformed but valid JSON definitions through raw SQL | **SUCCEEDED**: the draft was inserted as an invented author | DENIED: an INSERT needs `workflow.define` attested over `body_hash`, and the API signs only after validating the definition | TestApprovalProvenance_WorkflowDefinitionPublication |
| 6 | Replay; swap document hash; change amount, tenant or subject; expired | n/a (no assertions existed) | DENIED for each: replay, journal A → B, actor swap, mfa/exp/actor/perms tampering, wrong key, cross-tenant, expired, content changed after signing (amount), missing permission | TestAttestation_ReplaySubstitutionExpiryAndTampering |
| 6b | Reuse step-1 APPROVE evidence for another step or for REJECT | n/a | DENIED: `the attestation authorises a different step or decision` | TestAttestation_DecisionBoundToStepAndOutcome |
| 6c | MFA claim with an authentication 2 hours old; no MFA | n/a | DENIED: `period.reopen requires a recent multi-factor authentication` | TestAttestation_MFAFreshnessIsVerifiedInSQL |
| 7 | `SET ROLE`, editable GUC, temporary objects, objects in `public`, key read or install | partly tested at 0.2.0 (RV-series) | DENIED by privilege; a GUC tenant switch exposes no foreign evidence | TestAttestation_TenantLoginCannotReachKeysOrEscalate |
| 8 | Legitimate two-person approval with independent identities and current MFA still succeeds and leaves evidence | n/a | PASS: evidence rows for `journal.approve` (approver) and `journal.post` (poster); a service with no signer fails closed | TestAttestation_LegitimateTwoPersonFlowLeavesEvidence |
| 9 | Re-run SC-01, SC-02, SC-03, SC-04, SC-05, SC-08 and SC-14 | PASS at 0.2.0 | PASS: full suite `go test -race -count=1 -p 1 ./...` is green on 1371d63 | gate_a_*_test.go, kernel_*_test.go |

Other attacks blocked on the fixed commit, beyond the directive list:

- inserting a journal already APPROVED;
- starting an instance as an invented initiator;
- cancelling an instance as an invented administrator;
- reopening a period as an invented CFO;
- approving a WBS version;
- inserting evidence directly or rewriting it.

## 2. Least privilege (GATEA-06), commit 1371d63

| Attack | Result | Test |
|---|---|---|
| `serk_health`, `serk_publisher` or `serk_scheduler` login calls `ledger_integrity_scan`, `approval_require`, `approval_authorize`, `approval_subject_hash` or `workflow_gate_lock` | DENIED: `permission denied for function …` | TestPrivileges_NonTenantRolesAreRefused |
| Tenant login runs DELETE or TRUNCATE on journals or lines, disables triggers, rewrites evidence, line amounts, journal dates or the audit log | DENIED: `permission denied` / `must be owner` | TestPrivileges_TenantLoginCannotRewriteHistory |
| Catalog: functions callable by PUBLIC, unpinned DEFINER search_path, DELETE/TRUNCATE/TRIGGER grants, readable non-FORCE-RLS tenant tables, key reachability, cluster-level role attributes | none found | TestPrivileges_CatalogInvariants |

Defect found and fixed in this round: before 0008, PUBLIC could EXECUTE every invoker helper, and two DEFINER functions had `search_path=public`. See DB_PRIVILEGE_MATRIX.md §3.

## 3. Defects found by the adversarial work itself

| ID | Found by | Defect | Fix |
|---|---|---|---|
| (in 0007 dev) | fx_source hash mismatch while running the tests | `approval_subject_hash` is owner-run (definer context) and bypassed RLS, so it could hash **another tenant's** row with the same natural key | Every lookup is scoped to `tenant_id = current_tenant()` |
| (in 0007 dev) | the "content changed after signing" test | The journal subject hash was the stored `command_hash`, so line edits were not detected | The live hash now covers the header and all lines |
| R-08 | probe | Editing a DRAFT memo made the journal approvable but unpostable | `REVOKE UPDATE(memo)`, plus an approve-time `CommandHash` check |
| GATEA-06 | live privilege matrix | PUBLIC EXECUTE on helpers; unpinned search_path | Migration 0008 |

## 4. Mutation testing (do the tests detect a removed control?)

Each mutant was applied to the migration, the suite was run, and the original was restored.

| Mutant | Killed by |
|---|---|
| M1: skip the HMAC comparison in `approval_authorize` | TestAttestation_ReplaySubstitutionExpiryAndTampering (tampered or other-secret cases succeed) |
| M2: `journals_attest` becomes a no-op | TestApprovalProvenance_DirectJournalApprovalAndPosting |
| M3: journal subject hash uses only the stored `command_hash` | "attestation for content that has since changed" |
| M4: MFA freshness ignored (`mfa_fresh := mfa`) | TestAttestation_MFAFreshnessIsVerifiedInSQL |
| M5: decision `ctx` check removed | initially **survived**; TestAttestation_DecisionBoundToStepAndOutcome was added and now kills it |
| M6: 0008 REVOKE loop removed | TestPrivileges_CatalogInvariants and TestPrivileges_NonTenantRolesAreRefused |
| M7: 0009 global default-privilege revoke removed | TestPrivileges_NewFunctionsAreClosedByDefault |

## 5. Not tested / limits (honest)

- **Independent review.** A first independent review agent stopped before running anything, and its output was discarded rather than counted. A second review is recorded in §6 when complete. No external penetration test has been done (GATEP-01 NOT TESTED).
- **Before-state completeness.** On ea3533c each test stopped at its first successful forgery, so later attacks in the same test (for example FX snapshot approval) have no "before" log line. They are covered after the fix.
- **Not covered by these tests:**
  - compromise of the API process or the signing secret (by design that grants authority: R-SIGNER);
  - the owner or superuser disabling triggers (R-DBA);
  - real IdP-issued MFA (GATEA-07 BLOCKED).
- **Concurrency of attestation use** (two transactions racing the same nonce) relies on the primary-key uniqueness. It has no dedicated race test yet.

## 6. Independent review (executed)

An independent review agent reviewed 0007/0008 at HEAD 81ab48b with read-only access to the repository and a disposable database. A first agent stopped before running anything, and its output was discarded, not counted.

- Report: `docs/security/INDEPENDENT_REVIEW_2026-10-21.md` (verbatim).
- Before: `evidence/independent-review-before.txt` has **11 "GAP CONFIRMED" lines**. These are real failures of the reviewer's tests, which assert the secure behaviour.
- After migration 0010: `evidence/independent-review-after.txt` has **0** such lines. All probes and every earlier attestation test PASS.

| Finding | Sev. | Reproduced by | Fix (0010) | Mutation check |
|---|---|---|---|---|
| H1: `closed_by`/`closed_at` rewritable on a CLOSED period, so the closer could reopen their own close (SoD bypass) | High | Q1 probe | `authority_frozen`: authority columns change only in the transition that sets them | M8 (freeze no-op): Q1 fails |
| H2: WBS `approved_by`/`approved_at` rewritable; `posted_by` writable on an APPROVED journal | High | Q1 probe | same | M8 |
| M1: decision outcome not bound (a REJECT superseded/retired the predecessor; close evidence allowed LOCK) | Medium | Q2 probe | `ctx` = target status, checked; supersede/retire need a successor APPROVE attestation **and** a deferred commit-time check | M11 (deferred check removed): SupersedeNeedsApprovedSuccessorAtCommit fails |
| M2: definition body not bound in SQL; one evidence inserted two definitions | Medium | Q2 probe | `workflow_body_digest(body)` computed by SQL is the attested subject; `ctx` = key; single use | consumption mutant |
| M3: tenant-insertable `fiscal_period_closes`/`workflow_history`; effects without evidence | Medium | Q1 probe + HardeningControls | close records only via a definer function tied to consumed evidence (INSERT revoked); authority history kinds and effects need the actor's verified decision in the transaction | HardeningControls |
| M4: evidence reusable within the transaction; content checked only at registration | Medium | Q2 probe (lines added after authorize) | `approval_use()`: single use (`approval_consumptions`); live subject hash and expiry re-checked at use | M10 (no recheck): Q2 fails; consumption-write removed: 4 tests fail. M9 (unconsumed filter removed) **survives** because the consumption primary key still refuses reuse (equivalent mutant) |
| L1: canonical message re-parsable (U+001F in field, dropped field, JSON types) | Low | Q3 probe | exact key set and JSON types; no U+001F; no comma in perms; the signer refuses them too | HardeningControls (strict shape) |
| L3: expiry vs transaction start | Low | Q5 probe | `clock_timestamp()` at registration and use | Q5 |
| L4: caller-supplied approval timestamps | Low | HardeningControls | DB time set in the trigger | — |
| L2: subject-hash format and coverage (`reopen_reason`, cost-code `valid_to`, …) | Low | not exploitable now (the columns are immutable or append-only) | **open**: canonical `jsonb` hash of all business columns planned | — |
| Info: non-constant-time HMAC compare in SQL; 224 pgcrypto/btree_gist functions executable | Info | — | **accepted**: timing is not observable through SQL at useful resolution; the extension functions are side-effect free | — |
