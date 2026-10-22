#!/usr/bin/env python3
"""Single source for docs/release/GATE_STATUS.json and the filled release-gate
checklist CSV. Every evidence path is checked to exist; the script fails if
any is missing (directive §13: evidence paths must point to actual files)."""
import csv, json, os, subprocess, sys, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
commit = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], text=True).strip()
ENV = "Go 1.26.10 (built from the official source tag), PostgreSQL 16.15 (local disposable cluster), linux/amd64 sandbox, no network to Go proxy/sumdb/vulndb"
FULL = "SERK_TEST_ADMIN_DSN=<disposable> go test -race -count=1 -p 1 ./..."
AI_REV = "independent AI review agents x2 (not a human sign-off)"
AI_REV_P2P = "independent AI review agents x2 on 0013/0014 (reviews 3 and 4; not a human sign-off)"
J = ["internal/store/postgres/migrations/0013_procure_to_pay.sql", "internal/store/postgres/migrations/0014_p2p_hardening.sql",
     "internal/store/postgres/migrations/0015_p2p_hardening_2.sql", "internal/kernel/p2p.go", "internal/httpapi/p2p_handlers.go"]
J_EV = ["docs/testing/E2E_JOURNEY_A.md", "docs/testing/evidence/full-suite.log", "docs/testing/evidence/console-journey-a.log",
        "docs/security/INDEPENDENT_REVIEW_3_2026-10-21.md", "docs/security/INDEPENDENT_REVIEW_4_2026-10-22.md",
        "docs/security/evidence/independent-review-3-before.txt", "docs/security/evidence/independent-review-3-after.txt",
        "docs/security/evidence/independent-review-4-before.txt", "docs/security/evidence/independent-review-4-after.txt",
        "docs/adr/0009-subledger-documents-generate-bound-draft-journals.md", "docs/workflows/PROCESS_CATALOG.md"]
J_CMD = "SERK_TEST_ADMIN_DSN=<disposable> go test -race -count=1 -p 1 ./... (incl. TestJourneyA_*, TestAPIJourneyA_EndToEnd, TestConsoleBrowserJourneyA, TestR3_*, TestR4_*)"
J_RES = ("R-BANKFEED (statement authenticity depends on how the file is obtained; no bank-signed feed); R-SPLIT-SUPPLIER (no supplier-level "
         "aggregation for dual approval); collusion of two people; plus R-SIGNER/R-DBA/R-MFA-SOURCE")

def item(id, title, severity, gate, state, scope, repo_paths, threat, root_cause, remediation_commit, migration,
         negative_test, positive_test, executed_command, actual_result, evidence, residual, reviewer, blocker, next_action,
         signoff=True):
    return dict(id=id, title=title, severity=severity, gate=gate, owner="SERK engineering (this delivery); human owner UNASSIGNED",
                scope=scope, repo_paths=repo_paths, state=state, threat_or_requirement=threat, root_cause=root_cause,
                remediation_commit=remediation_commit, migration=migration, negative_test=negative_test, positive_test=positive_test,
                executed_command=executed_command, environment=ENV if executed_command else "", actual_result=actual_result,
                evidence_path=evidence, residual_risk=residual, independent_reviewer=reviewer, blocker=blocker,
                next_action=next_action, signoff_required=signoff)

items = [
 item("GATEA-01", "Direct tenant-SQL forged-approver attempts blocked", "P0", "Gate A", "PASS", "journals, periods, FX, WBS, workflow",
      ["internal/store/postgres/migrations/0007_approval_attestation.sql", "0010_attestation_hardening.sql", "0012_attestation_hardening_2.sql"],
      "Compromised tenant DB credential forges approvals", "SQL checked approval field shape, not provenance (ea3533c)",
      "eb8094d, 32a220e, 74fb7d4", "0007, 0010, 0012", "TestApprovalProvenance_*, TestIndependentReview_*, TestIndependentReverify_*",
      "TestAttestation_LegitimateTwoPersonFlowLeavesEvidence", "go test ./internal/kernel -run 'ApprovalProvenance|Attestation|Independent' -v",
      "before: 6 forgeries succeed on ea3533c; after: all denied; 2 independent reviews' probes all hold",
      ["docs/security/evidence/approval-forgery-before.txt", "docs/security/evidence/approval-forgery-after.txt",
       "docs/security/evidence/independent-review-before.txt", "docs/security/evidence/independent-review-after.txt",
       "docs/security/evidence/independent-reverify-before.txt", "docs/security/evidence/independent-reverify-after.txt",
       "docs/security/ADVERSARIAL_RESULTS.md"],
      "R-SIGNER (API/secret compromise = signing authority); R-DBA (owner/superuser); R-MAKER", AI_REV, "",
      "Human security review of 0007/0010/0012; external pentest (GATEP-01)"),
 item("GATEA-02", "Verified step-up MFA bound to exact approval action", "P0", "Gate A", "BLOCKED", "approval attestations",
      ["pkg/attest/attest.go", "internal/kernel/kernel.go"], "MFA claim forged or reused for another action",
      "MFA was a caller-written boolean", "eb8094d, 32a220e", "0007, 0010",
      "TestAttestation_ReplaySubstitutionExpiryAndTampering, TestAttestation_MFAFreshnessIsVerifiedInSQL, TestIndependentReview_Q3/Q5",
      "TestAttestation_LegitimateTwoPersonFlowLeavesEvidence", "go test ./internal/kernel -run Attestation -v",
      "SQL side PASS: replay, expiry, actor/subject/amount (content) substitution, tampering, stale auth_time all denied",
      ["docs/security/evidence/approval-forgery-after.txt", "docs/security/APPROVAL_ATTESTATION_DESIGN.md"],
      "R-MFA-SOURCE: amr/auth_time come from the IdP token; only as trustworthy as the IdP integration", AI_REV,
      "No live OIDC provider with step-up (acr/amr) available in this environment", "Integrate real IdP step-up; re-run with IdP-issued tokens"),
 item("GATEA-03", "Workflow publication only through validated authorized path", "P0", "Gate A", "PASS", "workflow definitions",
      ["internal/store/postgres/migrations/0012_attestation_hardening_2.sql", "internal/kernel/workflow.go"],
      "Raw-SQL / malformed definition publication", "insert and decide accepted invented names", "eb8094d, 32a220e, 74fb7d4", "0007, 0010, 0012",
      "TestApprovalProvenance_WorkflowDefinitionPublication, TestIndependentReview_Q2, TestIndependentReverify_Q2_DefinitionBodyHashColumn",
      "TestWorkflow_* (publish via API)", FULL, "raw insert/publish denied; body bound by SQL digest; maker/checker enforced",
      ["docs/security/evidence/independent-reverify-after.txt", "docs/audit/evidence/final-test-run.log"], "R-SIGNER", AI_REV, "",
      "Human review"),
 item("GATEA-04", "FX human approval provenance enforced in SQL trust boundary", "P0", "Gate A", "PASS", "fx_sources, fx_policies, fx_snapshots",
      ["internal/store/postgres/migrations/0012_attestation_hardening_2.sql"], "Forged FX source/snapshot/exception approval",
      "approved_by/approver_mfa caller-written", "eb8094d, 32a220e, 74fb7d4", "0007, 0010, 0012",
      "TestApprovalProvenance_FXApprovals, TestIndependentReverify_Q1_FXSnapshotAuthorityOnTransition", "TestSC03_FXMakerChecker",
      FULL, "forged source/policy/rate/exception denied; approval record frozen per transition",
      ["docs/security/evidence/approval-forgery-before.txt", "docs/security/evidence/independent-reverify-after.txt"], "R-SIGNER", AI_REV, "",
      "Human review"),
 item("GATEA-05", "Old SC-01 to SC-14 accounting/security tests rerun", "P0", "Gate A", "PASS", "kernel",
      ["internal/kernel"], "Regression of v0.2 controls", "n/a", "74fb7d4", "0001-0012", "TestSC01..SC14 negative cases", "lifecycle tests",
      FULL, "205 tests PASS, 0 FAIL, 0 SKIP (race detector, 13 packages, migrations 0001-0015)",
      ["docs/audit/evidence/final-test-run.log", "docs/testing/evidence/full-suite.log"], "", "", "",
      "Re-run in CI once a runner is available", signoff=False),
 item("GATEA-06", "Database roles, functions and grants least privilege", "P0", "Gate A", "PASS", "all runtime roles that exist",
      ["internal/store/postgres/migrations/0008_function_least_privilege.sql", "docs/security/privilege_matrix.sql"],
      "Over-broad grants", "PUBLIC EXECUTE on helpers; unpinned search_path; per-schema default privilege no-op (R-10)", "1371d63, b314922",
      "0008, 0009", "TestPrivileges_* (catalog + live attempts as health/relay/timer/monitor/tenant)", "full suite",
      "go test ./internal/kernel -run Privileges -v", "no PUBLIC function, pinned DEFINER paths, no DELETE/TRUNCATE, monitor aggregate-only",
      ["docs/security/DB_PRIVILEGE_MATRIX.md"], "authenticator/reporting/analyst/backup/break-glass roles do not exist yet", AI_REV, "",
      "Create remaining roles with tests when introduced"),
 item("GATEA-07", "Session revocation and role removal become effective", "P1", "Gate A", "BLOCKED", "API sessions",
      ["internal/store/postgres/migrations/0009_session_revocation.sql", "internal/kernel/sessions.go"],
      "Terminated user keeps access until token expiry", "stateless tokens", "b314922", "0009",
      "TestSessions_TenantLoginCannotUndoOrBackdateRevocations", "TestAPISessionRevocationAcrossReplicas, TestSessions_*",
      "go test ./internal/kernel ./internal/httpapi -run 'Session' -v",
      "server-side revocation PASS: effective on all replicas at next request and inside approvals",
      ["docs/audit/evidence/final-test-run.log"], "IdP back-channel logout / SCIM role-removal feed not integrated", "",
      "No real OIDC provider (JWKS rotation, back-channel logout) reachable", "Integrate IdP; add back-channel logout endpoint"),
 item("GATEA-08", "Staging deployment operational with TLS and vault secrets", "P1", "Gate A", "BLOCKED", "deployment",
      ["deploy/docker-compose.prod.yml"], "Untested deployment", "", "", "", "", "", "", "not executed",
      [], "", "", "No Docker, staging hosts, DNS, TLS certificates or vault in this environment", "Provision staging; run smoke tests"),
 item("GATEA-09", "Real backup restore/PITR drill completed", "P1", "Gate A", "PASS", "PostgreSQL backup/WAL archive",
      ["deploy/drills/pitr_drill.sh", "deploy/drills/pitr_offsite_encrypted_drill.sh"], "Unrecoverable data loss", "", "81ab48b + offsite drill", "",
      "operator TRUNCATE after target; primary storage lost; wrong private key; forged base backup and forged WAL segment in the offsite store (R10-F8)", "exact restore from the signed, encrypted offsite copy on a second host; forgeries refused before decryption",
      "DRILL_DIR=... LOAD_BIN=... deploy/drills/pitr_offsite_encrypted_drill.sh",
      "signed drill (after review 10): restore to named point identical (16 tables), clean integrity scan, 12/12 audit chains verify, pg_verifybackup verified, migrations 1-35; 0 plaintext markers offsite (controls present in the primary before the damage); no plaintext base tar on the primary; wrong key, forged base and forged WAL refused; RTO 1.0 s (47 MB); RPO 6 s at archive_timeout=10s (earlier drill)",
      ["docs/operations/BACKUP_PITR_RESTORE_PROOF.md", "docs/operations/evidence/pitr-drill-2026-10-21.txt", "docs/operations/evidence/pitr-offsite-encrypted-drill-2026-10-22.txt", "docs/operations/evidence/pitr-offsite-signed-drill-2026-10-22.txt"],
      "not production-scale; offsite store is a directory, not object storage with retention lock; a compromised primary can sign forged objects (object lock is the control); private-key and signing-key custody (vault/HSM) and key ceremony are human-owned; RPO/RTO targets need business sign-off", "", "",
      "Repeat at staging scale against real offsite object storage; key ceremony"),
 item("GATEA-10", "Distributed abuse and fail-closed access controls", "P1", "Gate A", "PARTIAL", "edge + API",
      ["internal/httpapi/abuse.go", "internal/httpapi/abuse_shared.go", "internal/store/postgres/abuse_store.go",
       "internal/store/postgres/migrations/0029_distributed_abuse_limits.sql"], "Credential stuffing / DoS across replicas",
      "in-process per-replica limiters", "this checkpoint", "0029",
      "TestSharedAbuse_RolePrivileges, TestSharedAbuse_StoresDigestsOnly, TestPrivileges_CatalogInvariants, TestProductionRequiresSharedAbuseLimits",
      "TestSharedAbuse_LockoutAndBudgetsSpanReplicas (2-3 API replicas in one process over one PostgreSQL; per-process control case), TestSharedAbuse_StoreFailureFallsBackToLocalLimits",
      "go test ./internal/httpapi -run SharedAbuse -v", "shared lockout, pre-auth and per-principal budgets enforced across replicas; HMAC digests only; store outage falls back to local limits with an alert",
      ["docs/testing/evidence/full-suite-abuse-fresh-db.txt"],
      "edge throttling exists only as an unexecuted nginx draft (deploy/nginx-edge.conf); nothing at the edge has been started or load-tested; replicas tested as separate servers in one process, not separate hosts; volumetric DoS is out of scope for an application limiter", "",
      "No edge proxy / multi-host load environment", "Edge rate limiting (proxy) + multi-host load test in staging"),
 item("GATEA-11", "OpenTelemetry, SLOs and alerts work", "P1", "Gate A", "BLOCKED", "observability",
      ["internal/obs", "deploy/observability/prometheus-alerts.yml"], "Silent failures", "", "bae7eeb", "0011",
      "TestAlertDrill_InducedFailuresFireTheRightAlerts (healthy baseline fires nothing)", "same (8 induced failures -> 8 expected alerts)",
      "go test ./internal/httpapi -run AlertDrill -v", "rule-level drill PASS incl. outbox lag and ledger failure",
      ["docs/operations/OBSERVABILITY_SLOS.md", "docs/operations/evidence/alert-drill-2026-10-21.txt"],
      "no OTLP export; Prometheus/Alertmanager routing and SLO ratio rules untested", "",
      "No Prometheus/Alertmanager/OTel collector available; OTel SDK not in pinned deps", "Staging Prometheus; OTel SDK after dependency review"),
 item("GATEA-12", "Cold source build, go.sum trust, govulncheck, SBOM", "P1", "Gate A", "BLOCKED", "supply chain",
      ["scripts/supply_chain_local.sh", ".github/workflows/ci.yml"], "Compromised dependency", "4 go.sum hashes unverifiable offline", "8a2948b", "",
      "", "", "tools/verify_gosum_origin.py; tools/osv_scan.py; scripts/supply_chain_local.sh",
      "30/30 go.sum lines equal the upstream git source; module/package OSV scan (vulndb e0bad56): 50 imported-package advisories found and fixed by Go 1.26.10 + pgx 5.9.2 + x/text 0.43.0 -> 0",
      ["docs/release/SECURITY_AND_SUPPLY_CHAIN_EVIDENCE.md", "docs/release/evidence/gosum-origin-after-upgrade.txt", "docs/release/evidence/osv-scan-before-upgrade.txt",
       "docs/release/evidence/osv-scan-after-upgrade.txt", "docs/release/evidence/gatea-12-reachability-2026-10-22.txt", "docs/release/evidence/go1.26.10-source-tag.txt"],
      "Origin check trusts GitHub/mirrors, not the sumdb transparency log; OSV scan is package-level, not govulncheck symbol reachability",
      "", "sum.golang.org and vuln.go.dev refused by the egress gateway (403), proxy.golang.org unresolvable; no CI runner",
      "Run .github/workflows/ci.yml on a trusted runner"),
 item("GATEA-13", "Validated migrated FK and legacy financial data exceptions", "P1", "Gate A", "PARTIAL", "legacy data",
      ["pkg/legacy/legacy.go", "cmd/serk-import/main.go", "internal/store/postgres/constraints.go", "pkg/legacy/testdata"],
      "Unvalidated legacy data", "NOT VALID FKs (SC-10) pending data review; no customer data set", "this checkpoint", "",
      "TestDirtyBundleReportsEveryDefect (17 planted defects all reported), TestLegacy_NotValidConstraintsAreValidatedOrReported (dirty row reported and ledgered, not rewritten)",
      "TestCleanBundleHasNoExceptions; serk-migrate validate-constraints --apply validated the three NOT VALID constraints on a clean database",
      "serk-import validate --dir pkg/legacy/testdata/{clean,dirty} --cutover 2026-09-30; serk-migrate validate-constraints --apply",
      "rehearsed on representative synthetic fixtures: FK, duplicates, precision, cut-over dates, balanced opening, control-account ties; constraints validated only with 0 violators",
      ["docs/testing/evidence/legacy-validation-rehearsal-2026-10-22.txt"],
      "no real (anonymised) customer data set has been validated; the loader (DRAFT documents for human approval) is not built", "",
      "No legacy/customer data set provided", "Validate an anonymised extract of the customer's books; build the DRAFT loader"),
]
JB = ["internal/store/postgres/migrations/0018_contract_to_cash.sql", "internal/store/postgres/migrations/0019_human_decisions.sql",
      "internal/store/postgres/migrations/0020_review6_corrections.sql", "internal/kernel/contract.go", "internal/httpapi/ar_handlers.go"]
JB_EV = ["docs/testing/E2E_JOURNEY_B.md", "docs/testing/evidence/journey-b-kernel.txt", "docs/testing/evidence/full-suite-r6-fixes.txt",
         "docs/testing/evidence/journey-b-screens/03-reconciliation-receivables.png", "docs/security/INDEPENDENT_REVIEW_6_2026-10-22.md",
         "docs/security/evidence/independent-review-6-before.txt", "docs/security/evidence/independent-review-6-after.txt",
         "docs/adr/0011-contract-to-cash-and-human-decisions.md"]
DONE = {
 "GATEB-02": item("GATEB-02", "Versioned BOQ estimation and approved baseline", "P1", "Gate B", "PASS", "BOQ versions, cost-code budgets",
      J, "Unapproved or altered budget baseline", "", "a1f337c + this checkpoint", "0013-0015",
      "TestJourneyA_SegregationOfDutiesAndBudget, TestR3_03 (items frozen after DRAFT)", "TestJourneyA_BOQToBankReconciliationToGL",
      J_CMD, "BOQ maker/checker, items frozen, budget = approved BOQ; over-budget PR/PO refused or escalated (override+MFA)", J_EV,
      "BOQ estimation is quantities x rates only (no resource build-up, tender comparison or versions diff UI)", AI_REV_P2P, "",
      "Human review; estimation build-up and tender module (directive §4)"),
 "GATEB-03": item("GATEB-03", "PR RFQ technical commercial approval PO implemented", "P1", "Gate B", "PASS", "requisitions, RFQs, quotes, POs",
      J, "Collusive or unjustified award; altered PO", "maker identity free text (review 3 H1), quote lines appendable (review 4 M-A)",
      "a1f337c + this checkpoint", "0013-0015",
      "TestJourneyA_ProcurementRules, TestR3_07, TestR3_14, TestR4_01, TestR4_09", "TestAPIJourneyA_EndToEnd, TestConsoleBrowserJourneyA",
      J_CMD, "min 3 suppliers or justified single source; evaluator != recorder; lowest compliant or 20-char reason; PO = award; late quotes refused",
      J_EV, J_RES, AI_REV_P2P, "", "Human review; PO change orders/cancel; RFQ clarifications"),
 "GATEB-04": item("GATEB-04", "GRN partial delivery invoice 3-way matching to AP", "P1", "Gate B", "PASS", "GRNs, invoices, AP",
      J, "Paying for goods not received or at unagreed prices", "", "a1f337c + this checkpoint", "0013-0015",
      "TestJourneyA_ReceiptAndMatchingControls (over-receipt, over-billing, VAT, exception+MFA, duplicates)", "TestJourneyA_BOQToBankReconciliationToGL",
      J_CMD, "partial deliveries; DB 3-way match with tolerance; price variance to PPV; GRNI and AP reconcile to GL at 0", J_EV,
      "No debit notes/returns, GRN cancel, landed costs or inventory valuation (GATEB-05)", AI_REV_P2P, "", "Human review; returns and debit notes"),
 "GATEC-01": item("GATEC-01", "Journey A BOQ to payment controlled bank reconciliation", "P1", "Gate C", "PASS", "end-to-end",
      J + ["internal/webui/static/app.js", "e2e/console_journey_a.mjs"], "Unreconciled or unauthorised money flow",
      "review 3: 2 High/3 Medium/3 Low; review 4: 2 Medium/4 Low (all fixed)", "a1f337c + this checkpoint", "0013-0015",
      "TestR3_* (14), TestR4_* (9), 12+ API-boundary probes, UI SoD refusal", "Journey A at kernel, HTTP and browser level (15 people)",
      J_CMD, "GRNI/AP/in-transit 0, bank -2,486,875 = GL, cost report exact, 2 payments SETTLED, no unposted P2P journals; all probes held",
      J_EV + ["docs/testing/evidence/console/08-subledger-gl-reconciliation.png"], J_RES, AI_REV_P2P,
      "Not on staging (GATEA-08 BLOCKED); no real bank feed; no human finance sign-off",
      "Human finance/security review; staging run; Journey B"),
 "GATEC-02": item("GATEC-02", "Journey B measurement to IPC AR and receipt", "P1", "Gate C", "PASS", "end-to-end",
      JB + ["internal/webui/static/app.js", "e2e/console_journey_b.mjs"], "Misstated revenue, receivables or cash application",
      "review 6: 4 Medium/2 Low/2 Info (all fixed in 0020); found while building: AI could approve (0019), receipt bank recon (0018)",
      "f29ebd8, 297ab8f + review 6 fixes", "0018-0020",
      "TestJourneyB_Controls (22 refusals with asserted reasons), TestJourneyB_CancelReceipt, TestR6_* (17), TestGovernedAI_DraftOnly",
      "Journey B at kernel, HTTP and browser level (11 people)", FULL,
      "IPC1 due 4,691,000, IPC2 due 3,663,000; AR 1,663,000 / retention 432,000 / advance 0 = GL; every AR check and bank check difference 0",
      JB_EV, "No variations, invoice cancellation, dunning or FX contracts; credit notes (0022) and retention release (0023) built; quantity corrections by credit are procedural only (JB-CREDIT-QTY); VAT rates are test data pending tax sign-off",
      "independent AI review agent (review 6; not a human sign-off)", "Not on staging (GATEA-08 BLOCKED); no human finance/tax sign-off",
      "Credit notes; human finance review; stock valuation (GATEB-05)"),
 "GATEB-05": item("GATEB-05", "Inventory FIFO/WAC integrated with project/GL", "P1", "Gate B", "PASS", "stock items, warehouses, put-away, issues, counts",
      ["internal/store/postgres/migrations/0021_stock_valuation.sql", "internal/store/postgres/migrations/0024_review7_corrections.sql",
       "internal/kernel/stock.go", "internal/httpapi/stock_handlers.go", "e2e/console_journey_c.mjs"],
      "Unvalued or misvalued stock; project cost without consumption",
      "review 7: 4 Medium/5 Low/1 Info (fixed in 0024; R7-F9 by start-up posture check); review 8: 3 Medium/5 Low/2 Info (0028; R8-F5 acceptance proposed, needs human owner); review 9 budget rule corrected in 0030 (JC-BUDGET-ORIGIN open, conservative)", "067e08d + review 7 fixes", "0021, 0024",
      "TestJourneyC_Controls (19 refusals incl. concurrency), TestR7_* (13), TestR8_* (16), TestR9_BudgetAfterPutAway, TestR9_Designation", "TestJourneyC_StockValuationToGL, TestAPIJourneyC_StockValuation, TestConsoleBrowserJourneyC", FULL,
      "FIFO and WAC exact to the cent; inventory = GL; stock balances = GL with reconciling items; balances = documents = layers; project cost from issues; budget not double counted",
      ["docs/testing/E2E_JOURNEY_C.md", "docs/testing/evidence/journey-c-kernel-api-browser.txt", "docs/testing/evidence/full-suite-review7-fixes.txt",
       "docs/security/INDEPENDENT_REVIEW_7_2026-10-22.md", "docs/security/INDEPENDENT_REVIEW_8_2026-10-22.md", "docs/testing/evidence/full-suite-review8-fixes-fresh-db.txt", "docs/adr/0012-stock-valuation-fifo-wac.md"],
      "No supplier returns, landed cost or in-transit stock; invoice variance not revalued into stock (JC-INVOICE-REVALUE); review 8 corrections (0028) not re-reviewed independently",
      "independent AI review agents (reviews 7 and 8)", "", "Human review; independent re-review of 0028"),
 "GATEB-06": item("GATEB-06", "Contracts variations retention and IPC workflows", "P1", "Gate B", "PARTIAL", "contracts, measurements, IPCs",
      JB, "Uncontrolled claims on the client", "", "f29ebd8 + review 6 fixes", "0018-0020",
      "TestJourneyB_Controls, TestR6_*", "TestJourneyB_ContractToCashToGL", FULL,
      "contracts, measurements, computed IPCs with retention and advance recovery, certification with MFA and certificate hash: PASS",
      JB_EV, "Retention release (0023) and credit notes (0022) reviewed (review 8, fixed in 0028); variations (0026) reviewed (review 9, fixed in 0030); variation interplay with credits/retention/advances not probed; no claims/daywork", "independent AI review agent (review 6)", "",
      "Independent review of 0022-0026; claims and daywork"),
 "GATED-02": item("GATED-02", "Project scheduling CPM baseline variance EVM", "P2", "Gate D", "PARTIAL", "schedule versions, baselines, progress, EVM",
      ["internal/store/postgres/migrations/0027_project_schedule.sql", "pkg/schedule/cpm.go", "internal/kernel/schedule.go",
       "internal/httpapi/schedule_handlers.go", "e2e/console_planning.mjs"],
      "Unverified programme dates; progress or earned value misreported", "", "this checkpoint", "0027",
      "TestCPMRefusesInvalidNetworks, TestScheduleBaselineProgressEVM (14 refusals incl. tampered dates refused by SQL), TestR9_ScheduleProgressAndRaw, TestR9_ScheduleEVMCost",
      "TestCPMTextbook, TestAPISchedule_BaselineProgressEVM, TestConsoleBrowserPlanning, TestR9_ScheduleEVMHand", FULL,
      "CPM exact on the textbook network; the database re-verifies dates, floats, critical flag and late dates; EV per activity; PV 4,700,000 EV 3,850,000 SPI 0.8191; independent hand computation matched incl. SS/FF lags and holidays",
      ["docs/testing/E2E_PLANNING.md", "docs/adr/0013-planning-cpm-and-earned-value.md", "docs/testing/evidence/full-suite-review9-fixes-fresh-db.txt", "docs/security/INDEPENDENT_REVIEW_9_2026-10-22.md"],
      "No resource levelling, per-activity calendars, forecast dates from progress, or constant-price EVM; AC is all posted expense on the project; review 9 fixes (0030) not re-reviewed",
      "independent AI review agent (review 9)", "", "Re-review of 0030; forecasting"),
 "GATEF-01": item("GATEF-01", "AI has no kernel write or approval capabilities", "P2", "Gate F", "PARTIAL", "every attested action",
      ["internal/store/postgres/migrations/0019_human_decisions.sql", "pkg/auth/auth.go", "internal/kernel/kernel.go"],
      "AI or automation approves, posts or releases", "only payments required the human marker before 0019", "f29ebd8", "0019",
      "TestGovernedAI_DraftOnly, TestR6_11, TestR4_08, TestJourneyA_PaymentControls", "AI drafts an invoice that a person approves", FULL,
      "no decision possible for ai/service/unknown kinds in kernel or SQL; Go and SQL draft-action lists agree (74 actions)",
      ["docs/adr/0011-contract-to-cash-and-human-decisions.md", "docs/security/INDEPENDENT_REVIEW_6_2026-10-22.md"],
      "AI/service principals CAN write drafts (draft-only by design); depends on the IdP asserting pkind correctly (R-MFA-SOURCE)",
      "independent AI review agent (review 6)", "No AI features exist yet; IdP pkind mapping untested", "Build governed AI assistance on this rule"),
 "GATEB-07": item("GATEB-07", "Accessible user-facing ERP core screens", "P1", "Gate B", "PARTIAL", "web console (Journey A and B screens)",
      ["internal/webui/static/index.html", "internal/webui/static/app.js", "internal/webui/static/app.css", "e2e/console_journey_a.mjs", "e2e/console_journey_b.mjs"],
      "Unusable or inaccessible operations", "", "this checkpoint", "",
      "automated audit: labels, names, landmarks, unique ids, WCAG AA contrast light+dark, 390px reflow, skip link, CSP",
      "TestConsoleBrowserJourneyA, TestConsoleBrowserJourneyB", "go test ./internal/httpapi -run TestConsoleBrowserJourney -v",
      "Journey A (15 people) and Journey B (11 people, 12 audited pages) PASS; 7 UI defects found by the browser runs and fixed", ["docs/testing/evidence/console-journey-a.log",
      "docs/testing/evidence/console/05-finance-my-work.png", "docs/testing/E2E_JOURNEY_A.md"],
      "Only Journey A/B screens; no manual WCAG audit or screen-reader test; English only (no Amharic/Tigrinya/Oromo yet); no offline", "", "",
      "Manual accessibility audit; localisation; screens for other modules"),
}
for gid, title, prio in [
 ("GATEB-01","Canonical entities, project scopes, WBS and cost codes","P1"),("GATEB-02","Versioned BOQ estimation and approved baseline","P1"),
 ("GATEB-03","PR RFQ technical commercial approval PO implemented","P1"),("GATEB-04","GRN partial delivery invoice 3-way matching to AP","P1"),
 ("GATEB-05","Inventory FIFO/WAC integrated with project/GL","P1"),("GATEB-06","Contracts variations retention and IPC workflows","P1"),
 ("GATEB-07","Accessible user-facing ERP core screens","P1"),("GATEC-01","Journey A BOQ to payment controlled bank reconciliation","P1"),
 ("GATEC-02","Journey B measurement to IPC AR and receipt","P1"),("GATED-01","Offline field capture, duplicate sync and revocation","P2"),
 ("GATED-02","Project scheduling CPM baseline variance EVM","P2"),("GATED-03","Equipment, work hours maintenance job cost","P2"),
 ("GATED-04","Quality HSE and safety exception flows","P2"),("GATEE-01","Document control revision and IFC model mapping","P2"),
 ("GATEE-02","Payroll locality policies independently reviewed","P2"),("GATEE-03","Multi-entity project reporting and consolidation","P2"),
 ("GATEF-01","AI has no kernel write or approval capabilities","P2"),("GATEF-02","Evidence-backed AI and prompt-injection handling","P2"),
 ("GATEP-01","Independent external penetration test accepted","P0"),("GATEP-02","Load soak chaos and recovery tested","P0"),
 ("GATEP-03","Finance tax legal and data policy signed","P0"),("GATEP-04","Authorized engineering security ops product GO/NO-GO","P0")]:
    blocker = "Requires independent human parties / signed records; an AI agent cannot provide or sign these" if gid.startswith("GATEP") else ""
    if gid in DONE:
        items.append(DONE[gid])
        continue
    items.append(item(gid, title, prio, "Gate " + gid[4], "NOT TESTED", "", [], "", "", "", "", "", "", "", "not started", [], "", "", blocker,
                      "Phase 1: Journey A slice (BOQ->PR->RFQ->PO->GRN->invoice->AP->payment instruction->bank rec->GL)" if gid in ("GATEB-02","GATEB-03","GATEB-04","GATEC-01") else "per directive §12 order"))

missing = [p for it in items for p in it["evidence_path"] if not os.path.exists(os.path.join(ROOT, p))]
if missing:
    sys.exit("missing evidence paths: " + ", ".join(missing))
gates = {}
for it in items:
    if it["id"].startswith("GATE"):
        gates.setdefault(it["gate"], []).append(it["state"])
summary = {g: ("PASS" if all(s == "PASS" for s in v) else "NOT PASSED") for g, v in gates.items()}
doc = {"generated_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "source_commit": commit,
       "source_commit_note": "The commit whose tree was evaluated. This file is committed afterwards, so the release tag points at a child of source_commit that differs from it only by the generated documents (GATE_STATUS.json, inventory, register, feature matrix). The checkpoint record names both.",
       "release_decision": "NO-GO", "release_decision_reason": "Gate A not passed (BLOCKED items); Gate B/C partly evidenced (Journeys A and B), other items not tested or partial; Gate P requires independent human sign-off",
       "deployment_authorization": "NONE. Production deployment and live financial operations require explicit authorization and independent human sign-off.",
       "gate_summary": summary, "items": items}
os.makedirs(os.path.join(ROOT, "docs/release"), exist_ok=True)
with open(os.path.join(ROOT, "docs/release/GATE_STATUS.json"), "w") as f:
    json.dump(doc, f, indent=1)
with open(os.path.join(ROOT, "docs/release/SERK_Production_Release_Gate_Checklist.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["ID", "Priority", "Gate", "Acceptance criterion", "Current status", "Actual evidence path", "Owner", "Blocker / note"])
    for it in items:
        if it["id"].startswith("GATE"):
            w.writerow([it["id"], it["severity"], it["gate"], it["title"], it["state"], "; ".join(it["evidence_path"]),
                        it["owner"], it["blocker"] or it["residual_risk"]])
print(json.dumps(summary), "|", sum(1 for i in items if i["state"] == "PASS"), "PASS,",
      sum(1 for i in items if i["state"] == "BLOCKED"), "BLOCKED,", sum(1 for i in items if i["state"] == "PARTIAL"), "PARTIAL,", sum(1 for i in items if i["state"] == "NOT TESTED"), "NOT TESTED")
