#!/usr/bin/env python3
"""Single source for docs/release/GATE_STATUS.json and the filled release-gate
checklist CSV. Every evidence path is checked to exist; the script fails if
any is missing (directive §13: evidence paths must point to actual files)."""
import csv, json, os, subprocess, sys, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
commit = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], text=True).strip()
ENV = "Go 1.24.7, PostgreSQL 16.15 (local disposable cluster), linux/amd64 sandbox, no network to Go proxy/sumdb/vulndb"
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
      ["deploy/drills/pitr_drill.sh"], "Unrecoverable data loss", "", "81ab48b", "", "operator TRUNCATE after target", "exact restore",
      "DRILL_DIR=... LOAD_BIN=... deploy/drills/pitr_drill.sh",
      "restore to named point identical (16 tables), 14/14 audit chains verify; RTO 0.90 s (53 MB); RPO 6 s at archive_timeout=10s",
      ["docs/operations/BACKUP_PITR_RESTORE_PROOF.md", "docs/operations/evidence/pitr-drill-2026-10-21.txt"],
      "not production-scale; archive on same disk; no encryption/offsite; RPO/RTO targets need business sign-off", "", "",
      "Repeat at staging scale with pgBackRest/WAL-G to encrypted offsite storage"),
 item("GATEA-10", "Distributed abuse and fail-closed access controls", "P1", "Gate A", "BLOCKED", "edge + API",
      ["internal/httpapi/abuse.go"], "Credential stuffing / DoS across replicas", "in-process per-replica limiters", "", "", "", "", "", "not executed",
      [], "rate limits are per replica (in memory); no edge throttle", "", "No edge proxy / multi-replica load environment", "Edge rate limiting (proxy) + shared limiter"),
 item("GATEA-11", "OpenTelemetry, SLOs and alerts work", "P1", "Gate A", "BLOCKED", "observability",
      ["internal/obs", "deploy/observability/prometheus-alerts.yml"], "Silent failures", "", "bae7eeb", "0011",
      "TestAlertDrill_InducedFailuresFireTheRightAlerts (healthy baseline fires nothing)", "same (8 induced failures -> 8 expected alerts)",
      "go test ./internal/httpapi -run AlertDrill -v", "rule-level drill PASS incl. outbox lag and ledger failure",
      ["docs/operations/OBSERVABILITY_SLOS.md", "docs/operations/evidence/alert-drill-2026-10-21.txt"],
      "no OTLP export; Prometheus/Alertmanager routing and SLO ratio rules untested", "",
      "No Prometheus/Alertmanager/OTel collector available; OTel SDK not in pinned deps", "Staging Prometheus; OTel SDK after dependency review"),
 item("GATEA-12", "Cold source build, go.sum trust, govulncheck, SBOM", "P1", "Gate A", "BLOCKED", "supply chain",
      ["scripts/supply_chain_local.sh", ".github/workflows/ci.yml"], "Compromised dependency", "4 go.sum hashes unverifiable offline", "8a2948b", "",
      "", "", "scripts/supply_chain_local.sh", "offline part PASS: go mod verify, build-list SBOM (9 components), MIT/BSD only, secret scan clean",
      ["docs/release/SECURITY_AND_SUPPLY_CHAIN_EVIDENCE.md", "docs/release/evidence/supply-chain-local-2026-10-21.txt", "docs/release/evidence/sbom-local.cdx.json"],
      "go mod verify is circular for the 4 mirror-derived hashes", "", "No network to proxy.golang.org / sum.golang.org / vuln.go.dev; no CI runner",
      "Run .github/workflows/ci.yml on a trusted runner"),
 item("GATEA-13", "Validated migrated FK and legacy financial data exceptions", "P1", "Gate A", "NOT TESTED", "legacy data",
      [], "Unvalidated legacy data", "NOT VALID FKs (SC-10) pending data review", "", "", "", "", "", "not executed", [], "", "",
      "No legacy/customer data set provided", "Migration rehearsal on anonymized data"),
]
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
 "GATEB-07": item("GATEB-07", "Accessible user-facing ERP core screens", "P1", "Gate B", "PARTIAL", "web console (Journey A screens only)",
      ["internal/webui/static/index.html", "internal/webui/static/app.js", "internal/webui/static/app.css", "e2e/console_journey_a.mjs"],
      "Unusable or inaccessible operations", "", "this checkpoint", "",
      "automated audit: labels, names, landmarks, unique ids, WCAG AA contrast light+dark, 390px reflow, skip link, CSP",
      "TestConsoleBrowserJourneyA", "go test ./internal/httpapi -run TestConsoleBrowserJourneyA -v",
      "15-person UI journey PASS; 3 UI defects found by the audit and fixed", ["docs/testing/evidence/console-journey-a.log",
      "docs/testing/evidence/console/05-finance-my-work.png", "docs/testing/E2E_JOURNEY_A.md"],
      "Only Journey A screens; no manual WCAG audit or screen-reader test; English only (no Amharic/Tigrinya/Oromo yet); no offline", "", "",
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
       "release_decision": "NO-GO", "release_decision_reason": "Gate A not passed (BLOCKED items); Gate B/C partly evidenced (Journey A only), other items not tested; Gate P requires independent human sign-off",
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
