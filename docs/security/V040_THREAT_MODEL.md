# Threat model: v0.4 line (Journey A, IA-040-01, Journey B, governed AI)

Scope: the repository at the commit this file ships with. That covers migrations 0001–0019, the Go API and kernel, the embedded console, the relay and timers.

It extends `docs/architecture/THREAT_MODEL.md` (T-1 to T-9, written for the kernel and workflow engine) and keeps its IDs.

"Tested" means an automated test in this repository attacks the control and its log is saved. "Designed" means it is not yet tested. Nothing here is a third-party assessment. The external penetration test (GATEP-01) has not been done.

## Assets

| ID | Asset | Why it matters |
|---|---|---|
| A1 | Posted ledger and its history | The books |
| A2 | Approval evidence (attestations, audit chain) | Proves who decided what with which authority |
| A3 | FX rates and policies | Drive conversions |
| A4 | Tenant and project separation | Confidentiality between companies and between projects |
| A5 | Workflow definitions and policies (P2P, contract) | They *are* the control configuration: thresholds, accounts, VAT |
| A6 | Audit chain and outbox | Repudiation and downstream integrity |
| A7 | Secrets | Tenant-credential secret, approval signing key, webhook secret, OIDC trust |
| A8 | Availability of approvals and posting | |
| A9 (new) | Bank account numbers (supplier and company) | Payment-redirection fraud |
| A10 (new) | Commercial figures: contract values, measurements, IPC figures, certificates | Revenue recognition and client disputes |
| A11 (new) | Receivables, retention and advances | Cash and misstatement |
| A12 (new) | Payment instructions and statement lines | Money out and its settlement evidence |

## Principals

People, asserted `pkind=human` by the identity provider and holding roles from `pkg/auth` (listed in `docs/baseline/V040_INVENTORY.md`):

| Area | Roles |
|---|---|
| Project | estimator, site engineer, project manager, quantity surveyor, commercial manager, storekeeper |
| Procurement | procurement officer, procurement manager |
| Payables | AP clerk, AP supervisor |
| Receivables | AR clerk, AR supervisor |
| Treasury | treasury officer, bank statement officer |
| Finance | accountant, finance manager, controller, CFO |
| Oversight | auditor, process owner |

Roles carry an optional project list. A tenant-wide role with a project list is project-scoped everywhere (SC-05, ADR 0010).

Non-human principals:

- AI assistants (`pkind=ai`) and integration services (`pkind=service`). Since 0019 they may create and submit drafts only; every decision needs `principal.human`.
- The workflow timer (`system:workflow-timer`, service kind) records escalations and expiries and signs nothing.
- The relay (`serk_publisher`).
- The migrator (schema owner).

## Trust boundaries

B1 to B6 as in the kernel threat model:

| ID | Boundary |
|---|---|
| B1 | Internet → TLS proxy → API |
| B2 | API → PostgreSQL (per-tenant login) |
| B3 | Relay |
| B4 | Timer |
| B5 | Operator/migrator |
| B6 | Identity provider → API |

New:

| ID | Boundary | What crosses it |
|---|---|---|
| B7 | **Bank statement file → importer → API** | The file's provenance is whatever the importer uploads. The database binds the stored lines to the attested file content and requires independence of importer, reconciler and payment people. It cannot know whether the bank produced the file (R-BANKFEED). |
| B8 | **Browser console → API** | Strict CSP with no inline script and no third-party origins. The token is held in memory and revoked server-side at sign-out. Revealed bank numbers are shown once and not stored. |
| B9 | **Client certificate file → console** | The IPC certificate file is hashed (SHA-256) in the browser. Only the hash and the reference reach the server; the file stays with the user. The hash proves which file was presented, not that the client signed it. |

## Attacker profiles and results (v0.4 additions)

| # | Attacker | Can | Cannot (enforced by) | Status |
|---|---|---|---|---|
| T-2 | Authenticated user within roles | Anything their roles allow on their projects | <ul><li>Read or act on documents outside their scope, including known-id reads; out-of-scope reads as not found (IA-040-01, review 5 F1/F2/F5)</li><li>Approve their own document</li><li>Take two duties of one chain (DB separation checks)</li><li>Over-measure</li><li>Certify a stale IPC</li><li>Invoice an IPC twice</li><li>Over-allocate a receipt</li><li>Receive more advance than agreed</li><li>Confirm a receipt for a statement they imported</li><li>Pay above the dual threshold alone, including split across invoices or days (R-SPLIT-SUPPLIER)</li></ul> | tested: TestIA04001_*, TestR5_*, TestJourneyA_*, TestJourneyB_Controls, TestSupplierExposure* |
| T-3 | Arbitrary SQL as one tenant's runtime login | Read and write rows within column grants | <ul><li>Create or advance any P2P or AR document without the named actor's same-transaction attestation</li><li>Write or alter subledger journal lines outside the generating transaction</li><li>Approve or post a journal whose lines differ from the document's expected accounting</li><li>Insert a decision attestation without the human marker (0019)</li></ul> | tested: TestR3_*, TestR4_*, TestJourneyB_Controls (direct journal edit), TestGovernedAI_DraftOnly (SQL path) |
| T-3c (new) | Same login, **reading** | Read bank account numbers in the master tables | Since 0032 the tables hold AES-256-GCM ciphertext bound to the row and tenant, a keyed digest and the last four characters; the key is in the API, never in the database (tested: `TestBankAtRest_*`; the offsite drill finds no number in backups) | **residual: custody of the data key** (vault/HSM not available) and the API process itself, which must decrypt for the audited MFA reveal |
| T-10 (new) | **AI assistant or integration service** with a role (prompt-injected, buggy or malicious) | Create and submit drafts (invoices, receipts, measurements, statements) | <ul><li>Approve, verify, certify, confirm, post, release, close or configure anything</li><li>Gain the human marker from a role</li><li>Mint it through an attestation (SQL refuses at insert)</li></ul> | tested: TestGovernedAI_DraftOnly, TestJourneyA_PaymentControls, TestR4_08. Residual: an AI can still flood people with plausible drafts, and a careless human checker can approve them. |
| T-11 (new) | **Forged or altered bank statement** (insider importer, or a compromised file path) | Present money-in or money-out lines | <ul><li>Settle a payment with a statement imported by someone involved in the payment</li><li>Reconcile it themselves</li><li>Confirm a receipt for their own statement</li><li>Alter lines after the attested import</li></ul> | tested: TestR3_*, TestR4_*, TestJourneyB_Controls. **Residual R-BANKFEED (High):** no bank-signed feed, so a fabricated statement by an independent importer is accepted. |
| T-12 (new) | **Collusion of two people** in different duties | Complete a maker/checker chain together | Exceed limits that need a third person (dual payment approval) | **residual (inherent).** Detective controls: reconciliation, audit chain. |
| T-13 (new) | **Number guessing against masked bank data** | Register a guessed company account number | Confirm a guess from attestation hashes or payee fingerprints (keyed digest, 0017) | **residual R5-F3 (Low, accepted, mitigated):** the duplicate-number refusal is generic and audited; full fix with R-BANK-AT-REST |
| T-3b | API process compromise | Sign attestations for anyone | Since ADR 0015 the API holds no signing key in production; the isolated signer re-verifies the person's own token and signs only claims it supports (tested: `TestSignerIsolation_CompromisedAPICannotForge`) | **residual R-SIGNER (custody, High):** signatures in the name of people who are logged in, for their token lifetime; whoever controls the signer process or its secret (HSM/KMS not built) |
| T-4 | API process compromise | Every tenant credential | Silently alter history | **residual**, unchanged |

## Residual risks (open)

| ID | Risk | Severity | Blocked on |
|---|---|---|---|
| R-SIGNER | Process isolation done (ADR 0015); the signer's secret is a file in memory, not in an HSM/KMS, and a compromised API can still obtain signatures for people currently logged in | High (custody) | HSM/KMS keyring behind the `Keyring` seam; key ceremony; short token lifetimes |
| R-BANKFEED | Statement authenticity depends on the file path | High | A bank-signed feed or host-to-host channel with an agreement from the bank |
| R-MFA-SOURCE | Step-up evidence (`amr`, `auth_time`) comes from token claims | High until a real IdP is integrated | An OIDC provider with step-up (GATEA-02) |
| R-BANK-AT-REST | Closed for the database, exports and backups (0032). Since 0035 the account digest is keyed in the API too (R10-F4: the database-side digest was an offline guessing oracle). Both keys are file-held secrets in the API | Low (custody) | Vault/KMS custody of `SERK_BANK_DATA_KEY` and `SERK_BANK_DIGEST_KEY`; rotation runbook (previous-key support exists for the data key; the digest key is not rotatable in place) |
| R-DBA | The schema owner or superuser can disable triggers; detected after the fact by the integrity scan | Medium | Separation of DBA duties, managed database audit |
| GATEA-10 | Application limits and lockouts are shared across replicas since migration 0029 (HMAC-keyed counters in PostgreSQL; local fallback with an alert if the store fails). No edge throttling is configured or load-tested; volumetric DoS is out of the application's reach | Low (application), Medium (edge) | Edge proxy/WAF limits and a multi-host load test in staging |
| R5-F3 | Duplicate company account number oracle | Low, accepted | A named human risk owner must accept it (see `REMEDIATION_REGISTER.yaml`) |
| — | Collusion (T-12), careless checkers approving AI drafts (T-10) | Inherent | Detective controls and training; not a code defect |
| — | No external penetration test, load or chaos test, or legal, tax or data-policy sign-off | — | Gate P; requires independent humans |
