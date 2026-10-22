# Independent review 5: IA-040-01 fix (commit 0dcf5d3)

Reviewer: independent; did not write the fix. Working copy: `review5/repo`, branch `security/ia-040-01-document-scope`.
Database: local PostgreSQL on port 5433, database `serk_review5`, synthetic data only, no network.

Probes:

- `internal/kernel/zz_review5_test.go`: `TestR5_01` to `TestR5_07`.
- `internal/httpapi/zz_review5_test.go`: `TestR5_H1`.

Each probe logs `held:` when the control works and fails with `OPEN:` when it does not. Lines tagged `info:` are observations.

Artifacts:

- `review5/probe-output.txt`: the probe run (`go test -race -count=1 -p 1 -run 'TestR5_' -v ./internal/kernel ./internal/httpapi`).
- `review5/full-suite.txt`: the full `./internal/kernel` and `./internal/httpapi` run with `-race`, including the browser test.

## Verdict

The fix works for what it targets. These all hold, with executed evidence:

- `GET /v1/p2p/{type}/{id}`, `ListP2PDocs`, every `loadDoc` mutation and the reveal go through one `canSee`.
- Detail and list responses never contain a full account number or `bank_snapshot`.
- Out-of-scope and nonexistent ids give identical responses on detail, reveal and the mutations tested.
- The reveal is correctly permissioned, MFA-gated, purpose-gated, revocation-aware and audited without the number.

The claim "one visibility policy for list, detail, mutation" is **not complete**. Six other P2P paths still decide "tenant-wide" with `authz.Has(p, scope.tenant_wide)` instead of `ScopeOf`. That is exactly the v0.4.0 rule the ADR says was removed ("A role with a project list is project-scoped everywhere"). Through these paths, a project-restricted principal can still:

- create entity-level payment instructions;
- import statements on company accounts it cannot see, and learn their balances;
- reconcile, which returns payment numbers and ids and settles payments;
- list the tenant-wide journal worklist, which includes payment journals;
- read the entity GL reconciliation.

I also found several lower-severity residual disclosures; they are listed under Findings.

| # | Severity | Finding |
|---|---|---|
| F1 | **Medium** | Six P2P paths use `Has(scope.tenant_wide)` instead of `ScopeOf`/`canSee`, so project-restricted tokens bypass the policy. |
| F2 | Low | Mutations take `FOR UPDATE` before `canSee`, so lock contention reveals whether an out-of-scope document exists. |
| F3 | Low | The unique constraint on company account numbers lets a treasury officer confirm a guessed full number with no reveal and no audit. |
| F4 | Low | The approval attestation `subject_hash` covers the full bank row, so a guessed number can be confirmed offline from the masked projection. |
| F5 | Low | Journal detail returns 403 for an out-of-scope id and 404 for a nonexistent one (existence disclosure for derived P2P journals). |
| F6 | Info | Supplier bank accounts are not project-scoped for `supplier.manage` holders. A custom role holding `supplier.manage` and `bank.details.reveal` can reveal any supplier account from any project. |
| F7 | Info | Reveal hygiene: failed attempts are not audited, the purpose is measured in bytes with no upper bound, and `p2p.read` is not required. |
| F8 | Info | The `supplier.bank.add` audit payload reveals the account-number length. |
| F9 | Info | `urn:uuid:` ids pass `uuid.Parse` and return 500. Uppercase, braced and unhyphenated ids return 200 with `detail:null` for in-scope readers. No leak. |

Regressions: none. The full suites give 156 top-level PASS and 5 FAIL; the 5 failures are exactly my probes F1 to F5. No test skipped. The browser test `TestConsoleBrowserJourneyA` ran and passed.

---

## Area 1: is every path that returns P2P content or derived data governed by canSee?

### What I checked

**Code.** I read the following and followed every caller of `postgres.GetDoc`:

- `docscope.go` and all of `p2p.go`;
- `p2prepo.go`: `GetDoc`, `ListDocs`, `listSQL`, `ExpectedLines` and the reports;
- `p2p_handlers.go` and `server.go`: `fail` and `translate`;
- `auth.go`, `sessions.go`, `workflow.go` (`loadSubjectFacts`) and `kernel.go` (`GetJournal`, `record`);
- the 0013 `p2p_subject_text` and `approval_subject_hash` functions and the `RAISE` messages in 0013 to 0015.

**Results of the code review:**

- `GetDoc` is reached only through `visibleDoc`.
- `ExpectedLines` is used only inside commands that already called `loadDoc`.
- Workflow subjects are only `journal`, `fx_snapshot` and `fiscal_period`.
- No audit read API exists.
- `docProject` covers every project type in `p2pTables` (BOQ, PR, RFQ, quote, PO, GRN, invoice), and its default `""` fails closed to tenant-wide only. I found no missing case.

**List labels.**

- Supplier and invoice labels carry the supplier name, which every `p2p.read` holder may see by design.
- The `payment_instruction` and `bank_statement` lists are entity-level, so tenant-wide only.
- Bank-account labels show only the last 4 digits.

### F1 (Medium): `Has(scope.tenant_wide)` instead of the visibility policy

These sites still gate entity-level P2P data with `s.authz.Has(p, auth.PermScopeTenantWide)`. That is true for a token that has a tenant-wide role **and** a project list. `ScopeOf`, and therefore `canSee`, treat the same token as restricted.

- `internal/kernel/p2p.go:1085`, `PreparePayment`: creates entity-level payment instructions. Invoices, supplier bank and company bank in the allocation are not checked with `visibleDoc`.
- `internal/kernel/p2p.go:1437`, `ImportBankStatement`: writes to an entity-level company account.
- `internal/kernel/p2p.go:1492`, `AutoReconcile`. Its helper `reconcileLine` (`p2p.go:1548-1584`) reads and updates `payment_instructions` (sets `SETTLED`) and returns `payment_number` and `payment_id` without `visibleDoc`.
- `internal/kernel/p2p.go:1615`, `GLReconciliation`: per-entity subledger totals, including bank and payments in transit.
- `internal/kernel/p2p.go:1676`, `ListJournals`: the tenant-wide journal worklist. `GetJournal` (`kernel.go:153`) uses `RequireProject`/`ScopeOf`, so list and detail disagree.
- `internal/kernel/p2p.go:1703`, `Whoami`: reports `tenant_wide:true` for a restricted token. Display only, but the console uses it.

**Probes** (actual output, from `probe-output.txt`). All principals hold their default role and are restricted by `ProjectIDs=[P-001]`.

```
OPEN: project-restricted treasury officer PREPARED payment instruction 8c7ff701 (entity-level); reading it back: store: not found
OPEN: project-restricted statement officer learns the company account balance from the error: "store: database invariant violated: statement opening balance 1.000000 does not continue the previous closing balance 902825.000000"
OPEN: project-restricted statement officer IMPORTED a statement on an entity-level company account it cannot see
OPEN: project-restricted accountant ran AutoReconcile: {"matched":[{"line_no":1,"payment_id":"c00f82af-...","payment_number":"PAY-2026-000001","journal_id":"e932575b-..."}],"unmatched":null}; payment now SETTLED; same principal reading the payment: store: not found
OPEN: project-restricted accountant lists 6 P2P journals (2 payment/settlement, e.g. P2P_PAYMENT "Payment PAY-2026-000001" source_ref=c00f82af debits=97175); GetJournal of the first: auth: forbidden: tenant-wide (unassigned) records require scope.tenant_wide
OPEN: project-restricted controller reads entity-level GL reconciliation (4 checks): [... "Payments in transit: CBE Operating","subledger":"97175" ...]
info: Whoami(project-restricted accountant).TenantWide = true
```

The same failures reproduce over HTTP (`TestR5_H1`):

```
OPEN: project-restricted accountant gets the tenant-wide journal worklist (200)
OPEN: project-restricted controller gets entity P2P reconciliation (200)
OPEN: project-restricted statement officer imports a statement on an entity-level account it cannot read (201)
      same officer reading that account -> 404
info: /v1/identity/me for scoped accountant: tenant_wide=true project_ids=[...]
```

**Why Medium.** ADR 0010 states, under Consequences, that "a role with a project list is project-scoped everywhere (SC-05)". The fix's own tests treat a "project-restricted analyst" (a tenant-wide role plus a project list) as a principal that must not see entity-level documents. Through these paths that principal:

- obtains payment numbers, ids and amounts;
- obtains company bank balances;
- mutates payment instructions (PREPARE, and SETTLE via reconciliation).

Each mutation still needs the matching permission and an attestation, and SoD still applies. That is why I rate it Medium rather than High.

**Fix.**

1. Add a single helper, for example `func (s *Service) requireTenantWide(p) error { if !s.authz.ScopeOf(p).TenantWide { return ErrForbidden } }`, or better `canSee(p, "<type>", "")`. Use it at the six sites above. `Whoami` should report `ScopeOf(p).TenantWide`.
2. In `PreparePayment`, call `visibleDoc` on the supplier bank account, the company bank account and each allocated invoice.
3. In `reconcileLine`, call `visibleDoc(..., "payment_instruction", paymentID, true)` before the update.
4. Add a lint or test that forbids `Has(p, auth.PermScopeTenantWide)` outside `auth.ScopeOf`.

### Detail of other types

`TestR5_02` read every document of all 12 types as 8 principals: CFO, finance manager, treasury, controller, tenant-wide auditor, buyer, PM and AP supervisor. It also listed every type.

```
held: 117 successful detail reads across 12 types and 8 principals (+ lists): no full account number, no bank_snapshot
```

The RFQ detail includes all quotes and prices for any project role with `p2p.read`, the storekeeper included. The supplier master, including the tax id, is visible to all `p2p.read` holders. Both are by design; recorded as info.

## Area 2: scope semantics

`TestR5_06` and `TestR5_H1` results:

```
held: no roles -> forbidden for real and random ids and lists (auth: forbidden: p2p.read)
held: p2p.read with empty project list and no tenant_wide -> not found
held: tenant_wide role + project list confined to its projects
project list ["", UPPER(project)] reading purchase_order|payment_instruction|p2p_policy -> store: not found   (fails closed)
held: cross-tenant ids -> not found
type "Payment_Instruction"/"PAYMENT_INSTRUCTION"/"payment_instruction "/"bank_statement"/"bank_statement_line"/"journal"/"" -> p2p: unknown document type (same for real and random ids)
HTTP: type upper / bank_statement -> 404 {"message":"unknown document type"} for both tenant-wide and scoped
```

- A role granting `p2p.read` without a project list sees nothing project-level and nothing entity-level.
- Unknown types never reach the database, so their response does not depend on whether the id exists.
- The only scope divergences found are F1 (`Has` vs `ScopeOf`) and F6 (the `supplier.manage` design).

## Area 3: masking

**Detail and list responses.** Covered above: 117 reads, all lists, no full number and no `bank_snapshot`.

**Persistence.** `TestR5_02` scanned every public table as the operator, after a full flow with a reveal of both account kinds:

```
held: full number 10...77 stored in company_bank_accounts (2 rows) (expected master table)
held: full number 10...89 stored in supplier_bank_accounts (2 rows) (expected master table)
```

The full numbers appear nowhere else: not in `audit_log`, `outbox`, `approval_attestations`, workflow or journals.

**Audit payloads:**

```
info: audit supplier.bank.add    {"supplier_id": "...", "account_last4": "*********6789", "bank_account_id": "..."}
info: audit bank.details.reveal  {"account": "****6789", "purpose": "...", "document_type": "supplier_bank_account", "mfa_auth_time": "..."}
```

**Errors.**

- An invalid supplier number is rejected with only the check-constraint name; the number is not echoed.
- A duplicate company number returns only the constraint name.
- The server log was captured in `TestR5_H1` across the setup, reveal, error and 500 paths: 11,529 bytes and no full number.

**F3 (Low): guessed-number oracle on company accounts.**

- `0013_procure_to_pay.sql:442` declares `UNIQUE (tenant_id, account_number)`.
- `internal/store/postgres/store.go:137` returns the constraint name.

```
wrong guess -> <nil>          (a PENDING row is created)
right guess -> store: database invariant violated: company_bank_accounts_tenant_id_account_number_key
OPEN (oracle): registering a guessed company account number distinguishes right from wrong guesses
```

A `bankacct.manage` holder who sees only `****8777` can confirm a full number without `bank.details.reveal`, MFA or a reveal audit. Every wrong guess leaves a PENDING row, so the attack is noisy. The holder also usually entered the account in the first place, hence Low.

Fix: run a pre-insert uniqueness check that returns a generic "cannot register this account" message, audit the refused duplicate attempt, and rate-limit registrations. Alternatively, enforce uniqueness on an HMAC of the number and do not expose which constraint failed.

Supplier accounts have no uniqueness constraint, so there is no oracle there, but duplicates are accepted.

**F4 (Low): attestation hash enables offline confirmation.**

- `approval_subject_hash` (`0013:1733-1777`) calls `p2p_subject_text('supplier_bank_account')`, which is `to_jsonb(row)` including `account_number` (`0013:1692`). The result is stored as `approval_attestations.subject_hash`.
- Every other field of that row is in the masked projection, plus `tenant_id`, which the caller knows. The status and approver at signing time are predictable.

`TestR5_07` uses **only** the buyer's masked API response, the tenant id and a 10^5 candidate space:

```
OPEN (info/low): the stored approval subject hash confirms the account number ****6789 (full match) from the masked projection after 100000 guesses
```

No API exposes `approval_attestations` today, so the exposure is limited to anyone who can read that table: the app DB role, replicas, backups and BI exports. This is the same population the ADR puts out of scope (R-BANK-AT-REST), but the hash defeats masking even where only the attestations are shared. The same applies to `payment_instruction` (its `payee` section) and to `bank_snapshot` (`0013:736-738`), which is unkeyed sha256 over the same fields.

Fix: hash the account number with a keyed HMAC, held in an `account_number_hmac` column, and use that in `p2p_subject_text` and `p2p_bank_snapshot` instead of the plain number.

**F8 (Info).** `last4` (`p2p.go:305-311`) pads with one `*` per hidden character, so `account_last4` in audit and outbox reveals the number's length. Use `MaskAccount` instead.

**Masking strength (Info).** Numbers may be 6 characters long (`^[A-Z0-9]{6,34}$`). For a 6-character number `****` plus the last 4 leaves only 2 unknown characters, 1,296 candidates, which makes F3 and F4 trivial for short numbers. Consider masking proportionally, for example showing at most the last 4 and never more than 1/3 of the characters.

## Area 4: reveal

From `TestR5_04` and `TestR5_H1`:

```
held: reveal type "payment_instruction" / "supplier" / "Supplier_Bank_Account" / "supplier_bank_account " / "SUPPLIER_BANK_ACCOUNT" -> not found
held: whitespace-padded purpose refused
MFA age 9m0s -> <nil>;  MFA age 11m0s -> auth: recent multi-factor authentication required (within 10m0s); MFA=false refused
held: 2 identical reveals -> 2 audit records
held: reveal out-of-scope == nonexistent: store: not found   (kernel)  and 404 identical bodies (HTTP)
held: cross-tenant reveal -> not found
held: reveal with a revoked session -> kernel: session revoked
held: reveal 200 with Cache-Control: no-store
```

The pre-existing tests also cover the no-permission case (403 for buyer, site engineer and treasury) and the stale-MFA case (401 with an RFC 9470 challenge).

**No way to get the number without an audit record.**

- The number leaves the kernel only from `RevealBankAccount` (`docscope.go:206-214`).
- The audit and outbox `record` call is in the same transaction, and the value is returned only after commit.
- Every other path is masked: detail, list, reconciliation, journals and errors.
- The only ways to derive the number without an audit are the oracles F3 and F4.

**F6 (Info).** `canSee` (`docscope.go:43-44`) lets any `supplier.manage` holder see every supplier's bank account (masked) regardless of project. With the default roles nothing changes, because the reveal roles are tenant-wide. Roles are tenant data in production, though. With a custom role combining `supplier.manage` and `bank.details.reveal`:

```
info: project-restricted (other project) holder of supplier.manage+bank.details.reveal revealed ****6789
```

Fix: require `ScopeOf(p).TenantWide` inside `RevealBankAccount`, or reject that role combination when roles are defined.

**F7 (Info).**

- Refused reveal attempts (out of scope, nonexistent, no permission, stale MFA) leave no audit record: `audit records for 3 refused reveal attempts: 0`. Probing for numbers is therefore invisible. Consider a security log entry for refused reveals.
- The purpose is checked in bytes (`docscope.go:195-196`). `aaaaaaaaaaaaaaaaaaaa` and 9 Ethiopic runes are accepted.
- There is no upper bound: a 70 kB purpose returned 200 and is stored in the audit and outbox. The body limit is 1 MiB. Cap the purpose at around 500 runes.
- `p2p.read` is not required for a reveal: `reveal by a principal without p2p.read -> <nil>`.
- Replay is permitted, with one audit record per call. There is no reveal-specific rate limit.

## Area 5: existence disclosure

**Detail, reveal and mutations.** These hold in the kernel (identical error strings) and over HTTP (identical status and body):

```
held: ApprovePayment / ReleasePayment / CancelPayment / SubmitPayment (scoped), DecideP2PPolicy, ApproveCompanyBank, ApproveSupplierBank, DecidePR (other project), GetP2PDoc payment/PR: real == random: store: not found
HTTP: GET policy/company bank/supplier bank, reveal company/supplier, approve pending company bank, approve policy: out-of-scope == nonexistent: 404 {"error":{"code":"not_found","message":"not found"}}
```

**F2 (Low): lock before check.** `visibleDoc` (`docscope.go:60-73`) runs `GetDoc(..., lock=true)`, which is `SELECT ... FOR UPDATE`, **before** `docProject` and `canSee`. An out-of-scope caller therefore waits on another transaction's row lock for an existing document, and returns at once for a nonexistent one:

```
locked out-of-scope payment: timeout: context deadline exceeded after 1.501s; nonexistent: store: not found after 5ms
OPEN (low): out-of-scope mutation takes FOR UPDATE before canSee
```

This is a deterministic existence oracle, not microsecond timing. It also lets out-of-scope callers queue on, and briefly hold, locks on documents they may not see.

Fix: resolve the project and evaluate `canSee` first, without a lock (`docProject`, then `canSee`), and only then run `GetDoc(..., FOR UPDATE)`, re-checking after the lock in case the document moved.

**F5 (Low).** `GetJournal` (`kernel.go:153`) returns `auth: forbidden: tenant-wide (unassigned) records require scope.tenant_wide`, which maps to 403, for an existing out-of-scope journal. A nonexistent id gives `store: not found`, which maps to 404. P2P payment and settlement journals carry `source_ref` set to the payment id. The same pattern applies to journal approve/post in the batch results. Fix: map an out-of-scope result to `ErrNotFound`.

**F9 (Info).**

- `urn:uuid:<id>` passes `uuid.Parse` (`p2p_handlers.go:449`) but PostgreSQL rejects it, so the request returns 500 `internal` and logs an error. It does so for existing and nonexistent ids alike, so there is no oracle.
- Uppercase, braced and unhyphenated ids return 200 with `detail:null` to in-scope readers, because `p2p_subject_text` requires the canonical form. This is harmless.

Fix: canonicalise the id (`uuid.Parse(id).String()`) before it reaches the kernel.

## Area 6: regressions

Command: full `./internal/kernel` and `./internal/httpapi` with `-race -count=1 -p 1` on `serk_review5` (output in `full-suite.txt`).

- Package results: `FAIL kernel 35.2s`, `FAIL httpapi 15.2s`.
- Top level: 156 PASS, 5 FAIL, 0 SKIP.
- The 5 failures are `TestR5_01`, `TestR5_03`, `TestR5_05`, `TestR5_07` and `TestR5_H1`, my probes reporting F1 to F5.
- Every pre-existing test passes, including all IA-040-01, review-3 and review-4 regressions and `TestConsoleBrowserJourneyA`, which ran in 10.6 s under node and Playwright with no environmental failure.

The commit message cites "209 PASS"; my count is top-level tests in these two packages only.

## What I could not test

- **Fine-grained timing.** I tested only the blocking or lock oracle (F2), not statistical response-time differences between out-of-scope and nonexistent ids.
- **Production identity provider.** The claims came from the test verifier: `pkind`, `amr`, `auth_time` and project lists. I did not test whether production tokens can carry a project list together with a tenant-wide role, although SC-05 says they can.
- **Downstream consumers.** I did not test the outbox relay and its external consumers (`internal/relay`). The reveal event carries the free-text purpose and the masked number. I checked the payload contents, not the consumers' logs.
- **Console rendering.** I did not render the console for the new probes. The existing browser test passed. I read `app.js`: the revealed number is written only into an `<output>` element, with nothing in local or session storage.
- **Data at rest.** Backups, replicas and BI exports, which make F4 practical, were out of scope. So was column encryption, which is the recorded follow-up R-BANK-AT-REST.
- **Concurrency.** I did not run concurrent reveal or revoke races.
