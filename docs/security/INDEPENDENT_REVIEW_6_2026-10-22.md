# Independent review 6: contract to cash (0018) and human decisions (0019)

- Target: SERK Construction worktree at commit `297ab8f`.
- Scope:
  - `0018_contract_to_cash.sql` and `0019_human_decisions.sql`;
  - `internal/kernel/contract.go`, `kernel.go` (authorize), `docscope.go`;
  - `pkg/auth/auth.go` and `internal/httpapi/ar_handlers.go`;
  - ADRs 0008 to 0011 as background.
- Method: executable probes only.
  - `internal/kernel/zz_review6_test.go`: 16 tests.
  - `internal/httpapi/zz_review6_test.go`: 1 test.
  - Both ran against PostgreSQL 16 in a disposable database, with `-race`. Every claim below comes from that run.
- Raw output:
  - probes: `probe-output.txt`;
  - existing suite: `full-suite.txt`. It was run before the probe files were added. It includes both browser journeys, with 169 tests passing, 0 failing and 0 skipped, so there is no regression.

## Verdict

**The security controls of the slice held; the financial workflow has four real Medium defects.**

The attestation boundary, the human-only rule, separation of duties and visibility all held in every probe I wrote, whether the probe went through the kernel, raw SQL as the tenant runtime role, or HTTP. This was 66 "held" results, including concurrency races on allocations, advances and measurements. None of my probes let an authenticated user or a holder of the tenant runtime credential:

- forge a decision;
- skip a workflow step;
- change a computed figure;
- bind a journal to the wrong document;
- see another project's or tenant's documents.

The four Medium defects are correctness and availability problems in the financial workflow, not authority bypasses:

1. The contract policy can never be succeeded. The VAT rate is frozen for good.
2. A receipt cannot be cancelled, and a cancelled one still holds its bank line. One wrong draft blocks applying that cash permanently.
3. Contract terms that the database accepts produce a certified IPC with a negative amount due, and that IPC can never be invoiced.
4. Reversing an AR journal, which is the only correction path, leaves the documents saying "invoiced and payable". The AR reconciliation still shows zero difference.

I would not call Journey B production-ready for revenue until F1 to F4 are fixed.

## Findings

| ID | Severity | Finding |
|---|---|---|
| R6-F1 | Medium | No successor contract policy can ever be created and approved. The insert guard treats the existing policy's AR, retention and advance accounts as "control accounts" and refuses them. The approval guard requires a successor to keep exactly those accounts. So the VAT rate and base are frozen for good. |
| R6-F2 | Medium | Customer receipts have no cancel command in the kernel or API. `customer_receipts.statement_line_id` is UNIQUE across all statuses, CANCELLED included. One wrong DRAFT receipt therefore makes a money-in line unusable permanently. This applies to a wrong allocation, a sub-cent split, a foreign-currency advance, or a draft recorded by the statement importer. Any AR clerk can do this to any line. |
| R6-F3 | Medium | `ipc_compute` certifies a negative amount due when retention plus advance recovery exceed the gross, for example 20% retention with 100% recovery. The database accepts those contract terms. The certified IPC can never be invoiced: the expected lines drop the non-positive AR line, so the journal is unbalanced. |
| R6-F4 | Medium | Reversing a posted `AR_INVOICE` journal leaves the invoice APPROVED and payable, and the IPC INVOICED. The work stays in `previous_gross` for good, so it can never be certified again. `ar_gl_reconciliation` reports zero difference on every check while the GL holds a credit receivable and the contract position says "invoiced 38,500, open 0". |
| R6-F5 | Low | The company bank account control guard ignores contract-policy control accounts. A bank account whose GL account is the AR control account was registered and approved by the CFO. |
| R6-F6 | Low | `ipcs.period_end` is free text in effect. An IPC "to 2025-01-01" on a contract signed 2026-10-01 was prepared, certifying work measured to 2026-10-20. |
| R6-F7 | Info | `POST /v1/contracts` with a malformed `customer_id` returns 500 instead of 4xx. |
| R6-F8 | Info | Smaller observations: `ContractPosition` locks for a read, manual journals can hit AR control accounts (the reconciliation detects it), the advance-recovery shortfall has no catch-up, and two comments say "0017". |

---

### R6-F1 (Medium): contract policy succession is impossible

**Evidence** (`TestR6_09_ContractPolicySuccession`):
```
OPEN: no successor contract policy can ever be approved (VAT rate/base frozen forever):
  same control accounts: store: database invariant violated: contract policy control accounts must not be bank or procure-to-pay control accounts
  fresh control accounts: store: database invariant violated: a successor contract policy keeps the AR, retention and advance control accounts
  same AR/retention/advance, new VAT account: store: database invariant violated: contract policy control accounts must not be bank or procure-to-pay control accounts
```

**Cause.** 0018 redefines `p2p_is_control_account` to include every row of `contract_policies`. `contract_policies_guard` on INSERT then calls it for the new policy's AR, retention, advance and VAT accounts. A v2 that reuses v1's accounts, which the approval branch requires, is therefore refused at insert. The same thing happened to P2P policies in 0015 (L-D), but `p2p_policies_control` only checks bank accounts and PO lines, so P2P succession still works.

**Why it matters:**
- The contract policy is where the VAT rate and base live (ADR 0011: "VAT is tenant configuration"). A change in the VAT rate, or a correction after the tax sign-off GATEP-03, cannot be applied without a database owner editing the table.
- Only the first policy can ever exist.

**Fix:**
- In the insert guard, exclude the entity's own contract policies from the control-account test. For example, use a variant of `p2p_is_control_account` that ignores `contract_policies` rows of the same `legal_entity_id`.
- Or test only bank and P2P accounts there.
- Keep the successor rule at approval.
- Add a test that proposes and approves v2 with the same accounts and a new VAT rate.

### R6-F2 (Medium): a draft receipt is irreversible and the bank line it uses is lost permanently

**Evidence** (`TestR6_06`, `TestR6_02`, `TestR6_07`, `TestR6_12`):
```
info: re-recording the line while the wrong draft exists: ... customer_receipts_statement_line_id_key
OPEN: after cancelling the wrong draft receipt the money-in line can never be receipted again: ... customer_receipts_statement_line_id_key
info: AR recon "Unapplied money in (statement lines without a confirmed receipt)": 35000 in 1 lines (permanently, for this line)
```
Ways a DRAFT that can never be confirmed gets created, all accepted at recording:
```
held (late): sub-cent receipt recorded as DRAFT 9f2e349d but refused at confirmation: ledger: invalid line: line 3 amount must be positive
held (at confirmation): USD 1000 receipt to an ETB contract advance refused: ... journals_tenant_id_legal_entity_id_functional_currency_fkey
info: but it was accepted as DRAFT df8e673f and now blocks the statement line
info: the importer could RECORD a receipt on its own statement line (refused only at confirmation)
```

The cancellation in `TestR6_06` had to be done as raw SQL with an attested `ar.receipt.cancel`. `grep` finds no `CancelReceipt` in the kernel and no `/v1/receipts/{id}/cancel` route.

**Why it matters.** A receipt clerk who allocates to the wrong invoice or contract has no way back except to have a supervisor confirm the wrong allocation. The other failure cases are worse because their draft can never be confirmed:
- allocations that are not in whole cents;
- a foreign-currency bank line allocated to an advance (there is no currency check on advance allocations at recording);
- a draft recorded by the statement importer, which the independence rule will refuse.

That cash can then never be applied to the customer's invoice: the receivable stays open and the line shows as "unapplied" permanently. Any `ar_clerk` can do this to every money-in line, deliberately or by mistake, which makes it a denial of service on cash application.

**Fix:**
- Add a kernel/API `CancelReceipt` that makes a DRAFT receipt CANCELLED, with an attested reason. The SQL branch already exists.
- Replace `UNIQUE (statement_line_id)` with a partial unique index `WHERE status <> 'CANCELLED'`.
- Refuse at recording, as well as at confirmation:
  - allocation amounts that do not respect currency precision (`assert_currency_precision`);
  - advance allocations whose contract currency differs from the receipt's;
  - recording by the statement importer.

### R6-F3 (Medium): negative amount due on a certified IPC

**Evidence** (`TestR6_01_NegativeAmountDue`). The contract has 20% retention, an advance of 1,000,000 received, and 100% recovery. The HTTP probe shows the same terms are accepted over the API.
```
OPEN: IPC certified with a negative amount due: -70000.000000 (gross 350000.000000, retention 70000.000000, recovery 350000.000000, VAT 0.000000)
OPEN: certified IPC 9e1a91b7 cannot be invoiced (stuck: IPC stays CERTIFIED, invoice DRAFT, no credit to the client's account): ledger: journal does not balance: debits 420000.00 ETB credits 350000.00 ETB
```

**Cause:**
- `amount_due = this_gross - retention - recovery + VAT` has no lower bound.
- `ar_expected_lines` keeps only lines with `amount > 0`, so the AR line, which should be a credit of 70,000, disappears.
- The contract check constraints allow `retention_pct <= 0.2` and `advance_recovery_pct <= 1` independently.

**Why it matters:**
- A certificate signed by the client with a negative balance (money owed to the client) is valid commercially. Here the database certifies it and then cannot invoice it.
- The IPC stays CERTIFIED with no way out (CERTIFIED cannot be cancelled), and its figures still count in the next IPC's `previous_gross`.
- The client's credit is never booked.

**Fix**, choose one:
- (a) Constrain recovery so the amount due cannot go negative. For example, cap recovery at `this_gross - retention + VAT`, or refuse contracts where `retention_pct + advance_recovery_pct > 1`.
- (b) Support a negative amount due properly: emit a CREDIT on AR in `ar_expected_lines` instead of dropping the line, and allow negative-total invoices (credit memos) in the allocation logic.

Either way, add the case to the IPC tests.

### R6-F4 (Medium): reversing an AR journal leaves the documents invoiced, payable and certified for good

**Evidence** (`TestR6_08_ReversedInvoiceJournal`). The steps were:
1. The invoice journal is posted.
2. The controller reverses it; a second controller posts the reversal.
3. The client pays the invoice.
```
info: after reversal: invoice APPROVED / journal REVERSED / IPC INVOICED
info: AR recon Accounts receivable   subledger -38500 gl -38500 diff 0 open 1
info: AR recon Retention receivable  subledger      0 gl      0 diff 0 open 1
info: contract position invoiced 38500 certified 35000 receivable_open 0; GL AR -38500 revenue 0
info: next IPC gross 350.000000 (the reversed 35,000 of work is treated as already certified: previous_gross 35000.000000)
OPEN: AR reconciliation reports zero difference on every check while the GL shows AR -38500 ...
```

**Cause:**
- ADR 0009 says a wrong document "is corrected by reversal", and `journals_subledger_guard` refuses only cancellation. Nothing ties a reversal back to the document: the invoice stays APPROVED and payable, and the IPC stays INVOICED.
- `ar_gl_reconciliation` counts only documents whose journal is POSTED, so the reversed invoice drops out of the subledger and out of the GL together. The difference is 0. The only signal is `unposted_documents = 1`, which is mislabelled because the document was posted and then reversed.
- `ipc_compute` keeps counting the INVOICED IPC in `previous_gross`, so the same work can never be certified or recognised as revenue again.
- Credit notes are explicitly out of scope (ADR 0011), so reversal is the only correction tool available.

**Why it matters.**
- Revenue and the receivable were removed from the ledger, but the commercial documents still show them as invoiced, payable and certified.
- Cash received afterwards sits as a credit in AR, and reconciliation reports it as reconciled.
- A legitimate controller and finance manager doing the documented correction produce books where the documents and the GL disagree without any alarm.

**Fix:**
- Either refuse reversal of `AR_*` journals (and `P2P_*` ones by the same reasoning) until a document-level correction exists (a credit note, or invoice cancellation that reopens the IPC),
- or make reversal of an `AR_INVOICE` journal reopen the IPC and void the invoice in the same transaction.
- Report journals that are REVERSED while their document is still live as a separate, non-zero reconciliation exception, not as "unposted".

### R6-F5 (Low): a company bank account can use AR control accounts

**Evidence** (`TestR6_09`):
```
OPEN (low): a company bank account was registered with the AR control account as its bank GL account; CFO approval: <nil>
```

**Why it matters.** `company_bank_accounts_control` (0015) checks P2P policies and PO lines but not `contract_policies`. A receipt on that bank account would post Dr AR / Cr AR, cancelling itself out, and the bank and AR reconciliations would both be distorted. Exploiting this needs a treasury officer and the CFO, so it is a maker/checker failure rather than a single-user exploit.

**Fix:** use the updated `p2p_is_control_account` (which now covers contract policies) inside `company_bank_accounts_control`, and do the same in `p2p_policies_control`. I could not test the P2P policy direction (see "Not tested").

### R6-F6 (Low): the IPC period is unconstrained

**Evidence** (`TestR6_04`):
```
OPEN (low): IPC 0b404078 'to 2025-01-01' (contract signed 2026-10-01, work measured to 2026-10-20) prepared with gross 35000.000000
```

**Why it matters.**
- The certificate's period is what the client signs. An IPC can claim a period that predates the contract, or that ends before the work it certifies.
- `ipc_compute` ignores `period_end`, so the figures stay correct, but the document is misleading and periods can overlap or run backwards.

**Fix.** In `ipcs_guard`, require:
- `period_end >= contract.signed_on`;
- `period_end >= max(verified measurement period_end)`;
- `period_end` greater than the previous certified IPC's.

### R6-F7 (Info): a malformed id in the contract body returns 500

**Evidence** (`TestR6_API_JourneyB`):
```
OPEN (info): malformed customer_id -> 500 map[error:map[code:internal message:internal error]]
```
**Fix:** validate `project_id` and `customer_id`, and the allocation ids, with `canonicalUUID` before calling the kernel. A malformed allocation id already maps to 404.

### R6-F8 (Info): observations

- **`ContractPosition` locks for a read.** It uses `loadDoc`, which runs `SELECT … FOR UPDATE`, for a pure read under `p2p.read`. Any project reader takes a row lock on the contract.
- **Manual journals can post to AR control accounts.** A manual journal debiting the AR control account was created, approved and posted, because there is no control-account guard for manual journals. The AR reconciliation detected it (`difference -5000`), so I list it as held.
- **The advance-recovery shortfall is never caught up** (`TestR6_03`). IPC 1 recovered only 300,000 (all that had been received). Later IPCs recover only 50% of their own gross, so the total recovered was 475,000 out of 1,000,000 received. This may be intended, but the ADR should say so.
- **Stale "0017" labels.** The 0018 header comment and the `p2pTables` comment say "0017".

---

## Held

Each item below was executed. The probe output is in `probe-output.txt`.

**Raw SQL as the tenant runtime role** (`TestR6_05`):
- Inserting rows already in a later state, all refused:
  - an IPC inserted as CERTIFIED;
  - a measurement inserted as VERIFIED;
  - a contract inserted as ACTIVE;
  - a receipt inserted as CONFIRMED.
- Changes to contract and measurement data after the DRAFT stage, all refused:
  - inserting, updating or deleting contract lines after activation;
  - changing `retention_pct`;
  - updating or inserting measurement lines after verification.
- Changing IPC figures directly.
- Certifying a DRAFT IPC, skipping SUBMITTED, even with a genuine attestation.
- Certifying with an attestation that lacks MFA, or under a different actor than attested.
- Making an IPC INVOICED without an attested invoice approval.
- A second invoice for the same IPC.
- Approving an invoice:
  - without its journal;
  - with a MANUAL-source journal carrying the exact expected lines;
  - with another invoice's attestation;
  - bound to another invoice's journal.
- Changing `journal_id` after approval.
- Manual journals using the reserved types `AR_INVOICE`, `AR_RECEIPT` or `AR_OTHER`, which the binding trigger refuses.
- Receipts:
  - a receipt on a money-out line;
  - a receipt with a caller-chosen amount and no attestation;
  - adding, changing or deleting allocations after confirmation;
  - matching a line already used for a receipt to a payment.

**Money:**
- Recovery is limited to the advance received.
- An IPC prepared before an advance receipt is stale at certification.
- Total recovery never exceeds what was received (`TestR6_03`).
- Sub-cent allocations that round to a balanced journal are refused at confirmation because the journal lines differ from the expected lines (`TestR6_02b`).
- A USD receipt allocated to an ETB advance is refused at confirmation (`TestR6_07`).
- Negative retention or quantity is refused (HTTP probe).

**Concurrency:**
- Two receipts for 60% each of one invoice, and two advance receipts for 60% each of the advance, confirmed concurrently: exactly one of each pair succeeded (`TestR6_14`).
- Two measurements that together exceed the contract quantity, verified concurrently: one was refused, leaving 70 of 120 verified (`TestR6_15`).

**Human rule (0019):**
- `IsDraftAction` (Go) and `approval_is_draft_action` (SQL) agree on all 74 actions. These are every action used by `authorize`, `submitDoc`, `approval_use` and the creation triggers, plus edge strings.
- IPC certification is refused for the principal kinds `service`, `ai`, `""`, `"Human"` and `"human "`.
- Measurement verification and rejection by a service principal are refused, as is IPC cancellation by an AI principal.
- A validly signed `ipc.certify` attestation without `principal.human` is refused by the SQL trigger.
- An AI principal's `ar.receipt.create` (draft) attestation cannot be used to confirm.
- Receipt confirmation by a service principal is refused.
- Over HTTP, `pkind` service, ai or absent can create a customer (201) but not approve one (403).

**Separation of duties:**
- A user holding both `ar_clerk` and `ar_supervisor` cannot approve their own invoice, in the kernel or through raw SQL with a genuine attestation (`TestR6_12`).
- Receipt confirmation by the statement importer is refused (the existing test, and `TestR6_12`).

**Visibility** (`TestR6_13` and the HTTP probe), for principals scoped to project B (quantity surveyor, commercial manager, project manager, `ar_clerk`, `ar_supervisor`) and for a tenant-2 principal:
- They get not-found on project-A contracts, measurements, IPCs and invoices, and on receipts, which are entity level. The response is identical to a nonexistent id.
- Lists return 0 items for every new type, including `money_in` and `bank_statement`.
- Contract position returns 404 for both other-project and nonexistent ids.
- Profitability returns 403 for both other-project and nonexistent ids.
- The AR reconciliation is forbidden to project-scoped principals; the tenant-2 principal gets empty results through RLS.
- Mutations: issuing an invoice for, or measuring, another project's documents returns not found. A project-scoped AR clerk cannot record a receipt.

**Reconciliation:** a manual posting to the AR control account shows up as a difference (`TestR6_10`).

**Regression:** `go test -race -count=1 -p 1 ./internal/kernel ./internal/httpapi` passes, including `TestConsoleBrowserJourneyA` and `TestConsoleBrowserJourneyB` (`full-suite.txt`).

## Not tested

- **The P2P policy direction of F5.** The probe was refused for an unrelated reason (the P2P successor rule), so the result is inconclusive. It needs a world without an approved P2P policy.
- **OIDC `pkind` mapping** from a real identity provider. Only test-signed tokens were used.
- **Workflow-mandatory paths for AR documents.** No AR workflow definitions were published.
- **Period-close interactions** for back-dated invoice or receipt dates, beyond the existing control test.
- **Concurrency of IPC certification with advance-receipt confirmation**, which was reviewed in code only. `ipcs_one_open` serialises IPCs, but certification does not lock the contract.
- **Contracts in several entities or currencies.** These are out of scope per ADR 0011.
- **A second contract on the same project** was reviewed in code only: `ipc_compute` is per contract.
- **The console UI (new Journey B screens)**, beyond the existing browser tests.
- **Retention release, variations and credit notes**, which are not implemented.
