# Journey A end-to-end tests (GATEC-01)

Journey A is tested at three levels. All three run against a real, disposable PostgreSQL 16 database with every migration applied. Nothing is mocked below the HTTP client or the browser.

| Level | Test | What it drives | Evidence |
|---|---|---|---|
| Kernel | `internal/kernel/journey_a_test.go` `TestJourneyA_BOQToBankReconciliationToGL`, plus 7 control suites in `journey_a_controls_test.go` | Service commands as 16 different principals | `docs/testing/evidence/full-suite.log` |
| HTTP | `internal/httpapi/journey_a_api_test.go` `TestAPIJourneyA_EndToEnd` | Every step over HTTP with signed bearer tokens, one person per role, plus adversarial probes at the API boundary | same log |
| Browser | `internal/httpapi/console_browser_test.go` `TestConsoleBrowserJourneyA` → `e2e/console_journey_a.mjs` | Real Chromium (Playwright 1.56) clicking through the web console as 15 people, each in their own browser context | `docs/testing/evidence/console-journey-a.log`, `docs/testing/evidence/console/*.png` |

Adversarial regression from the independent review: `internal/kernel/review3_regression_test.go` (`TestR3_*`).

## Scenario (identical at all three levels)

The BOQ budget for cost code 01-MAT is 12,100,000 ETB: 120 t of steel at 85,000 and 2,000 bags of cement at 950.

1. **Requisition.** 20 t of steel (estimate 86,000) and 500 bags of cement (estimate 960). The project manager approves after the database budget check.
2. **RFQ to three suppliers.**

   | Supplier | Steel | Cement | Evaluation |
   |---|---|---|---|
   | ABC-STEEL | 84,500 | 940 | compliant |
   | HABESHA-CEMENT | 86,000 | 930 | compliant |
   | SAFARI-BUILD | 90,000 | 980 | non-compliant, no mill certificates |

   The award goes to ABC-STEEL, the lowest compliant quote. The PO totals 2,160,000.
3. **Receipts, in two deliveries.** 12 t of steel with 500 bags, then 8 t of steel. A storekeeper records each and a site engineer confirms it. Each confirmation generates a GRNI journal.
4. **Invoices, with three-way match.**
   - Invoice 1 bills cement at 945 against a PO price of 940. The variance is 0.53%, inside the 2% tolerance, so it is MATCHED and 2,500 goes to price variance. Total 1,709,475 including VAT.
   - Invoice 2 is for 8 t of steel, 777,400 including VAT.
   - An AP supervisor approves both, and each approval generates an AP journal.
5. **Journals.** The finance manager approves the 4 subledger journals in one batch; the controller posts them in one batch.
6. **Payments.** Both are above the 500,000 dual-approval threshold.
   - Treasury officer 1 prepares each payment.
   - The finance manager approves (PARTIALLY_APPROVED), then the CFO approves (APPROVED). Both use MFA and are human principals.
   - Treasury officer 2 releases.
   - The 2 release journals are approved and posted.
7. **Bank statement.** An independent statement officer imports a statement with 4 lines: both payments, a customer receipt and a bank charge. The accountant's auto-reconcile matches the 2 payments and leaves the other 2 lines with reasons. The 2 settlement journals are approved and posted.
8. **Expected results**, asserted to the cent at every level:
   - GRNI 0, accounts payable 0 and payments in transit 0. Each subledger equals the GL, with a difference of 0.
   - Reconciled bank movements −2,486,875, equal to the GL.
   - Cost report for 01-MAT:

     | Budget | Committed | Received | Invoiced | Actual posted | Available |
     |---|---|---|---|---|---|
     | 12,100,000 | 2,160,000 | 2,160,000 | 2,162,500 | 2,162,500 | 9,937,500 |

   - 2 payments SETTLED and no P2P journal left unposted. The browser test verifies these through the API after the UI run.

## Controls exercised at the boundary

In the HTTP and browser tests, each of these is refused, and the UI shows why:

- self-approval of the policy, the requisition and the receipt;
- approval by a project manager outside the project;
- awarding a non-compliant quote;
- an over-billed invoice, refused by the database at submit (409);
- approving an unsubmitted invoice;
- payment approval without MFA, a duplicate approver, and release before dual approval;
- release by the preparer, and release by a `pkind=service` principal;
- statement import by treasury;
- unknown document types and malformed ids return 404, not 500;
- an out-of-scope user sees no purchase orders;
- self-approval by a clerk who also holds the supervisor role: 409 "segregation of duties", shown in the UI alert;
- sign-out revokes the session server-side, so the old token gets 401.

## Accessibility and UI checks (browser test)

On every audited page:
- every visible form control has a label;
- every button and link has an accessible name;
- there is exactly one `h1` and a `main` landmark;
- there are no duplicate ids;
- text contrast meets WCAG 2.2 AA (4.5:1, or 3:1 for large text), measured in light theme and in dark theme (the accountant's context);
- there is no horizontal page scrolling at 390 px width;
- no stray `null`/`undefined` text appears;
- there are no uncaught script errors and no Content-Security-Policy violations.

On the sign-in page, the token field has focus and Shift+Tab reaches a visible skip link.

This is an automated check, **not a full WCAG audit**. Screen-reader testing (NVDA/JAWS/VoiceOver) and a manual audit by an accessibility specialist have not been done.

Defects found and fixed by these checks:
- the Sign out button was visible and focusable while signed out, because `.who{display:flex}` overrode `[hidden]`;
- nav link colours changed before their background during a transition (contrast 1.0 for about 120 ms);
- `Element.append(null)` printed "null" in document views.

## How to run

```
export SP=<scratch dir>
export GOWORK=off GOFLAGS=-mod=readonly GOSUMDB=off GOPROXY=file://$SP/gosum/proxy GOMODCACHE=$SP/finalcache
psql -h /tmp -p 5433 -U postgres -c "DROP DATABASE IF EXISTS serk_e2e" -c "CREATE DATABASE serk_e2e"
SERK_E2E_SHOTS=$PWD/docs/testing/evidence/console \
SERK_TEST_ADMIN_DSN='postgres://postgres@/serk_e2e?host=/tmp&port=5433' \
  go test -count=1 -p 1 -run 'TestConsoleBrowserJourneyA|TestAPIJourneyA|TestJourneyA' -v ./internal/httpapi ./internal/kernel
```

The browser test needs `node` and the `playwright` package (`SERK_PLAYWRIGHT` = module directory; it defaults to `npm root -g`/playwright) with its Chromium. Without them the test is **skipped**, never reported as passed.
