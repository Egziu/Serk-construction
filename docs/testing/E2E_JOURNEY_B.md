# Journey B: contract to cash, worked figures

The expected numbers of `TestJourneyB_ContractToCashToGL` (internal/kernel/journey_b_test.go), worked by hand. The test checks every figure below against PostgreSQL. All data is synthetic.

The VAT rate (15%) and base (gross less advance recovery) are tenant configuration used as test data. They are not a statement of any jurisdiction's tax law.

## Contract CTR-2026-000001

- Customer: Ethiopian Roads Administration (synthetic).
- Retention: 5%.
- Advance: 1,000,000, recovered at 20% of each certificate's gross. Recovery is limited to the advance actually received.

| Line | Description | Quantity | Rate | Amount |
|---|---|---|---|---|
| 1 | Bulk excavation | 10,000 m3 | 350 | 3,500,000 |
| 2 | Concrete C30 | 1,200 m3 | 6,500 | 7,800,000 |
| 3 | Reinforcement (BOQ item 3.1) | 120 t | 98,000 | 11,760,000 |
| | **Contract value** | | | **23,060,000** |

## Sequence and figures

1. **Advance.** Statement line of 1,000,000 → receipt allocated to the contract advance → `AR_RECEIPT`: Dr Bank 1,000,000 / Cr Advances received 1,000,000.
2. **Measurement 1** (period ending 15 Oct). 4,000 m3 / 300 m3 / 20 t, verified by the site engineer.

   | | Calculation | Amount |
   |---|---|---|
   | Cumulative gross | 1,400,000 + 1,950,000 + 1,960,000 | 5,310,000 |
   | Previous gross | | 0 |
   | **IPC 1 gross** | | **5,310,000** |
   | Retention | 5% | 265,500 |
   | Advance recovery | min(20% × 5,310,000 = 1,062,000, 1,000,000 received) | 1,000,000 |
   | VAT | 15% × (5,310,000 − 1,000,000) | 646,500 |
   | **Amount due** | 5,310,000 − 265,500 − 1,000,000 + 646,500 | **4,691,000** |

   `AR_INVOICE`:

   | Side | Account | Amount |
   |---|---|---|
   | Dr | AR | 4,691,000 |
   | Dr | Retention | 265,500 |
   | Dr | Advances | 1,000,000 |
   | Cr | Revenue | 5,310,000 |
   | Cr | VAT output | 646,500 |

   Both sides total 5,956,500.

3. **Receipt** of 4,691,000 allocated to invoice 1.
4. **Measurement 2** (period ending 20 Oct). +3,000 / +200 / +10, so cumulative 7,000 / 500 / 30.

   | | Calculation | Amount |
   |---|---|---|
   | Cumulative gross | 2,450,000 + 3,250,000 + 2,940,000 | 8,640,000 |
   | Previous gross | | 5,310,000 |
   | **IPC 2 gross** | | **3,330,000** |
   | Retention | 5% | 166,500 |
   | Advance recovery | advance fully recovered | 0 |
   | VAT | 15% × 3,330,000 | 499,500 |
   | **Amount due** | 3,330,000 − 166,500 + 499,500 | **3,663,000** |

5. **Receipt** of 2,000,000 allocated to invoice 2 (part payment).
6. Finance approves and posts all five journals.

## Expected end state

| Measure | Value |
|---|---|
| Contract value | 23,060,000 |
| Measured = certified | 8,640,000 |
| Retention held | 432,000 |
| Advance received / recovered | 1,000,000 / 1,000,000 |
| Invoiced (amount due) | 8,354,000 |
| Received on invoices | 6,691,000 |
| Receivable open | 1,663,000 |

| GL account | Balance (debit +) |
|---|---|
| 1000 Bank | 7,691,000 |
| 1100 Accounts receivable | 1,663,000 |
| 1150 Retention receivable | 432,000 |
| 2200 Advances from customers | 0 |
| 2300 VAT output | −1,146,000 |
| 4000 Contract revenue (on the project) | −8,640,000 |

Every AR reconciliation check has difference 0 with no unposted documents, and no money in is unapplied. The bank check of the P2P reconciliation shows reconciled movements of 7,691,000 = GL 7,691,000 with 0 unmatched lines.

## Controls (TestJourneyB_Controls)

Each refusal is asserted with its reason. The run log is in `docs/testing/evidence/journey-b-kernel.txt`.

**Contracts**
- An advance above the contract value.
- Approval with stale MFA.
- Self-approval.

**Measurements**
- A cumulative quantity above the contract quantity.
- A nonexistent contract line.
- A second sheet for the same period.
- Self-verification.
- A QS of another project (not found).

**IPCs**
- Self-certification.
- Certification without fresh MFA.
- Certification without the certificate hash.
- A stale IPC after a newer verified measurement.

**Invoices**
- An AI principal approves.
- Approval without the permission.
- A second invoice for the same IPC.

**Journals**
- Generated AR journal lines edited directly.

**Receipts**
- Confirmed by the statement importer.
- An advance above the agreed amount.
- Over-allocation of a part-paid invoice.
- An allocation short of the amount received, refused at recording.
- Allocations altered directly after recording, refused at confirmation.

**Periods**
- A period closed while an approved journal awaits posting.
- Approval or posting into a closed period.

## Credit note (`TestJourneyB_CreditNote`, migration 0022)

This is a separate world with no advance received.

**IPC 1**

| Item | Amount |
|---|---|
| Gross | 5,310,000 |
| Retention 5% | 265,500 |
| Advance recovery | 0 |
| VAT 15% on 5,310,000 | 796,500 |
| **Due** | **5,841,000** |

**Credit note:** net 200,000, VAT 30,000, total **230,000**. Journal `AR_CREDIT`: Dr 4000 200,000 (project), Dr 2300 30,000 / Cr 1100 230,000.

**Receipts**

- A receipt of 5,841,000 is refused at confirmation because the credited part is no longer receivable. The draft is cancelled.
- 5,611,000 settles the invoice.
- A second credit note of 10,000 + 1,500 is refused at approval (nothing is open) and is cancelled.

**After posting**

| Account | Balance |
|---|---|
| AR (1100) | 0 |
| Retention (1150) | 265,500 |
| VAT output (2300) | −766,500 |
| Revenue (4000) | −5,110,000 |

- AR reconciliation: difference 0 everywhere. The refused 5,841,000 line stays as unapplied money in (1 line).
- Contract position: invoiced 5,841,000; credited 230,000; received 5,611,000; open 0.
- Project revenue posted: 5,110,000.

**HTTP journey:** IPC 2's invoice is credited 100,000 + 15,000.

| Measure | Value |
|---|---|
| Receivable open | 1,663,000 − 115,000 = **1,548,000** (AR reconciliation agrees) |
| Credited | 115,000 |
| Project revenue posted | 8,640,000 − 100,000 = **8,540,000** |

## Retention release (`TestJourneyB_RetentionRelease`, migration 0023)

This is a separate world with no advance received.

**Certificates**

| IPC | Gross | Retention | VAT | Due |
|---|---|---|---|---|
| IPC 1 | 5,310,000 | 265,500 | 796,500 | 5,841,000 |
| IPC 2 | 3,330,000 | 166,500 | 499,500 | 3,663,000 |

Retention held: **432,000**.

**Releases**

- Release 1, taking over: 216,000. Release 2, end of defects liability: 216,000. Each generates `AR_RETENTION`: Dr 1100 / Cr 1150.
- A further 0.01 is refused (nothing is left).
- A receipt of 300,000 allocated wholly to release 2 is refused (over-allocation) and cancelled.

**Receipts**

| Receipt | Allocated to |
|---|---|
| 5,841,000 | Invoice 1 |
| 216,000 | Release 1 |
| 300,000 | 216,000 release 2 + 84,000 invoice 2 |

**After posting**

| Account | Balance |
|---|---|
| Retention (1150) | **0** |
| AR (1100) | 5,841,000 + 3,663,000 + 432,000 − 6,357,000 = **3,579,000** |
| Revenue (4000) | −8,640,000 (unchanged) |
| VAT (2300) | −1,296,000 |

- AR reconciliation: difference 0. The refused 300,000 line is unapplied money in.
- Position: retention held 0, released 432,000, invoiced 9,504,000, received 6,357,000, open 3,579,000.

**HTTP journey:** 216,000 released after the credit note.

| Measure | Value |
|---|---|
| Retention held | 216,000 |
| Retention released | 216,000 |
| Receivable open | 1,548,000 + 216,000 = **1,764,000** |

**Browser journey:** 265,500 released at taking over. Receivable open is 265,500 and retention held is 0.
