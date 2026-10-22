# Planning: worked figures (migration 0027)

These are the figures of `TestScheduleBaselineProgressEVM`, `TestAPISchedule_BaselineProgressEVM` and `TestConsoleBrowserPlanning`. All data is synthetic.

## Network and calendar

- **Calendar:** Monday to Saturday working. The start is Monday 2026-10-05 (day 0).
- **Cost code:** every activity is on the project's 01-MAT, whose approved BOQ budget is 12,100,000 in the kernel test and 10,200,000 in the HTTP and browser tests.

| Activity | Name | Duration | Budget | Depends on (FS) |
|---|---|---|---|---|
| A | Mobilisation | 3 | 1,000,000 | — |
| B | Excavation | 4 | 2,000,000 | A |
| C | Drainage | 2 | 500,000 | A |
| D | Foundations | 5 | 3,000,000 | B |
| E | Handover | 1 | 0 | C, D |

## Critical path

| Activity | ES–EF | LS–LF | Total float | Free float | Dates (early) |
|---|---|---|---|---|---|
| A | 0–3 | 0–3 | 0 | 0 | 2026-10-05 – 10-07 |
| B | 3–7 | 3–7 | 0 | 0 | 10-08 – 10-12 (across Sunday) |
| C | 3–5 | 10–12 | **7** | 7 | 10-08 – 10-09 |
| D | 7–12 | 7–12 | 0 | 0 | 10-13 – 10-17 |
| E | 12–13 | 12–13 | 0 | 0 | 10-19 |

- Finish: working day 12, which is **Monday 2026-10-19**.
- Critical path: A, B, D, E.
- **Required finish 2026-10-14** (day 8, so target EF 9): the minimum float is **−4**. The database verifies the late dates against that target.

## Progress at Wednesday 2026-10-14 (working day 8; 9 days elapsed including it)

| Activity | % | Actual |
|---|---|---|
| A | 100 | 10-05 – 10-07 |
| B | 100 | 10-08 – 10-13 |
| C | 50 | from 10-08 |
| D | 20 | from 10-14 |

## Earned value at 2026-10-14

| Measure | Working | Value |
|---|---|---|
| BAC | | 6,500,000 |
| PV | A 1,000,000 + B 2,000,000 + C 500,000 + D 3,000,000 × 2/5 | **4,700,000** |
| EV | 1,000,000 + 2,000,000 + 250,000 + 600,000 | **3,850,000** |
| SV | | **−850,000** |
| SPI | 3,850,000 / 4,700,000 | **0.8191** |
| AC | no posted cost in the test world | 0, so CPI is undefined |

## Refusals (kernel test)

- A cycle, reported as [A B D E A].
- A start on a Sunday.
- A user without `schedule.manage`.
- Budgets over the BOQ: 15,500,000 > 12,100,000.
- A tampered ES / EF / TF, refused by the SQL equations.
- Self-approval, an AI approver, and the planner approving.
- 100 % without a finish.
- Progress going backwards (D 20 → 10).
- A status date before the last approved one.
- A future status date.
- Superseding a baseline directly.
