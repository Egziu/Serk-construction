# ADR 0013: Planning by the critical path method, baselines and earned value

Status: accepted (migration 0027). Date: 2026-10-22. Gate: GATED-02.

## Context

Projects were budgeted (BOQ) and costed (ledger) but not scheduled. Nothing said when work should happen, whether it was late, or whether the money spent matched the work done. `pkg/evm` computed earned-value figures but nothing fed it.

## Decision

1. **The CPM engine** is pure Go (`pkg/schedule`, `cpm-v1`).
   - Durations and lags are whole working days.
   - Links are FS, SS, FF and SF, with lags or leads.
   - The forward pass gives early dates, the backward pass gives late dates against the network finish or a required finish, and the engine computes total and free float.
   - **Refusals.** It refuses duplicate or unknown activities, self-links, duplicate links, negative durations and cycles. A cycle is reported with its path.
   - **Infeasible finish.** A required finish the network cannot meet is shown as negative float, not hidden.
2. **Calendar.** A schedule has its own working weekdays and holiday dates. A start or required finish on a non-working day is refused. Go and SQL use the same rules.
3. **Trust boundary: the database re-verifies the computation.**
   - The kernel computes and stores early and late offsets, floats and dates. When the schedule is submitted, and again when it is approved, `schedule_assert_cpm` checks each activity against its local equations:
     - ES = max(0, constraints from its predecessors);
     - LF = min(target, constraints from its successors);
     - EF = ES + d; LF = LS + d; TF = LS − ES;
     - the stored early dates match the calendar;
     - the finish is the latest EF.
   - It also checks that the network is acyclic.
   - On an acyclic network these equations have exactly one solution, so local checks verify the whole schedule without trusting the application. A date altered after computation is refused at submission (`TestScheduleBaselineProgressEVM`).
4. **Budgets.** Activities carry a cost code and a budget. At submission, budgets per cost code may not exceed the approved BOQ for that code, and every code must belong to the project.
5. **Approval.**
   - A planner (`schedule.manage`) creates and submits a schedule.
   - A project manager (`schedule.approve`) approves it as the **BASELINE**, as a different person and a human. The previous baseline is superseded in the same transaction; a baseline cannot be superseded any other way.
   - A rejection needs a reason.
6. **Progress.**
   - The planner reports percent complete and actual dates against the baseline, at a status date between the start and today. Status dates move forward.
   - 100 % requires an actual finish, and any progress requires an actual start.
   - A project manager approves the report. Percent complete never decreases compared with the last approved report.
7. **Earned value** (`schedule_evm`, nominal basis):
   - **PV:** each activity's budget, spread linearly over its working days [ES, EF), up to and including the status date. A milestone counts in full once due.
   - **EV:** budget × the latest approved percent complete on or before the status date.
   - **AC:** posted EXPENSE journal lines on the project up to the status date.
   - SV, CV, SPI and CPI follow. SPI and CPI are undefined, not zero, when their denominator is zero.

## Consequences and limits

- **Not built:**
  - resource loading and levelling;
  - per-activity calendars;
  - constraints other than the start and the required finish;
  - forecast dates recomputed from progress (out-of-sequence progress);
  - constant-price EVM. The `pkg/evm` index deflation is not wired.
- **AC is all posted expense on the project**, not only cost coded to scheduled activities. With partial schedules, CPI understates performance.
- **Free float and late dates** are stored by the kernel but not re-verified. Only the equations above are checked.
- **AI principals** may prepare schedules and progress as drafts; approval is human (0019).

## Tests

- `pkg/schedule`: the textbook network, all link types and lags, a required finish with negative float, invalid networks, and a 6-day calendar with a holiday.
- Kernel: `TestScheduleBaselineProgressEVM` (figures in docs/testing/E2E_PLANNING.md).
- HTTP: `TestAPISchedule_BaselineProgressEVM`.
- Browser: `TestConsoleBrowserPlanning`, in which the planner builds the network in the form, the project manager approves, progress is reported and approved, and the EVM page is checked. It also runs at 390 px in the dark theme.

## Addendum: independent review 9 (2026-10-22), migration 0030

- **Earned value (R9-F1).** Each activity's EV uses its own latest approved percent complete at or before the status date. A progress report need not list every activity.
- **Planned value (R9-F4).** The elapsed working-day count includes the start day once the status date has reached it, so a non-working status date gives the same PV as the last working day before it.
- **Bounds (R9-F3).**
  - The status date must lie within ten years before the start and ten years after the finish; outside that range the request returns 422.
  - A version may hold at most 400 holidays.
  - The report runs under a 5 s statement timeout.
- **Verification (R9-F7).** The database also re-checks free float, the critical flag (least total float, and ≤ 0) and the late dates against the pkg/schedule rules. A forged computed column can no longer reach a baseline.
- **Progress order (R9-I1).**
  - Reports are approved in status-date order.
  - An actual start may not precede the schedule start.
