# Independent review 9: contract variations, planning (CPM/EVM), review 8 corrections, distributed abuse limits (migrations 0026–0029) at commit 11dcff3

Independent review. Every claim below comes from a probe that was run against dedicated disposable databases (PostgreSQL 16, Go 1.26.10, `-race`):
- `serk_review9` was used while the probes were being developed;
- `serk_review9b` (fresh) was used for the final probe run;
- `serk_review9_full` (fresh) was used for the existing suite.

The shared `postgres` database and the other existing databases were not used. All data is synthetic.

- Probes: `zz_review9_kernel_test.go` (package `kernel`, 10 tests) and `zz_review9_httpapi_test.go` (package `httpapi`, 2 tests), all named `TestR9_*`. Both were removed from the repository tree after the run; the delivering team later kept them as `internal/kernel/review9_regression_test.go` and `internal/httpapi/review9_regression_test.go`.
- Raw probe output: `docs/testing/evidence/review9/probes-before-fix.txt` (final run on `serk_review9b`), `fallback-reruns.txt` (three more runs of one probe), `kernel-run1.txt` and `run2.txt` (development runs on `serk_review9`).
- Existing suite: `full-suite.txt` (`go test -race -count=1 -p 1 ./internal/kernel ./internal/httpapi -skip TestR9_` on fresh `serk_review9_full`, before any probe file existed). Result: **kernel 203 PASS, httpapi 31 PASS, 0 FAIL, 0 SKIP** (top-level tests); both packages `ok`.

Convention: `OPEN:` (t.Errorf) means a defect was observed; `held:` (t.Logf) means the control worked; `info:` is an observation.

## Verdict

**Not ready to sign off. Three Medium defects need a decision or a fix first. None is Critical or High.**

What holds under attack:
- **Variations (0026).** The effective-quantity cap held:
  - in three rounds of a reduction racing a verification;
  - when two reductions raced;
  - when two drafts reused a NEW line number.

  Every raw tenant-role write was refused or re-priced. Approval by another project's CFO, a service principal, a manager without `contract.approve`, the maker, or without MFA was refused.
- **Planning integrity (0027).** The database re-derived ES/EF/LS/LF exactly as computed by hand for a network with an SS+2 link, an FF+1 link and a holiday. Raw cycles, BASELINE tampering, raw BASELINE inserts and a concurrent double approval were all refused. Other-project scope held.
- **Designation path (0028).** It refused an item of another legal entity, another project's buyer and a non-existent line. The R8 raw, AI and service checks were not re-run here.
- **The abuse role (0029).** It has no table privileges, no TEMP and no advisory locks in the test database. Lockout, reset and rate-limit sequences at 1–4 s windows match the in-process limiter. A rotating `X-Forwarded-For` is ignored without trusted proxies.

The defects:
- **EV reads only the newest progress report.** A later report that lists one activity sets every other activity's earned value to 0 (EV 3,850,000 → 1,200,000, SPI 0.8191 → 0.2264). ADR 0013 defines EV as the latest approved percent per activity.
- **After 0028 the PR/PO budget gate no longer bounds stock purchasing.** Put-away releases the commitment, so 18,593,760 of steel was bought through budget-checked PRs on a cost code with a 12,100,000 budget, and "available" never fell below 12,100,000.
- **The EVM endpoint can be made to run a very long query.** `status_date` is unbounded and there is no `statement_timeout`. One request by a project reader costs 5.3 s of database time, and over 30 s (cut off by the probe's timeout) when the baseline carries 3,000 holidays.

Smaller items:
- PV is understated on every non-working status date (weekends and holidays).
- A count shortage reaches no cost code, contrary to the ADR 0012 addendum.
- Abuse limits are per full IPv6 address, so a /64 evades them and grows the counter table.
- The CPM check does not verify the `critical` flag, free float or late dates, so a BASELINE can carry forged ones.
- The posture check misses EXECUTE on an advisory function granted directly to a tenant login.

## Findings

| ID | Severity | Finding |
|---|---|---|
| R9-F1 | Medium | Earned value is read from the single latest approved progress report. A report dated 10-15 that lists only D at 40% took EV from 3,850,000 (10-14) to 1,200,000; A and B (100%) and C (50%) counted as 0; SPI 0.8191 → 0.2264. The "never goes backwards" check does not see omitted activities. |
| R9-F2 | Medium | 0028 semantics: put-away releases an inventory PO line's commitment, so the PR/PO budget gate does not bound stock purchases on a cost code. Four budget-checked PR→PO cycles bought 18,593,760 on 01-MAT (budget 12,100,000). After each put-away: committed 0, available 12,100,000. The control case (two POs open, nothing put away) was refused correctly. |
| R9-F3 | Medium | `GET /v1/projects/{id}/evm?status_date=` accepts any date, and the tenant transaction has `statement_timeout` "0". EVM at 9999-12-31 took 5.34 s with no holidays. With 3,000 holidays it hit the probe's 30 s limit (`context deadline exceeded`). Any principal with `p2p.read` on the project can issue it, up to the per-principal budget. |
| R9-F4 | Low | PV on a non-working status date omits the last working day. Hand: 200,000 at the holiday (Wed 10-07) and 600,000 at Sat 10-10 and Sun 10-11. Database: 100,000 and 400,000. Working-day status dates matched the hand figures exactly. |
| R9-F5 | Low | A count shortage of 12 t (1,014,000) was approved and posted with journal lines `cost_code=-`. 01-MAT available stayed 12,100,000 → 12,100,000. Together with R9-F2, stock bought on a code and written off by count never touches any cost code's budget. The ADR 0012 addendum says count variances are "actual cost of the code they are charged to". |
| R9-F6 | Low | The pre-auth and auth-failure limits key on the full client address. Behind a trusted proxy, 60 invalid tokens from 60 addresses of one IPv6 /64 (limit 3 with lockout) got 0 × 429, and a valid token from the same /64 was served (404). Each address is a new `abuse_counters` row: 100,000 keys = 17 MB (~183 B per key), kept at least window + 1 h. |
| R9-F7 | Low | `schedule_assert_cpm` does not verify `critical`, `free_float`, `late_start` or `late_finish`. In a raw-SQL DRAFT, truly critical D was marked `critical=f ff=30 late=2027-03-01..2027-03-31` and C was marked critical. The version was submitted and approved as BASELINE. Free float and late dates are disclosed in ADR 0013; the `critical` flag is not. |
| R9-F8 | Low (conditional) | EXECUTE on `pg_try_advisory_xact_lock(bigint)` granted directly to the tenant login, rather than to PUBLIC or `serk_app`, let it take the relay lock 727002. `serk_database_posture()` stayed `[]`. |
| R9-I1 | Info | Progress approval order. A 10-16 report (D 60%) was approved after the 10-17 report (D 50%), and an actual start of 2026-09-01 (before the schedule start of 2026-10-05) was accepted. |
| R9-I2 | Info | Designation. Accepted on a DRAFT PO. The attestation binds `purchase_order/<id>` with ctx `DESIGNATE`, not the line or the item. One buyer designated a "Reinforcement steel" line as CU-WIRE-16. A missing line returns "concurrent modification". |
| R9-I3 | Info | Variations. The tenant role added a NEW line (rate 9,999,999) to a commercial manager's DRAFT; it became part of the submitted value 10,653,499. Any commercial manager can cancel a SUBMITTED variation. Rounding happens per variation: 4 × +0.0001 m3 @ 350 gives a revised value of 23,060,000.16, against 23,060,000.14 from effective quantity × rate. |
| R9-I4 | Info | Abuse limits under load. 6,000 concurrent auth failures across 20 limiters on a 4-connection pool caused 3,474–3,938 store timeouts (p50 250–251 ms). Shared calls run before the `MaxInFlight` semaphore. The number allowed stayed 5 in 4 saved runs, and was 6 in one unsaved run. With block < window, the first event after the block re-blocks. |

---

### R9-F1 (Medium): EV reads only the newest progress report

**Evidence** (`TestR9_ScheduleProgressAndRaw`; textbook network A 1,000,000, B 2,000,000, C 500,000, D 3,000,000):
```
EV at 10-14 (full report) 3850000; EV at 10-15 after a report listing only D at 40%: 1200000 (hand, latest known percent per activity: 4450000)
OPEN: a later progress report that lists only D drops EV from 3850000 to 1200000: A, B (100%) and C (50%) count as 0; SPI 0.8191 -> 0.2264
```

**Cause.**
- `schedule_evm` takes `pd := max(status_date)` of approved reports (0027:371). It then joins only the lines of that one report (0027:378–382: `LEFT JOIN schedule_progress p ... AND p.status_date = pd`). An activity missing from it gets `COALESCE(l.percent_complete, 0)`.
- `RecordProgress` accepts any non-empty subset of activities (`kernel/schedule.go:220–227`).
- The monotonic check on approval compares only the lines present (0027:301–306), so omission is never seen as "going backwards".

**Why it matters.**
- EV, SV and SPI are the reported schedule performance. A routine partial update, such as reporting only the activities that moved, collapses them.
- An approver who sees only the lines of the new report cannot tell this will happen.
- Equally, a selective report can be used to steer the indices.
- ADR 0013 §7 defines EV as "budget × the latest approved percent complete on or before the status date". Per activity, that is 4,450,000 here.

**Fix.** Choose one of these:
- Compute EV per activity from its latest approved line on or before the status date (`DISTINCT ON (activity_code) ... ORDER BY status_date DESC`).
- Or require a report to cover every baseline activity, both in SQL at approval and in Go.

Also extend the monotonic check to activities absent from the new report.

### R9-F2 (Medium): put-away releases the budget, so the gate no longer bounds purchasing

**Evidence** (`TestR9_BudgetAfterPutAway`; BOQ budget on 01-MAT 12,100,000; each PR is 55 t steel + 1 bag, estimated 4,730,960; each PO is 4,648,440):
```
held: with two POs open and nothing put away (committed 9296880, available 2803120) a third 4,730,960 PR is refused: kernel: approved budget exceeded ...
after receiving and putting away both POs (9296880): committed 0 actual 0 available 12100000
PR/PO 3 approved by the budget gate; after put-away: committed 0 actual 0 available 12100000; purchased so far 13945320 on a 12100000 budget
PR/PO 4 approved by the budget gate; after put-away: committed 0 actual 0 available 12100000; purchased so far 18593760 on a 12100000 budget
OPEN: 18593760 of stock bought on 01-MAT (budget 12100000) ... available is still 12100000
```

**Cause.**
- `p2p_cost_position` (0028:80–83) commits an inventory line at `greatest(0, commitment − p2p_put_away_value)`, and stock is charged only when issued.
- `DecidePR` (`p2p.go:623`) and `ApprovePO` (`p2p.go:884`) gate on this function, so every put-away restores the code's full budget.

**Why it matters.**
- The gate is the only automated purchasing limit per cost code. After put-away, a requester and approver can buy without bound on a code. That money is spent.
- The overrun appears only when stock is issued (actual), or never: see R9-F5.
- The ADR 0012 addendum discloses that "between put-away and issue the stock is in no project's budget". It does not state that the budget gate stops limiting purchases.

**Fix.**
- Keep inventory purchases bounded by something: count unissued stock bought on a code against that code until it is issued or transferred; or add an inventory/warehouse purchasing budget checked at PR and PO.
- Otherwise, record a named human acceptance that stock purchasing is outside the cost-code gate.

### R9-F3 (Medium): an unbounded EVM status date ties up the database

**Evidence** (`TestR9_ScheduleEVMCostNoHolidays`, `TestR9_ScheduleEVMCost`; caller is a site engineer scoped to the project):
```
info: EVM at 3000-01-01, no holidays: 649ms, PV 6500000 err <nil>
info: EVM at 9999-12-31, no holidays: 5.34s, PV 6500000 err <nil>
info: statement_timeout in the tenant transaction: "0"
info: EVM at status date 2100-01-01 with 3000 holidays (one GET by a project reader): 338ms, err <nil>
info: EVM at status date 9999-12-31 with 3000 holidays (one GET by a project reader): 30s, err timeout: context deadline exceeded
```

**Cause.**
- `projectEVM` parses any `YYYY-MM-DD` (`schedule_handlers.go:117–124`). `ScheduleEVM` checks only scope (`kernel/schedule.go:295–306`).
- `schedule_offset` runs `generate_series(start+1, d)` and calls `schedule_is_working` on every day (0027:138–142, 370). That call scans the `holidays` array linearly, so the cost is days × holidays. The planner controls the array size (up to the 1 MiB body).
- No statement timeout is set.

**Why it matters.**
- Any project reader can occupy a database backend for seconds to minutes per request, and repeat up to the per-principal budget (300/min by default).
- Pre-auth and principal limits do not bound per-request cost.

**Fix.**
- Bound `status_date` to [baseline start, today + a small horizon] in Go (422) and in `schedule_evm`.
- Compute the working-day count arithmetically (whole weeks, plus the holidays in the range).
- Cap the number of holidays.
- Set a `statement_timeout` on tenant transactions.

### R9-F4 (Low): PV omits the last working day on non-working status dates

**Evidence** (`TestR9_ScheduleEVMHand`). Mon–Fri calendar, start Mon 2026-10-05, holiday Wed 10-07. P(4) 400,000; Q(3) 300,000 with P→Q SS+2; R(2) 200,000 with Q→R FF+1. The stored dates match the hand values `P [0 4 0 4] Q [2 5 2 5] R [4 6 4 6]`.
```
held: PV at 2026-10-06 (Tue, 2 working days elapsed) = 200000
OPEN: PV at 2026-10-07 (Wed holiday, still 2 working days elapsed) is 100000, hand computation 200000
held: PV at 2026-10-09 (Fri, 4 elapsed: P 1, Q 2/3) = 600000
OPEN: PV at 2026-10-10 (Sat, still 4 elapsed) is 400000, hand computation 600000
OPEN: PV at 2026-10-11 (Sun, still 4 elapsed) is 400000, hand computation 600000
held: PV at 2026-10-12 (Mon, 5 elapsed: P 1, Q 1, R 1/2) = 800000
```

**Cause.** At 0027:370, `n := schedule_offset(v, d) + CASE WHEN schedule_is_working(v, d) AND d >= start THEN 1 ELSE 0 END`. `schedule_offset` excludes the start day, which the `+1` adds back, but only when `d` is a working day. The count of working days in [start, d] is `offset + 1` for any `d >= start`.

**Why it matters.**
- On every weekend or holiday status date, PV drops by one working day of every in-progress activity, so SPI is overstated.
- The handler defaults `status_date` to today, so weekend views are affected. Month-ends often fall on non-working days (2026-10-31 is a Saturday).
- The size is one day per in-progress activity, so it is small on long activities.

**Fix.** Use `n := CASE WHEN d >= start THEN schedule_offset(v, d) + 1 ELSE 0 END`. Add the non-working-day cases to the planning tests.

### R9-F5 (Low): a count shortage is charged to no cost code

**Evidence** (`TestR9_BudgetAfterPutAway`):
```
12 t shortage (1014000) approved and posted: journal 1200 CREDIT 1014000.000000 project=f25d9451 cost_code=-; 5200 DEBIT 1014000.000000 project=f25d9451 cost_code=-; 01-MAT available 12100000 -> 12100000
OPEN: a count shortage of 1014000 left every cost code's available budget unchanged ...
```

**Cause.** `stk_expected_lines` puts `NULL::uuid` as the cost code on both STK_ADJUST lines (0021:545–551), and `p2p_cost_position.actual_other` sums by cost code (0028:95–98).

**Why it matters.**
- With R9-F2, material bought on a code is released at put-away and written off by count, and no cost code ever bears it. Cost-code reports understate project cost by the loss.
- The GL and EVM AC (project-level EXPENSE) do include it.
- The approval needs storekeeper plus inventory controller, so this is a reporting gap rather than a bypass.
- The ADR 0012 addendum states the opposite.

**Fix.** Carry a cost code on counts (required for project warehouses) and put it on the variance line. Otherwise, correct the ADR and report unallocated write-offs per project.

### R9-F6 (Low): per-address limits do not aggregate IPv6

**Evidence** (`TestR9_AbuseClientKeys`, trusted proxy 127.0.0.1/32, `AuthFailuresPerMinute: 3`; `TestR9_AbuseSQL`):
```
held: through the trusted proxy, after 3 failures: IPv4 client -> 429, IPv6 client -> 429
60 invalid tokens from 60 addresses of 2001:db8:7:1::/64 (limit 3 per minute with lockout): 0 answered 429; a valid token from the same /64 -> 404; abuse_counters rows 100009 -> 100131
info: 100,000 distinct client keys (e.g. one IPv6 /64 rotated per request) in 2.245s: rows 3 -> 100003, abuse_counters 17 MB (~183 bytes per key); all 100000 allowed; rows are swept only after window_end + 1 hour
```

**Cause.**
- `authed` keys on `clientIP(...).String()` (`server.go:231`), which is the full /128.
- `sharedLimiter.digest` hashes it as-is (`abuse_shared.go:58–64`).
- `abuse_hit` inserts one row per key and sweeps only rows expired for over an hour, in about 1 call in 500 (0029:42–57).

**Why it matters.**
- An IPv6 client usually controls at least a /64, so the per-address budget and the lockout do not limit it.
- Each request also adds a row to an UNLOGGED table, kept at least an hour. At 1,000 req/s that is about 3.6 M rows/hour (about 660 MB at the measured 183 B/row).
- The ADR keeps edge limits as required, which bounds this, hence Low.

**Fix.** Key IPv6 clients by /64 (configurable), possibly with a second, coarser /48 budget. Bound the table: sweep by `window_end`/`blocked_until` on a timer, and cap rows per scope.

### R9-F7 (Low): a BASELINE can carry forged critical flags, free float and late dates

**Evidence** (`TestR9_ScheduleProgressAndRaw`):
```
activity C as computed: critical=f free_float=7 late_start=2026-10-16 late_finish=2026-10-17; raw updates: <nil> / <nil>
OPEN: a BASELINE was approved with forged computed columns the database does not verify: C critical=t ff=0 tf=7 late=2026-10-08..2026-10-09; D critical=f ff=30 tf=0 late=2027-03-01..2027-03-31
```

**Cause.**
- `schedule_assert_cpm` checks es/ef/ls/lf, total float and the early dates (0027:235–250). It does not check `critical`, `free_float`, `late_start` or `late_finish`.
- The tenant role may update those columns while DRAFT (0027:507, 265–268).

**Why it matters.**
- After the BASELINE is approved, the critical-path display can be false. Here truly critical D shows as non-critical with 30 days of free float.
- ADR 0013 discloses free float and late dates, but not the `critical` flag.

**Fix.**
- Verify `critical = (total_float = min(total_float) AND min <= 0)`, `late_start = schedule_date(ls)` when `ls >= 0`, `late_finish`, and the free-float equation.
- Or drop the stored columns and derive them in views.

### R9-F8 (Low, conditional): the posture check misses direct grants

**Evidence** (`TestR9_PostureFalseNegative`):
```
posture on the test database: []
with pg_catalog.pg_try_advisory_xact_lock(bigint) granted directly to tenant login serk_t_fe49e6cc...: posture []; lock 727002 taken: true <nil>
```

**Cause.**
- The advisory check uses `has_function_privilege('serk_app', p.oid, 'EXECUTE')` (0028:57–59). It covers PUBLIC and `serk_app`, but not grants made to a login.
- The TEMP and CREATE checks are already per login.

**Fix.** Evaluate the advisory check per `tenant_logins` row (`has_function_privilege(t.oid, p.oid, 'EXECUTE')`), as the other two checks do.

### R9-I1 (Info): progress approval order and actual dates

**Evidence:**
```
info: a 10-16 report (D 60%) was approved after the 10-17 report (D 50%): approved history now runs backwards in time; 'reported forward' is checked only at recording
info: progress d963c5ad with D actual start 2026-09-01 (schedule starts 2026-10-05) recorded
```

**Cause.** The forward check is at INSERT only (0027:287–289), and approval checks only percentages (0027:295–311). Consider re-checking at approval that no later report is approved, and refusing actual dates before the schedule start, or flagging them.

### R9-I2 (Info): designation

**Evidence** (`TestR9_Designation`):
```
info: the buyer alone designated PO line 1 'Reinforcement steel Grade 60' as CU-WIRE-16 (same unit and account); no second person
info: designation attestation: action po.line.designate subject purchase_order/8622f609 ctx DESIGNATE actor u-buyer (no line number or item in the attested decision)
info: designation accepted on a PO in status 0 (0 = DRAFT); the kernel and trigger do not check the PO status
held: designation of a line that does not exist refused: store: concurrent modification
```

**Cause.**
- `DesignatePOLineItem` (`stock.go:422–438`) and `po_lines_stock_item` (0028:109–121) do not check the PO status. The ADR says "an approved order".
- The attestation subject is the PO before the change, with ctx `DESIGNATE`. The audit event records the line and item, but the signed decision does not. The attestation is same-transaction and single-use, so this was not exploitable in the probes.
- The decision is made by one person.

Consider:
- requiring status APPROVED;
- putting `line:item` in the attestation ctx;
- mapping 0 rows to "not found".

### R9-I3 (Info): variations

**Evidence** (`TestR9_VariationRawSQLAndScope`):
```
info: the tenant role added a NEW line (rate 9,999,999) to commercial manager's DRAFT variation 3f3d03cc; lines are not bound to the variation's creator until submission
submitted variation value_change 10653499 (100 m3 x 6,500 + injected/CHANGE lines as stored)
info: a commercial manager who did not prepare the SUBMITTED variation cancelled it
info: 4 variations of +0.0001 m3 @ 350: variations approved 0.16; revised contract value 23060000.16; sum(effective qty x rate) 23060000.14
```

The maker's submit attestation and the CFO's MFA approval both hash the lines, so an injected line is seen by both. `CancelVariation` accepts any `contract.manage` holder (`variation.go:158–176`), as in R8-I2 before its fix.

### R9-I4 (Info): shared limiter under load, and lockout semantics

**Evidence** (`TestR9_AbuseFallbackUnderLoad`, `fallback-reruns.txt`, `TestR9_AbuseSQL`):
```
pool 4 conns, 20 replicas, 6000 concurrent auth failures from one client (limit 5 + lockout): allowed 5; shared-store errors/timeouts 3938; latency p50 251ms p99 267ms max 280ms
(reruns) allowed 5; errors 3690 / 3474 / 3714; p50 250-251ms
pool 4 conns, 10 replicas, 1000 concurrent ...: allowed 5; shared-store errors/timeouts 0; latency p50 61ms p99 97ms
info: 64 connections x 20 abuse_hit on one key: p50 3ms p99 123ms max 180ms
info: limit 3 window 4s block 1s: [true true true]; 1.2s later (block over, window open): [false]
```

In one development run (console output only, not in a saved file) the same 6,000-call case printed `allowed 6; shared-store errors/timeouts 3720` (`OPEN: 6 auth failures allowed against a shared limit of 5`).

**Cause and observations.**
- The 250 ms fallback (`abuse_shared.go:66–77`) can be reached by request concurrency alone: `authed` calls `blocked` and `hit` before the in-flight semaphore (`server.go:231–251`).
- In practice the local limiters kept the total at or near the limit, which is the documented bounded fallback. The cost is that each pre-auth request waits up to 250 ms twice while `SerkAbuseLimitsDegraded` fires.
- With 40 calls over 4 replicas and no timeouts, only 2 were allowed (`allowed 2`). A call must fall within both the shared count and its own replica's local count, so the limit was applied more strictly than configured; nothing was over-admitted.
- When the block is shorter than the window, the first event after the block re-blocks. This happens only with configurations where the block is shorter than the window; with the default 5 min block and 1 min window it does not arise.

---

## Held (with executed evidence)

**Variations (0026).**

`TestR9_VariationRaces`:
- Three rounds of a −90 reduction (120 → 30) raced a verification of +15 (20 → 35) on line 3. In every round exactly one succeeded: `the variation leaves 30.0000 but 35.0000 is already verified`, with verified 35 ≤ effective 120.
- Two concurrent −60 reductions with 20 verified: one was refused (`leaves 0.0000 but 20.0000 is already verified`); effective 60 ≥ verified 20.
- Two concurrent drafts with NEW line 7: the second was refused (`already used on the contract or a live variation`).

Raw SQL as the tenant role (`TestR9_VariationRawSQLAndScope`):

| Attempt | Result |
|---|---|
| UPDATE `value_change` | permission denied |
| UPDATE a line's rate | permission denied |
| DELETE a line | permission denied |
| INSERT a variation | `contract.variation.create ... requires a verified approval attestation` |
| CHANGE line with forged rate 1 | re-priced to the contract rate 350 |
| raw submit | attestation required |
| raw approve | attestation required |
| `decision_reason` change without a transition | refused |
| UPDATE `credit_date` / `release_date` (0028 date trigger) | not updatable by the tenant role |

Scope and decisions:
- A variation on a DRAFT contract was refused.
- Another project's CFO got `not found` on the detail, 0 list rows, and `not found` on approval.
- A service principal was refused (`reserved to human principals`).
- A commercial manager without `contract.approve` was refused.

**Planning (0027)** (`TestR9_ScheduleEVMHand`, `TestR9_ScheduleProgressAndRaw`):
- The CPM dates for SS/FF links with lags and a holiday matched the hand computation, and PV on working-day status dates matched it exactly.
- On a BASELINE: activity updates, link inserts and deletes were refused. `holidays` was not updatable, `finish_offset` was refused, and a raw BASELINE insert was refused.
- A raw cycle (E→A) in a DRAFT was refused at submission. On a 300-activity chain with a 2-cycle the check took 31 ms.
- Two SUBMITTED versions approved concurrently left exactly 1 BASELINE.
- Another project's PM got `not found` on the detail and 0 list rows. That PM's EVM and that project's planner's progress report were `forbidden`.

**0028** (`TestR9_Designation`, `TestR9_BudgetAfterPutAway`):
- Designation refused an item of another legal entity, another project's buyer and a non-existent line.
- The PR budget gate refused a PR while open, un-put-away POs filled the budget (the control case of R9-F2).
- On a hardened test database, `serk_database_posture()` returned `[]`, so R8-F2 is no longer reproduced.

**0029** (`TestR9_AbuseSQL`, `TestR9_AbuseClientKeys`, `TestR9_AbuseFallbackUnderLoad`):
- The abuse login:
  - holds no table, view or sequence privilege outside the system catalogs;
  - can execute no SECURITY DEFINER function in `public` other than `abuse_hit` and `abuse_blocked`;
  - can execute nothing in `public` except those two and the PUBLIC defaults of the pgcrypto and btree_gist extensions;
  - is refused on TEMP, `pg_try_advisory_xact_lock` and `current_tenant()`. It can read `pg_catalog.pg_roles` (PostgreSQL default).
- Lockout with limit 3, window 2 s, block 3 s gave `[true true true false false]`, then `[true]` after 3.2 s. A rate limit of 2 per 1 s gave `[true true false]`, then `[true]`.
- `scope` (regex, ≤ 32 characters) and key (exactly 32 bytes) keep each row bounded.
- Without trusted proxies, a rotating `X-Forwarded-For` was ignored (429). IPv4 and IPv4-mapped forms canonicalise to one key.
- Up to 1,000 concurrent calls on a 4-connection pool gave 0 timeouts (p99 ≤ 97 ms) and exactly 5 allowed.

## Not tested

- HTTP-level behaviour of the variation and planning routes, other than the `status_date` parsing reviewed in code. The kernel was probed directly.
- Interplay of variations with credit notes, retention release and advance recovery, and IPCs after an approved reduction (the existing `TestJourneyB_Variation` covers one case).
- Designation on CLOSED or CANCELLED POs: no kernel path produces those states, and the trigger was reviewed only in code.
- EVM AC correctness (only `statement_timeout` and PV/EV were probed). Constant-price EVM is not built.
- A cluster where `deploy/02` was not applied. There the abuse login would inherit PUBLIC's TEMP and advisory-lock rights, and the posture check does not examine `serk_abuse` logins.
- A real reverse proxy (Caddy) forwarding IPv6. Load beyond a single host, and database CPU saturation by concurrent EVM requests (single requests were timed).
- Multi-entity tenants beyond the one foreign-entity item; browser UI.

## Files

All in `$SP/review9/`:
- `REVIEW_9.md` (this report)
- `probe-output.txt`, `fallback-reruns.txt`, `kernel-run1.txt`, `run2.txt`
- `full-suite.txt`
- `zz_review9_kernel_test.go`, `zz_review9_httpapi_test.go`

To re-run the probes, copy the two probe files back as `internal/kernel/zz_review9_test.go` and `internal/httpapi/zz_review9_test.go`.

---

## Resolution (delivering team, 2026-10-22): migration 0030 and kernel changes

The delivering team, not the reviewer, wrote these fixes. They are **AI-verified with executed tests and have not been independently re-reviewed**. The probes are kept as regression tests in `internal/kernel/review9_regression_test.go` and `internal/httpapi/review9_regression_test.go`. Where a fix changed a probe's premise, the probe now asserts the fixed behaviour:
- forged schedules no longer reach a baseline;
- 3,000 holidays are refused;
- the third purchase is refused;
- the load probe distinguishes a healthy store from the documented fallback.

| ID | Resolution | Proof after the fix |
|---|---|---|
| R9-F1 | EV is now taken per activity, from its latest approved report. | `TestR9_ScheduleEVMHand` PASS: the database matches the hand computation. |
| R9-F2 | Put-away releases nothing. An issue to the ordering code relieves the commitment, capped at what that code's own orders put away. | `held: cycle 3 PR refused by the budget gate after put-away: … available 2803120.000000 (budget 12100000 …, committed 9296880 …)` |
| R9-F3 | The status date is limited to the schedule horizon (the API returns 422), a version takes at most 400 holidays, and a 5 s statement timeout applies. | With 400 holidays, EVM ran in 4 ms at 2026-10-14 and 12 ms at 2036-01-01. At 2100-01-01 and 9999-12-31 it was refused in 1 ms. 3,000 holidays were refused at creation. |
| R9-F4 | The start day counts once the status date has reached it. | `TestR9_ScheduleEVMHand` PASS |
| R9-F5 | Lost stock stays inside the ordering code's commitment. | `held: the 8281000 shortage stays charged to 01-MAT through its commitment` |
| R9-F6 | IPv6 clients are counted per /64. | `60 invalid tokens from 60 addresses of 2001:db8:7:1::/64 …: 60 answered 429; a valid token from the same /64 -> 429` |
| R9-F7 | Free float, the critical flag and the late dates are re-checked by the database. | `held: submission with forged critical/free float/late dates refused: … activity C does not satisfy the critical path equations` |
| R9-F8 | Advisory-lock grants are checked for each tenant login. | `TestR9_PostureFalseNegative` PASS |
| R9-I1 | Progress reports are approved in status-date order, and an actual start before the schedule start is refused. | `TestR9_ScheduleProgressAndRaw` PASS |
| R9-I2 | Designation now requires an APPROVED order and a procurement approver who did not raise it. The attestation names the line and the item, and a missing line returns 404. The console and browser Journey C use the procurement manager, and the buyer is refused. | `TestR9_Designation`, `TestR7_PutAwayItemIdentityAndAI`, `TestConsoleBrowserJourneyC` PASS |
| R9-I3 | Variation lines can only be added in the variation's own transaction. Cancellation is limited to the preparer or an approver. Per-variation rounding is kept. | `TestR9_VariationRawSQLAndScope`, `TestJourneyB_Variation` PASS |
| R9-I4 | **Open.** Under thousands of concurrent calls the replicas fall back to their local limits, as designed. The cap is the number of replicas × the limit. | Registered OPEN; needs a load test on staging. |

**The budget rule was changed again: residual JC-BUDGET-ORIGIN (open).**
- Stock bought on one code and issued to another is charged to both.
- This is conservative: purchases are refused, and an overspend is never allowed.
- The CFO budget override, with a recorded reason, is the interim relief. ADR 0012 addendum.

**Executed evidence.** Full race suite on fresh database `serk_full30b`: 308 PASS, 0 FAIL, 0 SKIP. This includes the 12 `TestR9_*` tests and the four browser journeys. Log: `docs/testing/evidence/full-suite-review9-fixes-fresh-db.txt`.
- An earlier run on `serk_full30` had 2 failures, and both were fixed before the run above:
  - the horizon error returned 409 instead of 422;
  - the load probe counted the documented fallback as a defect.

**Not done.**
- An independent re-review of 0030.
- The items under "Not tested" above.
