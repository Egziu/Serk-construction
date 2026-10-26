# Platform 0038 — evidence (2026-10-26)

Test environment work; synthetic data; production remains NOT READY.

## What was built
See `docs/architecture/MODULES.md` (Platform row) and the commit
"Platform 0038". In short: company portals (tenant settings and branding),
server-side notifications, customer-configurable automation rules (notify
only, maker/checker), a deterministic intelligence layer (risk assessment,
EAC/ETC/VAC, cash outlook, control review, assistant with sources), export
budget + watermark + access events, a second synthetic company (Senselet
Construction PLC) in staging.

## Tests executed
- Full race suite, Go 1.26.10 / PostgreSQL 16, fresh database `serk_full40`:
  **378 PASS, 0 FAIL, 0 SKIP** (`evidence/full-suite-platform-0038-fresh-db.txt`).
- New: `pkg/automation` (catalogue accepted, 11 forbidden bodies refused,
  dedupe keys); `TestPlatform_RulesLifecycleAndWorker` (maker/checker at
  kernel and database, frozen body, notify-only worker leaves the document
  SUBMITTED, idempotent runs, resolution after a human decides, role and
  project scoping, tenant isolation); `TestPlatform_TenantSettings`;
  `TestPlatform_ExportBudget` (refusal committed with event, notification and
  audit); `TestPlatform_IntelligenceAndAssistant` (unknown with missing data,
  scope refusals, deterministic answers, phrasing guard rejects invented
  numbers, EAC/ETC/VAC worked example); `TestAPIPlatform` (routes, 429 export
  budget, letterhead from settings, unknown-field refusal on /assistant/ask);
  `TestStagingLoginCompanies`; `TestAIPhraserAdapter` (fake endpoint).
- Local staging simulation: migration 0038 applied to the existing database;
  the first company received settings and 8 rules on upgrade; the second
  company seeded; the worker ran 16 rules and recorded 4 snapshots.
- Browser (Chromium): company picker, Senselet branding, Ask (cash, budget),
  Risks (portfolio and project), Control review, Company settings, Automation
  (proposed by the process owner, activated by the workflow admin), security
  bell, night theme. No page errors.

## Not verified / open
- No live language-model endpoint is reachable from the build environment;
  the adapter is tested against a fake only. The assistant runs
  deterministically unless `SERK_AI_ENDPOINT` is set.
- Risk thresholds (SPI/CPI 0.95/0.85, budget 85%/100%) are engineering
  defaults, not calibrated on outcomes; snapshots exist so they can be.
- See `docs/BACKLOG.md` for every missing module.
