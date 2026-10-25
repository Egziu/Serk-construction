# Console redesign, exports, reports and notifications (2026-10-26)

Test environment work (synthetic data). Production remains NO-GO.

## Design

- Identity: forest green and cream. **Day** = green ink on cream paper; **night** = the exact reverse (cream ink on deep green). The top band reverses with it. Brass is a rare accent.
- Fonts are self-hosted (the CSP allows fonts from the same origin only): Fraunces for display, Manrope for text, IBM Plex Mono for references. All three are SIL OFL 1.1 (`internal/webui/static/fonts/LICENSES.txt`).
- Day/night switch in the top band. The choice is remembered per browser and defaults to the device setting.
- Contrast: every text/background pair in both themes is at least 4.5:1, computed with WCAG 2.2 relative luminance.
- On phones the menu folds behind one "Menu" button.

## Exports: PDF, Word (.docx) and Excel (.xlsx)

- Endpoint: `GET /v1/export?src=<read path>&format=pdf|docx|xlsx&title=…`.
- **Same authority as the screen.** The server re-issues `src` as an internal GET carrying the caller's own bearer token. It passes through authentication, revocation, rate limits, permissions, project scope and row-level security. A refused read is passed through unchanged (for example 403), so an export never contains more than the person may read.
- **What can be exported.** Only reads under an allow-list (`/v1/p2p/`, `/v1/journals`, `/v1/projects/`, `/v1/entities/`, `/v1/contracts/`, `/v1/reports/`, workflow, site devices). These are refused with 422: absolute URLs, `..`, the export endpoint itself, and anything else.
- **Letterhead.** The legal entity's registered name, or `SERK_COMPANY_NAME` if set, with "SERK Construction" under it. Every page carries "Generated <time> by <person>" and "Page n of N". DOCX and XLSX also record the company in their document properties.
- **Audit.** Each export is logged with tenant, person, source path, format and size.
- **No new dependencies.** The writers use the Go standard library only (`internal/export`).
- **PDF:**
  - A4 pages, turned landscape when a table is wide.
  - Tables wrap their text and repeat the header row on each page.
  - Ethiopic (Ge'ez) text embeds Noto Sans Ethiopic (OFL) as a CID font with a ToUnicode map, so the text stays searchable and copyable. The font is included only in documents that contain Ethiopic text.
- **Excel:**
  - A Summary sheet, plus one sheet per table.
  - Exact decimals are stored as numbers, with money formatted `#,##0.00`.
  - Header rows are frozen and have filters.
- **Word:** a header and footer with page fields, a repeated table header row, and landscape pages for wide tables.

## Reports (new)

All three reports are read-only and need tenant-wide scope, because they aggregate across projects.

| Report | Route | Permission | Basis |
|---|---|---|---|
| Trial balance | `/v1/reports/trial-balance?entity=&as_of=` | `journal.read` | Lines of POSTED/REVERSED journals dated up to `as_of`, the same basis as the reconciliations. Shows the balance check. |
| Payables aging | `/v1/reports/ap-aging` | `p2p.read` | Approved supplier invoices less payments RELEASED/SETTLED by `as_of`. Bucketed: not due, 1–30, 31–60, 61–90, over 90. |
| Receivables aging | `/v1/reports/ar-aging` | `p2p.read` | Approved customer invoices less CONFIRMED receipts and APPROVED credit notes by `as_of`. Same buckets. |

- Known limitation: aging totals add amounts across currencies. Each item shows its own currency.
- The Reports page gathers these with the existing reports: reconciliation, cost report, earned value, stock on hand and journals.

## Notifications

- A bell in the top band counts the items waiting for the person: the same queues as "My work", computed for their own permissions and scope. It refreshes every minute while the tab is visible.
- The drawer lists the queues and marks the ones that are new since they were last viewed.
- Desktop notifications are opt-in through the browser's permission prompt. They fire only when the count grows while the tab is in the background.
- Notifications only point people at work. **Nothing is approved automatically**: every decision stays a human, attested action checked by the database.
- The server-side timers (`SERK_SCHEDULER_DSN`: workflow SLA escalation and expiry) are unchanged.

## Evidence

- **`internal/export` tests:**
  - Decimal formatting, including half-up rounding carry (999.995 → 1,000.00).
  - JSON-to-document mapping, with internal ids and fields hidden.
  - PDF xref integrity, and the content containing the company, amounts and the page footer.
  - DOCX header and company property.
  - XLSX exact decimals, money style, frozen header and filter.
  - Safe file names.
  - Ethiopic font embedded only when needed.
- **`TestAPIReportsAndExports`:**
  - The trial balance balances, and the as-of date filters.
  - Aging reports return.
  - Project-scoped people get 403 on reports and on exports of them; anonymous export gets 401.
  - Six forbidden `src` values get 422, and an unknown format gets 422.
  - All three formats download with letterhead and file name.
- **Visual checks:**
  - Rendered exports: PDF via poppler; DOCX and XLSX via LibreOffice. Ethiopic text checked in PDF output.
  - Console screenshots in Chromium (Playwright): sign-in, home, bell, trial balance, list, document and aging pages in both themes and at phone width, with no page errors.
  - Five downloads through the console's export buttons.
