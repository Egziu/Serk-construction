#!/usr/bin/env python3
"""Generates the baseline inventory, the domain dependency map and the feature
evidence matrix from the repository itself and from the latest saved test logs.

Facts (tables, migrations, routes, console screens, permissions, roles, tests
and their latest results) are parsed from source and logs; only the status
judgement and the gaps of each domain are written by hand, in DOMAINS below.
A domain is "implemented" only when it has schema, rules, API, authorization,
UI and passing integration tests; anything less is "partial" or "absent".

Usage: python3 tools/inventory.py   (writes the three files, prints a summary)
"""
import csv, glob, os, re, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rd = lambda p: open(os.path.join(ROOT, p), encoding="utf-8").read()
commit = subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"], text=True).strip()

# ---------------------------------------------------------------- facts
migrations = sorted(os.path.basename(p) for p in glob.glob(os.path.join(ROOT, "internal/store/postgres/migrations/*.sql")))
tables = {}  # table -> migration that created it
for m in migrations:
    for t in re.findall(r"CREATE TABLE (?:IF NOT EXISTS )?([a-z_]+)", rd("internal/store/postgres/migrations/" + m)):
        tables.setdefault(t, m)
routes = []  # (method, path, file)
for f in sorted(glob.glob(os.path.join(ROOT, "internal/httpapi/*.go"))):
    if f.endswith("_test.go"):
        continue
    for meth, path in re.findall(r'Handle\("(GET|POST|PUT|PATCH|DELETE) (/[^"]*)"', open(f).read()):
        routes.append((meth, path, os.path.basename(f)))
app = rd("internal/webui/static/app.js")
screens = sorted(set(re.findall(r"\['(#/[a-z_/]+)', '([^']+)'", app)))
auth = rd("pkg/auth/auth.go")
perms = dict(re.findall(r'(Perm\w+)\s+Permission = "([a-z_.]+)"', auth))
roles = {}
for name, body in re.findall(r'"([a-z_]+)":\s*\{Name: "[a-z_]+", Permissions: \[\]Permission\{([^}]*)\}', auth):
    roles[name] = sorted(perms.get(p.strip(), p.strip()) for p in body.replace("\n", " ").split(",") if p.strip())
tests = {}  # name -> file
for f in sorted(glob.glob(os.path.join(ROOT, "**/*_test.go"), recursive=True)):
    for t in re.findall(r"^func (Test\w+)\(t \*testing\.T\)", open(f).read(), re.M):
        tests[t] = os.path.relpath(f, ROOT)
LOGS = ["docs/testing/evidence/full-suite-journey-c.txt", "docs/testing/evidence/full-suite-credit-notes.txt", "docs/testing/evidence/full-suite-retention-release.txt", "docs/testing/evidence/full-suite-review7-fixes.txt", "docs/testing/evidence/full-suite-stock-transfers.txt", "docs/testing/evidence/full-suite-variations-fresh-db.txt", "docs/testing/evidence/full-suite-planning-fresh-db.txt", "docs/testing/evidence/full-suite-review8-fixes-fresh-db.txt", "docs/testing/evidence/full-suite-abuse-fresh-db.txt"]
results = {}
for lg in LOGS:  # later logs override earlier ones
    if os.path.exists(os.path.join(ROOT, lg)):
        for st, name in re.findall(r"^--- (PASS|FAIL|SKIP): (Test\w+)", rd(lg), re.M):
            results[name] = st
journal_types = sorted(set(re.findall(r"'((?:P2P|AR)_[A-Z]+)'", "".join(rd("internal/store/postgres/migrations/" + m) for m in migrations))))

# ---------------------------------------------------------------- judgements
# status: implemented | partial | absent. tables/routes/screens/tests are regexes over the facts above.
DOMAINS = [
 dict(name="Ledger, periods and audit", status="implemented", tables=r"^(journals|journal_lines|accounts|fiscal_period|audit_log|outbox|legal_entities|tenants|projects)",
      routes=r"^/v1/(journals|periods)", screens=r"#/(journals|recon)", perms=r"^(journal|period|account)\.", postings="Every subledger posts through DRAFT journals approved and posted by finance",
      tests=r"^Test(SC|Ledger|Kernel|Gate|Period|Journal|Privilege|Tenan|Adversar)", gaps="No manual journal entry or reversal screens; no financial statements; no consolidation"),
 dict(name="Approval attestations and SoD", status="implemented", infra=True, tables=r"^approval_(attestations|keys)", routes=r"^$", screens=r"^$", perms=r"^principal\.",
      postings="-", tests=r"^Test(Attestation|ApprovalProvenance|Independent|R3_|R4_|R5_|GovernedAI)", gaps="Signing key held by the API process (R-SIGNER): needs an isolated signer/HSM"),
 dict(name="Identity, sessions and MFA", status="partial", tables=r"^(revoked|session)", routes=r"^/v1/(identity|sessions|auth)", screens=r"^$", perms=r"^scope\.",
      postings="-", tests=r"^Test(Session|Token|OIDC|Oidc|Revoc)", gaps="OIDC verifier code exists but has never run against a real identity provider; step-up comes from token claims (R-MFA-SOURCE)"),
 dict(name="FX rates and conversion", status="partial", tables=r"^fx_", routes=r"^/v1/fx", screens=r"^$", perms=r"^fx\.", postings="Conversion only",
      tests=r"^Test(FX|Fx|APIFX)", gaps="No console screens for FX"),
 dict(name="Workflow engine", status="partial", tables=r"^workflow_", routes=r"^/v1/workflow", screens=r"^$", perms=r"^workflow\.", postings="-",
      tests=r"^Test(Workflow|APIWorkflow)", gaps="API only: no console screens for definitions, instances or tasks"),
 dict(name="WBS and cost codes", status="partial", tables=r"^(wbs_|cost_codes)", routes=r"cost-codes", screens=r"#/cost", perms=r"^wbs\.", postings="Cost codes on journal lines",
      tests=r"^Test(CostCode|Gate.*Cost|WBS)", gaps="No HTTP API or screens to maintain the WBS (seeded via kernel in tests)"),
 dict(name="BOQ and budgets", status="implemented", tables=r"^boq_", routes=r"^/v1/boqs", screens=r"#/list/boq", perms=r"^boq\.", postings="Budget only (no posting)",
      tests=r"^Test(JourneyA|APIJourneyA|ConsoleBrowserJourneyA)", gaps="No BOQ import; no revisions workflow beyond supersede"),
 dict(name="Procurement (PR, RFQ, quotes, PO)", status="implemented", tables=r"^(purchase_|pr_lines|rfq|po_lines|suppliers|p2p_policies|p2p_counters)",
      routes=r"^/v1/(requisitions|rfqs|quotes|purchase-orders|suppliers|p2p/policies)", screens=r"#/list/(purchase|rfq|supplier$)", perms=r"^(pr|rfq|po|supplier|p2p\.policy)\.",
      postings="-", tests=r"^Test(JourneyA|APIJourneyA|ConsoleBrowserJourneyA|R3_|R4_)", gaps="No framework agreements, no supplier portal"),
 dict(name="Goods receipt", status="implemented", tables=r"^grn", routes=r"^/v1/goods-receipts", screens=r"#/list/grn", perms=r"^grn\.", postings="P2P_GRN: Dr expense/inventory, Cr GRNI",
      tests=r"^Test(JourneyA|R3_)", gaps="Receipts post to expense; no stock ledger (see Inventory)"),
 dict(name="Accounts payable and three-way match", status="implemented", tables=r"^(supplier_invoices|invoice_lines)", routes=r"^/v1/invoices", screens=r"#/list/supplier_invoice",
      perms=r"^ap\.", postings="P2P_INVOICE: Dr GRNI, VAT input, PPV; Cr AP", tests=r"^Test(JourneyA|R3_|R4_)", gaps="No withholding tax; no credit notes"),
 dict(name="Payments and treasury", status="implemented", tables=r"^(payment_|company_bank|supplier_bank)", routes=r"^/v1/(payments|company-bank|supplier-bank)|reveal-bank",
      screens=r"#/list/(payment|company_bank|supplier_bank)", perms=r"^(payment|bankacct|bank\.details|supplier\.bank)", postings="P2P_PAYMENT: Dr AP, Cr payments in transit",
      tests=r"^Test(JourneyA|SupplierExposure|IA04001|R5_|APIIA)", gaps="Instructions only: no bank payment file/API; bank numbers readable by the runtime credential (R-BANK-AT-REST)"),
 dict(name="Bank statements and reconciliation", status="partial", tables=r"^bank_statement", routes=r"^/v1/bank-statements|reconciliation", screens=r"#/(bank|recon)",
      perms=r"^bank\.(import|reconcile)", postings="P2P_SETTLEMENT: Dr payments in transit, Cr bank", tests=r"^Test(JourneyA|StatementParse|R3_|R4_)",
      gaps="Statement authenticity depends on how the file is obtained: no bank-signed feed (R-BANKFEED)"),
 dict(name="Contracts and measurements (Journey B)", status="implemented", tables=r"^(customers|contract_|contracts|measurement|variation_)", routes=r"^/v1/(customers|contract|measurements|variations)",
      screens=r"#/list/(contract|measurement|customer$|contract_variation)", perms=r"^(customer|contract|measure)\.", postings="-",
      tests=r"^Test(JourneyB|APIJourneyB|ConsoleBrowserJourneyB|GovernedAI)", gaps="No claims, daywork or extension-of-time records; no retention bonds"),
 dict(name="IPC, AR invoicing and receipts (Journey B)", status="implemented", tables=r"^(ipcs|customer_invoices|customer_receipts|receipt_allocations|customer_credit_notes|retention_releases)",
      routes=r"^/v1/(ipcs|customer-invoices|receipts|credit-notes|retention-releases)|ar-reconciliation|position", screens=r"#/list/(ipc|customer_invoice|customer_receipt|customer_credit_note|retention_release|money_in)",
      perms=r"^(ipc|ar)\.", postings="AR_INVOICE: Dr AR, retention, advances; Cr revenue, VAT output. AR_RECEIPT: Dr bank; Cr AR, advances. AR_CREDIT: Dr revenue, VAT output; Cr AR. AR_RETENTION: Dr AR; Cr retention",
      tests=r"^Test(JourneyB|APIJourneyB|ConsoleBrowserJourneyB)", gaps="No invoice cancellation, dunning, customer statements, FX contracts, withholding on receipts; credit-vs-measurement double deduction is procedural (JB-CREDIT-QTY)"),
 dict(name="Project cost and profitability reporting", status="partial", tables=r"^$", routes=r"cost-report|profitability", screens=r"#/cost", perms=r"^$",
      postings="Reads posted journals", tests=r"^Test(JourneyA|JourneyB)", gaps="No EVM wiring (pkg/evm is a library only), no forecasts or cost-to-complete"),
 dict(name="Inventory and stock valuation (FIFO/WAC)", status="implemented", tables=r"^(stock_|warehouses)", routes=r"^/v1/(stock|warehouses)|put-away|stock-",
      screens=r"#/(stock|list/stock|list/warehouse)", perms=r"^(stock|warehouse)\.", postings="STK_ISSUE: Dr project cost, Cr inventory. STK_ADJUST: inventory vs variance. Transfers: no journal (same account)",
      tests=r"^Test(JourneyC|APIJourneyC|ConsoleBrowserJourneyC|R7_)", gaps="No supplier returns, landed costs, in-transit stock, serial/lot tracking; invoice variance not revalued into stock (JC-INVOICE-REVALUE)"),
 dict(name="Planning, CPM and EVM", status="partial", tables=r"^schedule_", routes=r"^/v1/(schedules|progress)|/schedules$|/progress$|/evm$",
      screens=r"#/(list/schedule|evm)", perms=r"^schedule\.", postings="- (AC read from posted journals)",
      tests=r"^Test(CPM|Calendar|ScheduleBaseline|APISchedule|ConsoleBrowserPlanning)",
      gaps="No resource levelling, calendars per activity, progress-based forecast dates, or price-index (constant-basis) EVM wiring; AC is all posted project expense"),
 dict(name="Variations and claims", status="partial", tables=r"^(contract_variations|variation_lines|claim)", routes=r"^/v1/(variations|claims)|/variations$",
      screens=r"#/list/contract_variation", perms=r"^contract\.(manage|approve)", postings="- (revenue follows certification)",
      tests=r"^Test(JourneyB_Variation|APIJourneyB|ConsoleBrowserJourneyB)", gaps="Variations built (0026); claims, daywork and extension-of-time records not started"),
 dict(name="Site operations and offline capture", status="absent", tables=r"^(site_|diary|offline)", routes=r"^/v1/(site|sync)", screens=r"^#/site", perms=r"^site\.", postings="-",
      tests=r"^Test(Offline|Sync)", gaps="Not started"),
 dict(name="Equipment", status="absent", tables=r"^equipment", routes=r"^/v1/equipment", screens=r"^#/equipment", perms=r"^equipment\.", postings="-", tests=r"^TestEquipment", gaps="Not started"),
 dict(name="HR and payroll", status="absent", tables=r"^(employee|payroll)", routes=r"^/v1/(employees|payroll)", screens=r"^#/payroll", perms=r"^payroll\.", postings="-",
      tests=r"^TestPayroll", gaps="Not started; payroll rules need jurisdictional professional review"),
 dict(name="Quality, health, safety and environment", status="absent", tables=r"^(inspection|incident|ncr)", routes=r"^/v1/(inspections|incidents)", screens=r"^#/qhse",
      perms=r"^qhse\.", postings="-", tests=r"^TestQHSE", gaps="Not started"),
 dict(name="Document and drawing control", status="absent", tables=r"^(document|drawing|transmittal)", routes=r"^/v1/(documents|drawings)", screens=r"^#/documents",
      perms=r"^document\.", postings="-", tests=r"^TestDocument", gaps="Not started (certificate files are hashed, not stored)"),
 dict(name="BIM / IFC", status="absent", tables=r"^(ifc|bim)", routes=r"^/v1/(bim|ifc)", screens=r"^#/bim", perms=r"^bim\.", postings="-", tests=r"^Test(BIM|IFC)", gaps="Not started"),
 dict(name="Multi-entity finance and consolidation", status="partial", tables=r"^legal_entities", routes=r"^/v1/entities", screens=r"^$", perms=r"^$", postings="Per entity",
      tests=r"^Test(Gate.*Tenan|R3_11)", gaps="Entities and tenants are isolated; no intercompany, eliminations or consolidation"),
 dict(name="Analytics and executive reporting", status="absent", tables=r"^$", routes=r"^/v1/(analytics|dashboards)", screens=r"^#/analytics", perms=r"^analytics\.", postings="-",
      tests=r"^TestAnalytics", gaps="Only operational reports (reconciliation, cost, position, profitability)"),
 dict(name="Tax and localization", status="partial", tables=r"^tax_", routes=r"^/v1/tax", screens=r"^$", perms=r"^tax\.", postings="VAT rates are policy data",
      tests=r"^TestTax", gaps="pkg/tax engine not wired; VAT is a policy field; no i18n; every rate needs tax-professional sign-off"),
 dict(name="Governed AI", status="partial", tables=r"^$", routes=r"^/v1/ai", screens=r"^#/ai", perms=r"^$", postings="None (draft-only by rule)",
      tests=r"^TestGovernedAI|R4_08", gaps="Only the control exists (0019: AI and service principals draft-only); no AI features built"),
 dict(name="Events, outbox and webhooks", status="implemented", infra=True, tables=r"^(outbox|relay|webhook)", routes=r"^$", screens=r"^$", perms=r"^$", postings="-",
      tests=r"^Test(Relay|Webhook)", gaps="No production consumer configured"),
 dict(name="Observability and operations", status="partial", tables=r"^$", routes=r"^/(metrics|healthz|readyz)", screens=r"^$", perms=r"^$", postings="-",
      tests=r"^Test(AlertDrill|Metrics|Obs)", gaps="No live OTel collector, alert routing or staging (GATEA-08/11 blocked)"),
]

def pick(rx, items):
    return [x for x in items if re.search(rx, x)] if rx not in ("^$", "") else []

rows = []
for d in DOMAINS:
    t = pick(d["tables"], sorted(tables))
    r = [f"{m} {p}" for m, p, _ in routes if d["routes"] not in ("^$", "") and re.search(d["routes"], p)]
    s = [f"{h} ({l})" for h, l in screens if d["screens"] not in ("^$", "") and re.search(d["screens"], h)]
    pv = sorted(v for v in perms.values() if d["perms"] not in ("^$", "") and re.search(d["perms"], v))
    ro = sorted(n for n, ps in roles.items() if set(ps) & set(pv))
    ts = pick(d["tests"], sorted(tests))
    res = {k: sum(1 for x in ts if results.get(x) == k) for k in ("PASS", "FAIL", "SKIP")}
    res["not in logs"] = sum(1 for x in ts if x not in results)
    rows.append(dict(d, t=t, r=r, s=s, pv=pv, ro=ro, ts=ts, res=res))
    if d["status"] == "implemented" and (not ts or res["PASS"] == 0 or res["FAIL"]):
        raise SystemExit(f"{d['name']}: marked implemented without passing tests in the logs")
    if d["status"] == "implemented" and not d.get("infra") and not (r and s):
        raise SystemExit(f"{d['name']}: marked implemented without both API routes and console screens")
    if d["status"] == "absent" and (t or r):
        raise SystemExit(f"{d['name']}: marked absent but has tables/routes {t[:3]} {r[:3]}")

hdr = f"Generated by `tools/inventory.py` at commit `{commit}` from source and the saved test logs ({', '.join('`'+l+'`' for l in LOGS)}). Do not edit by hand."

# ---------------------------------------------------------------- V040_INVENTORY.md
out = ["# SERK Construction: implementation inventory (v0.4 line)", "", hdr, "",
       "This inventory describes what the code actually contains. A domain is **implemented** only with schema, rules, API, authorization, UI and passing PostgreSQL integration tests. Pure infrastructure (attestations, outbox) is exempt from the UI requirement. The generator refuses to mark a domain implemented without passing tests, routes and screens, or absent while it has tables or routes.",
       "",
       "**Implemented is not production-ready.** Production stays NO-GO (`docs/release/GO_NO_GO.md`).", "",
       "## Summary", "", "| Status | Domains |", "|---|---|"]
for st in ("implemented", "partial", "absent"):
    out.append(f"| {st} | {sum(1 for x in rows if x['status'] == st)} |")
out += ["", "## Domains", "", "| Domain | Status | Tables | Routes | Screens | Tests (latest logs: pass/fail/skip/not run) | Gaps |", "|---|---|---|---|---|---|---|"]
for x in rows:
    rs = x["res"]
    out.append(f"| {x['name']} | **{x['status']}** | {len(x['t'])} | {len(x['r'])} | {len(x['s'])} | {len(x['ts'])}: {rs['PASS']}/{rs['FAIL']}/{rs['SKIP']}/{rs['not in logs']} | {x['gaps']} |")
out += ["", f"## Migrations ({len(migrations)})", ""] + [f"- `{m}`" for m in migrations]
out += ["", f"## Tables ({len(tables)})", "", "| Table | Created by |", "|---|---|"] + [f"| `{t}` | `{m}` |" for t, m in sorted(tables.items())]
out += ["", f"## HTTP routes ({len(routes)})", "", "| Method | Path | File |", "|---|---|---|"] + [f"| {m} | `{p}` | {f} |" for m, p, f in routes]
out += ["", f"## Console screens ({len(screens)})", ""] + [f"- `{h}`: {l}" for h, l in screens]
out += ["", f"## Roles ({len(roles)})", "", "| Role | Permissions |", "|---|---|"] + [f"| `{n}` | {', '.join(ps)} |" for n, ps in sorted(roles.items())]
out += ["", f"## Reserved subledger journal source types", ""] + [f"- `{j}`" for j in journal_types]
out += ["", f"## Tests ({len(tests)} top-level functions)", "",
        "**Results in the latest logs**", "",
        "| Result | Count |", "|---|---|",
        f"| PASS | {sum(1 for t in tests if results.get(t) == 'PASS')} |",
        f"| FAIL | {sum(1 for t in tests if results.get(t) == 'FAIL')} |",
        f"| SKIP | {sum(1 for t in tests if results.get(t) == 'SKIP')} |",
        f"| not in the logs | {sum(1 for t in tests if t not in results)} |"]
missing = sorted(t for t in tests if t not in results)
if missing:
    out += ["", "**Not in the logs (written after the logged run, or skipped by package):**", ""] + [f"- `{t}`" for t in missing]
open(os.path.join(ROOT, "docs/baseline/V040_INVENTORY.md"), "w").write("\n".join(out) + "\n")

# ---------------------------------------------------------------- DOMAIN_DEPENDENCY_MAP.md
dm = ["# Domain dependency map", "", hdr, "",
      "For each domain:",
      "- the tables it owns;",
      "- the routes and screens that expose it;",
      "- the permissions and the roles that hold them;",
      "- its financial postings.",
      "",
      "Workflow dependencies (each step's precondition) follow the order of the journeys:",
      "- **Journey A:** BOQ → PR → RFQ → PO → GRN → invoice → payment → statement → reconciliation → GL.",
      "- **Journey B:** policy and customer → contract → measurement → IPC → customer invoice → receipt → GL.",
      "",
      "Every subledger posting is a DRAFT journal of a reserved source type. It is bound to its document and approved and posted by finance (ADR 0009, ADR 0011)."]
for x in rows:
    if x["status"] == "absent":
        continue
    dm += ["", f"## {x['name']} ({x['status']})", "",
           "- Tables: " + (", ".join(f"`{t}`" for t in x["t"]) or "none of its own"),
           "- Routes: " + (", ".join(f"`{r}`" for r in x["r"]) or "none"),
           "- Screens: " + (", ".join(x["s"]) or "none"),
           "- Permissions: " + (", ".join(f"`{p}`" for p in x["pv"]) or "none specific"),
           "- Roles: " + (", ".join(f"`{r}`" for r in x["ro"]) or "-"),
           "- Postings: " + x["postings"]]
dm += ["", "## Absent domains", "", "These have no tables, routes or screens yet: " + ", ".join(x["name"] for x in rows if x["status"] == "absent") + "."]
open(os.path.join(ROOT, "docs/baseline/DOMAIN_DEPENDENCY_MAP.md"), "w").write("\n".join(dm) + "\n")

# ---------------------------------------------------------------- FEATURE_EVIDENCE_MATRIX.csv
with open(os.path.join(ROOT, "docs/release/FEATURE_EVIDENCE_MATRIX.csv"), "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["domain", "status", "schema_tables", "api_routes", "ui_screens", "permissions", "tests_total", "tests_pass", "tests_fail", "tests_skip",
                "tests_not_in_logs", "postings", "gaps", "evidence_logs", "commit"])
    for x in rows:
        rs = x["res"]
        w.writerow([x["name"], x["status"], len(x["t"]), len(x["r"]), len(x["s"]), len(x["pv"]), len(x["ts"]), rs["PASS"], rs["FAIL"], rs["SKIP"], rs["not in logs"],
                    x["postings"], x["gaps"], "; ".join(LOGS), commit])
print(f"{len(rows)} domains: " + ", ".join(f"{st} {sum(1 for x in rows if x['status'] == st)}" for st in ("implemented", "partial", "absent")),
      f"| {len(tables)} tables, {len(routes)} routes, {len(screens)} screens, {len(tests)} tests ({sum(1 for t in tests if results.get(t) == 'PASS')} PASS in logs)")
