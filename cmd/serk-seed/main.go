// serk-seed provisions a synthetic demonstration tenant for a TEST
// environment (SERK_ENV=development or staging; refused otherwise). It is
// idempotent: when the tenant already has its legal entity it only reports
// the existing identifiers.
//
// Everything it creates is synthetic: names, tax ids and bank numbers are
// invented. Every approval goes through the kernel's maker/checker commands
// with distinct synthetic people, so the database verifies the same
// attestations it verifies for real users; nothing is written around them.
//
// Environment: SERK_ENV, SERK_ADMIN_DSN (schema owner), SERK_DB_BASE_DSN,
// SERK_TENANT_DB_SECRET, SERK_APPROVAL_SIGNING_KEY, SERK_BANK_DATA_KEY and
// SERK_BANK_DIGEST_KEY (optional; the company bank account is skipped
// without them), SERK_SEED_TENANT (uuid) and optionally SERK_SEED_TENANT_2
// (uuid) with SERK_SEED_TENANT_2_NAME. Writes KEY=value lines (tenant,
// project ids and the SERK_STAGING_COMPANIES list) to the file named by
// --out, for the staging sign-in.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/shopspring/decimal"

	"github.com/serk-group/serk-construction/internal/kernel"
	"github.com/serk-group/serk-construction/internal/store/postgres"
	"github.com/serk-group/serk-construction/pkg/attest"
	"github.com/serk-group/serk-construction/pkg/auth"
	"github.com/serk-group/serk-construction/pkg/datakey"
	"github.com/serk-group/serk-construction/pkg/ledger"
)

func fail(stage string, err error) {
	fmt.Fprintf(os.Stderr, "serk-seed: %s: %v\n", stage, err)
	os.Exit(1)
}

func dec(s string) decimal.Decimal { return decimal.RequireFromString(s) }

type project struct{ code, name, id string }

// company is one synthetic tenant to seed.
type company struct {
	tenant, name, shortCode, letterhead string
	projects                            []project
}

type seeded struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Projects []string `json:"projects"`
}

func main() {
	out := flag.String("out", "", "file to write SERK_STAGING_TENANT / SERK_STAGING_PROJECTS / SERK_STAGING_COMPANIES to")
	flag.Parse()
	env := os.Getenv("SERK_ENV")
	if env != "development" && env != "staging" {
		fmt.Fprintln(os.Stderr, "serk-seed creates synthetic data and runs only with SERK_ENV=development or staging")
		os.Exit(2)
	}
	adminDSN, baseDSN := os.Getenv("SERK_ADMIN_DSN"), os.Getenv("SERK_DB_BASE_DSN")
	sec, approval := os.Getenv("SERK_TENANT_DB_SECRET"), os.Getenv("SERK_APPROVAL_SIGNING_KEY")
	tenant := os.Getenv("SERK_SEED_TENANT")
	if adminDSN == "" || baseDSN == "" || tenant == "" || len(sec) < 32 || len(approval) < 32 || sec == approval {
		fmt.Fprintln(os.Stderr, "SERK_ADMIN_DSN, SERK_DB_BASE_DSN, SERK_SEED_TENANT, SERK_TENANT_DB_SECRET and a different SERK_APPROVAL_SIGNING_KEY (>= 32 bytes) are required")
		os.Exit(2)
	}
	companies := []company{{tenant: tenant, name: "SERK Demo Construction (synthetic)", shortCode: "serk-demo", letterhead: "SERK DEMO CONSTRUCTION PLC (synthetic)",
		projects: []project{{code: "P-001", name: "Mekelle Ring Road"}, {code: "P-002", name: "Addis Mixed-Use Tower"}}}}
	if t2 := os.Getenv("SERK_SEED_TENANT_2"); t2 != "" {
		name := envOr("SERK_SEED_TENANT_2_NAME", "Senselet Construction PLC (synthetic)")
		companies = append(companies, company{tenant: t2, name: name, shortCode: "senselet", letterhead: strings.ToUpper(name),
			projects: []project{{code: "SC-101", name: "Adwa Housing Phase 2"}, {code: "SC-102", name: "Aksum Water Supply Extension"}}})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var all []seeded
	for _, c := range companies {
		all = append(all, seedCompany(ctx, c, adminDSN, baseDSN, sec, approval))
	}
	if *out == "" {
		return
	}
	js, _ := json.Marshal(all)
	body := fmt.Sprintf("SERK_STAGING_TENANT=%s\nSERK_STAGING_PROJECTS=%s\nSERK_STAGING_COMPANIES='%s'\n", all[0].ID, strings.Join(all[0].Projects, ","), string(js))
	if err := os.WriteFile(*out, []byte(body), 0o600); err != nil {
		fail("write "+*out, err)
	}
}

func seedCompany(ctx context.Context, co company, adminDSN, baseDSN, sec, approval string) seeded {
	tenant := co.tenant
	projects := co.projects

	// 1. Tenant, its database role and its approval verification key.
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		fail("connect", err)
	}
	if err := postgres.ProvisionTenant(ctx, conn, tenant, co.name, postgres.TenantPassword([]byte(sec), tenant)); err != nil {
		fail("provision tenant", err)
	}
	if err := postgres.InstallApprovalKey(ctx, conn, tenant, "v1", attest.TenantKey([]byte(approval), tenant)); err != nil {
		fail("approval key", err)
	}
	_ = conn.Close(ctx)

	admin, err := postgres.Open(ctx, adminDSN)
	if err != nil {
		fail("admin store", err)
	}
	defer admin.Close()

	// 3. Governed setup through the kernel, as distinct synthetic people.
	router, err := postgres.NewRouter(ctx, postgres.RouterConfig{Credentials: postgres.DerivedCredentials{BaseDSN: baseDSN, Secret: []byte(sec)}})
	if err != nil {
		fail("router", err)
	}
	defer router.Close()
	svc := kernel.New(router, auth.NewAuthorizer(nil, true)).UseApprovalSigner(attest.Signer{Master: []byte(approval)})
	bankKey, digestKey := os.Getenv("SERK_BANK_DATA_KEY"), os.Getenv("SERK_BANK_DIGEST_KEY")
	if len(bankKey) >= 32 && len(digestKey) >= 32 && bankKey != digestKey {
		svc.UseBankDataKeys(datakey.Ring{Current: datakey.Key{ID: envOr("SERK_BANK_DATA_KEY_ID", "k1"), Master: []byte(bankKey)}, DigestKey: []byte(digestKey)})
	}
	now := time.Now()
	person := func(id string, scoped bool, roles ...string) auth.Principal {
		p := auth.Principal{Kind: auth.KindHuman, UserID: id, TenantID: tenant, Roles: roles, IssuedAt: now.Add(-time.Minute), MFA: true, AuthTime: now}
		if scoped {
			for _, pr := range projects { // ids are known once reference data exists
				if pr.id != "" {
					p.ProjectIDs = append(p.ProjectIDs, pr.id)
				}
			}
		}
		return p
	}
	// Idempotence: an existing entity means the seed already ran.
	var entity string
	err = admin.WithTenant(ctx, tenant, func(ctx context.Context, tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT id::text FROM legal_entities WHERE tenant_id = $1::uuid ORDER BY created_at LIMIT 1`, tenant).Scan(&entity); err != nil {
			return err
		}
		for i := range projects {
			if err := tx.QueryRow(ctx, `SELECT id::text FROM projects WHERE tenant_id = $1::uuid AND code = $2`, tenant, projects[i].code).Scan(&projects[i].id); err != nil {
				return err
			}
		}
		return nil
	})
	switch {
	case err == nil:
		fmt.Printf("serk-seed: %s already seeded; checking platform settings and rules\n", co.name)
		seedPlatform(ctx, svc, co, person)
		return report(co, entity, projects)
	case !errors.Is(err, pgx.ErrNoRows):
		fail("existing data", err)
	}

	// 2. Reference data (operator setup): entity, projects, periods, chart.
	acct := map[string]string{}
	err = admin.WithTenant(ctx, tenant, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		if entity, err = postgres.CreateLegalEntity(ctx, tx, tenant, co.letterhead, "ET", "ETB", "USD"); err != nil {
			return err
		}
		for i := range projects {
			if projects[i].id, err = postgres.CreateProject(ctx, tx, tenant, entity, projects[i].code, projects[i].name, "ETB"); err != nil {
				return err
			}
		}
		q := func(y, m int) time.Time { return time.Date(y, time.Month(m), 1, 0, 0, 0, 0, time.UTC) }
		for _, p := range []struct {
			name       string
			start, end time.Time
		}{
			{"FY2026-Q4", q(2026, 10), q(2026, 12).AddDate(0, 0, 30)},
			{"FY2027-Q1", q(2027, 1), q(2027, 3).AddDate(0, 0, 30)},
			{"FY2027-Q2", q(2027, 4), q(2027, 6).AddDate(0, 0, 29)},
			{"FY2027-Q3", q(2027, 7), q(2027, 9).AddDate(0, 0, 29)},
			{"FY2027-Q4", q(2027, 10), q(2027, 12).AddDate(0, 0, 30)},
		} {
			if _, err := postgres.CreateFiscalPeriod(ctx, tx, tenant, entity, p.name, p.start, p.end); err != nil {
				return err
			}
		}
		for _, a := range []struct{ code, name, typ string }{
			{"1000", "Cash at bank", "ASSET"}, {"1050", "Payments in transit", "ASSET"}, {"1100", "Accounts receivable", "ASSET"},
			{"1150", "Retention receivable", "ASSET"}, {"1200", "Inventory", "ASSET"}, {"1300", "VAT input", "ASSET"},
			{"2000", "Accounts payable", "LIABILITY"}, {"2100", "Goods received not invoiced", "LIABILITY"},
			{"2200", "Advances from customers", "LIABILITY"}, {"2300", "VAT output", "LIABILITY"},
			{"4000", "Contract revenue", "REVENUE"},
			{"5000", "Materials expense", "EXPENSE"}, {"5100", "Purchase price variance", "EXPENSE"}, {"5200", "Stock count variance", "EXPENSE"},
		} {
			if acct[a.code], err = postgres.CreateAccount(ctx, tx, ledger.Account{TenantID: tenant, LegalEntityID: entity, Code: a.code, Name: a.name,
				Type: ledger.AccountType(a.typ), Active: true}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		fail("reference data", err)
	}

	planner, finMgr := person("u-pm", true, "project_manager"), person("u-finance-manager", false, "finance_manager")
	controller, cfo := person("u-controller", false, "controller"), person("u-cfo", false, "cfo")
	buyer, procMgr := person("u-buyer", true, "procurement_officer"), person("u-proc-manager", true, "procurement_manager")
	arClerk, treasury := person("u-ar-clerk", false, "ar_clerk"), person("u-treasury", false, "treasury_officer")
	step := func(stage string, err error) {
		if err != nil {
			fail(stage, err)
		}
	}

	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, p := range projects {
		v, _, err := svc.ProposeWBSVersion(ctx, planner, p.id, "Tender WBS (synthetic)",
			[]postgres.WBSNode{{Code: "01", Name: "Substructure"}, {Code: "02", Name: "Superstructure"}, {Code: "03", Name: "Finishes and services"}},
			[]postgres.CostCode{
				{NodeCode: "01", Code: "01-MAT", Name: "Substructure materials", CostType: "MATERIAL", ValidFrom: from},
				{NodeCode: "01", Code: "01-PLT", Name: "Earthworks plant", CostType: "PLANT", ValidFrom: from},
				{NodeCode: "02", Code: "02-MAT", Name: "Structural materials", CostType: "MATERIAL", ValidFrom: from},
				{NodeCode: "02", Code: "02-LAB", Name: "Structural labour", CostType: "LABOUR", ValidFrom: from},
				{NodeCode: "03", Code: "03-SUB", Name: "Services subcontract", CostType: "SUBCONTRACT", ValidFrom: from},
				{NodeCode: "03", Code: "03-PRE", Name: "Site preliminaries", CostType: "PRELIMINARIES", ValidFrom: from},
			})
		step("WBS "+p.code, err)
		step("WBS approve "+p.code, svc.DecideWBSVersion(ctx, finMgr, v.ID, true, "Approved for the synthetic test environment"))
	}

	// Policies: the controller proposes, the CFO approves. The VAT rate is
	// tenant-configured test data, not a statement of current law.
	pol, err := svc.ProposeP2PPolicy(ctx, controller, postgres.P2PPolicy{LegalEntityID: entity, PriceTolerancePct: dec("0.02"), OverReceiptPct: dec("0.05"),
		VATRate: dec("0.15"), HighValuePOThreshold: dec("5000000"), DualPaymentThreshold: dec("500000"),
		GRNIAccountID: acct["2100"], APAccountID: acct["2000"], VATInputAccountID: acct["1300"], PPVAccountID: acct["5100"]})
	step("P2P policy", err)
	step("P2P policy approve", svc.DecideP2PPolicy(ctx, cfo, pol, true))
	cpol, err := svc.ProposeContractPolicy(ctx, controller, kernel.ContractPolicy{LegalEntityID: entity, VATRate: dec("0.15"), VATBase: "GROSS_LESS_ADVANCE",
		ARAccountID: acct["1100"], RetentionAccountID: acct["1150"], AdvanceAccountID: acct["2200"], RevenueAccountID: acct["4000"], VATOutputAccountID: acct["2300"]})
	step("contract policy", err)
	step("contract policy approve", svc.DecideContractPolicy(ctx, cfo, cpol, true))

	// Master data (synthetic names and tax ids).
	for i, s := range []struct{ code, name string }{{"ABC-STEEL", "ABC Steel PLC (synthetic)"}, {"HABESHA-CEMENT", "Habesha Cement PLC (synthetic)"},
		{"SAFARI-BUILD", "Safari Building Supplies PLC (synthetic)"}} {
		id, err := svc.CreateSupplier(ctx, buyer, entity, s.code, s.name, fmt.Sprintf("TIN-TEST-%04d", i+1))
		step("supplier "+s.code, err)
		step("supplier approve "+s.code, svc.ApproveSupplier(ctx, procMgr, id))
	}
	cust, err := svc.CreateCustomer(ctx, arClerk, entity, "ERA", "Roads Authority (synthetic)", "TIN-TEST-ERA")
	step("customer", err)
	step("customer approve", svc.ApproveCustomer(ctx, finMgr, cust))
	for _, it := range []struct{ code, name, unit, method string }{{"STEEL-G60", "Reinforcement steel Grade 60", "t", "FIFO"},
		{"CEM-OPC50", "OPC cement 50kg", "bag", "WAC"}, {"AGG-20", "Crushed aggregate 20mm", "m3", "WAC"}} {
		id, err := svc.CreateStockItem(ctx, buyer, kernel.StockItemInput{LegalEntityID: entity, Code: it.code, Name: it.name, Unit: it.unit,
			ValuationMethod: it.method, InventoryAccountID: acct["1200"]})
		step("stock item "+it.code, err)
		step("stock item approve "+it.code, svc.ApproveStockItem(ctx, finMgr, id))
	}
	for _, p := range projects {
		_, err := svc.CreateWarehouse(ctx, procMgr, entity, p.id, strings.ReplaceAll(p.code, "-", "")+"-STORE", p.name+" site store")
		step("warehouse "+p.code, err)
	}
	if len(bankKey) >= 32 {
		bank, err := svc.RegisterCompanyBankAccount(ctx, treasury, entity, "Operating account (synthetic)", "9999000011112222", "ETB", acct["1000"], acct["1050"])
		step("company bank account", err)
		step("company bank account approve", svc.ApproveCompanyBankAccount(ctx, cfo, bank))
	} else {
		fmt.Println("serk-seed: SERK_BANK_DATA_KEY/SERK_BANK_DIGEST_KEY not set; company bank account skipped")
	}
	seedPlatform(ctx, svc, co, person)
	fmt.Printf("serk-seed: %s seeded\n", co.name)
	return report(co, entity, projects)
}

func report(co company, entity string, projects []project) seeded {
	ids := make([]string, len(projects))
	for i, p := range projects {
		ids[i] = p.id
		fmt.Printf("  project %s %-32s %s\n", p.code, p.name, p.id)
	}
	fmt.Printf("  tenant %s, legal entity %s\n", co.tenant, entity)
	return seeded{ID: co.tenant, Name: co.name, Projects: ids}
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// seedPlatform adds the company portal settings and the starter automation
// rules when they are missing (idempotent, so an already-seeded company
// gets them on upgrade).
func seedPlatform(ctx context.Context, svc *kernel.Service, co company, person func(string, bool, ...string) auth.Principal) {
	step := func(stage string, err error) {
		if err != nil {
			fail(stage, err)
		}
	}
	secAdmin := person("u-security-admin", false, "security_admin")
	if cur, err := svc.TenantSettings(ctx, secAdmin); err == nil && cur.Version == 0 {
		_, err = svc.SaveTenantSettings(ctx, secAdmin, postgres.TenantSettings{DisplayName: co.name, ShortCode: co.shortCode, LetterheadName: co.letterhead,
			Country: "ET", Timezone: "Africa/Addis_Ababa", Locale: "en", ExportDailyLimit: 200})
		step("tenant settings", err)
	}
	owner, wfAdmin := person("u-process-owner", false, "process_owner"), person("u-workflow-admin", false, "workflow_admin")
	existing, err := svc.ListRules(ctx, owner, "")
	step("list rules", err)
	have := map[string]bool{}
	for _, r := range existing {
		have[r.Code] = true
	}
	for _, r := range []kernel.RuleInput{
		{Code: "AP-INVOICE-STALE", Name: "Supplier invoices waiting more than 2 days", Description: "Submitted supplier invoices not decided within 48 hours are escalated to the AP supervisor.",
			Body: []byte(`{"when":{"kind":"document_stale","subject":"supplier_invoice","status":"SUBMITTED","hours":48},"then":{"notify_role":"ap_supervisor","severity":"warn","title":"Invoice waiting"}}`)},
		{Code: "PR-STALE", Name: "Requisitions waiting more than 3 days", Description: "Submitted requisitions not decided within 72 hours are escalated to project managers.",
			Body: []byte(`{"when":{"kind":"document_stale","subject":"purchase_requisition","status":"SUBMITTED","hours":72},"then":{"notify_role":"project_manager","severity":"warn","title":"Requisition waiting"}}`)},
		{Code: "AP-DUE-7D", Name: "Supplier invoices due within 7 days", Description: "Treasury is told which approved invoices fall due in the coming week.",
			Body: []byte(`{"when":{"kind":"invoice_due","days":7},"then":{"notify_role":"treasury_officer","severity":"info"}}`)},
		{Code: "AR-OVERDUE-30", Name: "Customer invoices overdue 30 days", Description: "The AR supervisor is told about receivables more than 30 days past due.",
			Body: []byte(`{"when":{"kind":"receivable_overdue","days":30},"then":{"notify_role":"ar_supervisor","severity":"warn"}}`)},
		{Code: "PO-OVERDUE", Name: "Purchase orders past their needed-by date", Description: "Open purchase orders whose goods were needed before today.",
			Body: []byte(`{"when":{"kind":"po_overdue"},"then":{"notify_role":"procurement_manager","severity":"warn"}}`)},
		{Code: "BUDGET-90", Name: "Cost codes at 90% of budget", Description: "Project managers are told when a cost code has consumed 90% of its budget.",
			Body: []byte(`{"when":{"kind":"budget_threshold","percent":90},"then":{"notify_role":"project_manager","severity":"critical"}}`)},
		{Code: "SPI-LOW", Name: "Schedule performance below 0.9", Description: "Planners are told when a project's SPI falls below 0.9.",
			Body: []byte(`{"when":{"kind":"schedule_risk","ratio":"0.9"},"then":{"notify_role":"planner","severity":"warn"}}`)},
		{Code: "EXPORT-50", Name: "More than 50 exports in a day", Description: "Security is told when one person exports more than 50 files in 24 hours.",
			Body: []byte(`{"when":{"kind":"export_volume","count":50},"then":{"notify_role":"security_admin","severity":"critical"}}`)},
	} {
		if have[r.Code] {
			continue
		}
		rule, err := svc.ProposeRule(ctx, owner, r)
		step("rule "+r.Code, err)
		_, err = svc.DecideRule(ctx, wfAdmin, rule.ID, true, "")
		step("rule activate "+r.Code, err)
	}
}
