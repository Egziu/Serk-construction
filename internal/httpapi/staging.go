package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// StagingLogin is a test-environment sign-in that mints HS256 tokens for a
// fixed cast of synthetic personas, so testers need no identity provider.
// It is never available in production: config.Validate refuses
// SERK_STAGING_LOGIN_PASSPHRASE there, and production also refuses HS256
// tokens altogether. The minted token carries no authority beyond the
// persona's roles; the kernel and PostgreSQL re-authorize every action
// (separation of duties, project scope, step-up, attestations) exactly as
// for an identity-provider token.
type StagingLogin struct {
	Passphrase []byte // shared test passphrase (>= 16 bytes)
	Signer     HS256Verifier
	// Tenant and Projects are the first (default) company; Companies lists
	// every company a tester may sign in to (Tenant is added when absent).
	Tenant    string
	Projects  []string
	Companies []StagingCompany
	TTL       time.Duration
}

// StagingCompany is one synthetic construction company (tenant).
type StagingCompany struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Projects []string `json:"projects"`
}

// Persona is one synthetic test user.
type Persona struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Roles  []string `json:"roles"`
	Scoped bool     `json:"project_scoped"`
}

// StagingPersonas covers every journey: one person per duty so that
// separation of duties can be exercised by switching persona.
var StagingPersonas = []Persona{
	{"u-estimator", "Estimator", []string{"estimator"}, true},
	{"u-commercial", "Commercial manager", []string{"commercial_manager"}, true},
	{"u-pm", "Project manager", []string{"project_manager"}, true},
	{"u-planner", "Planner", []string{"planner"}, true},
	{"u-site-engineer", "Site engineer", []string{"site_engineer"}, true},
	{"u-buyer", "Procurement officer", []string{"procurement_officer"}, true},
	{"u-proc-manager", "Procurement manager", []string{"procurement_manager"}, true},
	{"u-storekeeper", "Storekeeper", []string{"storekeeper"}, true},
	{"u-inventory", "Inventory controller", []string{"inventory_controller"}, true},
	{"u-qs", "Quantity surveyor", []string{"quantity_surveyor"}, true},
	{"u-project-accountant", "Project accountant", []string{"project_accountant"}, true},
	{"u-ap-clerk", "AP clerk", []string{"ap_clerk"}, true},
	{"u-ap-supervisor", "AP supervisor", []string{"ap_supervisor"}, true},
	{"u-ar-clerk", "AR clerk", []string{"ar_clerk"}, false},
	{"u-ar-supervisor", "AR supervisor", []string{"ar_supervisor"}, false},
	{"u-treasury", "Treasury officer", []string{"treasury_officer"}, false},
	{"u-treasury-2", "Treasury officer (second)", []string{"treasury_officer"}, false},
	{"u-bank-officer", "Bank statement officer", []string{"bank_statement_officer"}, false},
	{"u-accountant", "Accountant", []string{"accountant"}, false},
	{"u-controller", "Controller", []string{"controller"}, false},
	{"u-finance-manager", "Finance manager", []string{"finance_manager"}, false},
	{"u-cfo", "CFO", []string{"cfo"}, false},
	{"u-auditor", "Auditor (read only)", []string{"auditor"}, false},
	{"u-process-owner", "Process owner (automation rules)", []string{"process_owner"}, false},
	{"u-workflow-admin", "Workflow admin (activates rules)", []string{"workflow_admin"}, false},
	{"u-security-admin", "Security admin (company settings)", []string{"security_admin"}, false},
}

func (s *Server) registerStaging() {
	sl := s.cfg.Staging
	if sl == nil {
		return
	}
	if len(sl.Passphrase) < 16 || sl.Tenant == "" {
		panic("httpapi: StagingLogin needs a passphrase of at least 16 bytes and a tenant")
	}
	if sl.TTL == 0 {
		sl.TTL = 8 * time.Hour
	}
	known := false
	for _, c := range sl.Companies {
		if c.ID == sl.Tenant {
			known = true
		}
	}
	if !known {
		sl.Companies = append([]StagingCompany{{ID: sl.Tenant, Name: "Default company", Projects: sl.Projects}}, sl.Companies...)
	}
	s.mux.HandleFunc("GET /staging/personas", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"environment": "staging", "synthetic_data": true, "vendor": "SERK Construction OS",
			"companies": sl.Companies, "personas": StagingPersonas})
	})
	s.mux.HandleFunc("POST /staging/token", func(w http.ResponseWriter, r *http.Request) {
		ip := limitKey(clientIP(r, s.cfg.Abuse.TrustedProxies))
		if s.authFail.blocked(ip) {
			w.Header().Set("Retry-After", "300")
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many failed authentication attempts")
			return
		}
		if !s.preauth.hit(ip) {
			w.Header().Set("Retry-After", "60")
			writeErr(w, http.StatusTooManyRequests, "rate_limited", "request budget exceeded")
			return
		}
		var in struct {
			Passphrase string `json:"passphrase"`
			Persona    string `json:"persona"`
			Company    string `json:"company,omitempty"`
		}
		if !decode(w, r, &in) {
			return
		}
		a, b := sha256.Sum256([]byte(in.Passphrase)), sha256.Sum256(sl.Passphrase)
		if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
			s.authFailure(ip, "staging_passphrase")
			writeErr(w, http.StatusUnauthorized, "unauthenticated", "wrong staging passphrase")
			return
		}
		company := sl.Companies[0]
		if in.Company != "" {
			found := false
			for _, c := range sl.Companies {
				if c.ID == in.Company {
					company, found = c, true
				}
			}
			if !found {
				writeErr(w, http.StatusUnprocessableEntity, "validation", "unknown company")
				return
			}
		}
		var p *Persona
		for i := range StagingPersonas {
			if StagingPersonas[i].ID == in.Persona {
				p = &StagingPersonas[i]
			}
		}
		if p == nil {
			writeErr(w, http.StatusUnprocessableEntity, "validation", "unknown persona")
			return
		}
		now := time.Now()
		c := Claims{Subject: p.ID, TenantID: company.ID, Roles: p.Roles, IssuedAt: now.Unix(), ExpiresAt: now.Add(sl.TTL).Unix(),
			Issuer: sl.Signer.Issuer, Audience: sl.Signer.Audience, Kind: "human", TokenID: uuid.NewString(),
			// A staging sign-in counts as a fresh multi-factor login; step-up
			// actions need a new sign-in after the step-up window.
			AMR: []string{"pwd", "otp"}, AuthTime: now.Unix()}
		if p.Scoped {
			c.Projects = company.Projects
		}
		tok, err := sl.Signer.Sign(c)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "could not issue token")
			return
		}
		s.cfg.Logger.Info("security", "event", "staging_token_issued", "persona", p.ID, "tenant", company.ID)
		writeJSON(w, http.StatusOK, map[string]any{"token": tok, "expires_at": now.Add(sl.TTL).UTC().Format(time.RFC3339)})
	})
}
