// gen-risk2-vectors generates ACP-RISK-2.0 unsigned test vectors.
//
// These vectors test the deterministic risk scoring formula (ACP-RISK-2.0 §3).
// They are intentionally unsigned — cryptographic validity is covered by the
// 73 signed vectors in compliance/test-vectors/.
//
// Usage:
//
//	go run ./cmd/gen-risk2-vectors/ -out ../../compliance/test-vectors/risk-2.0/
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// ─── Vector Schema ─────────────────────────────────────────────────────────────

type Meta struct {
	ID               string `json:"id"`
	Layer            string `json:"layer"`
	Severity         string `json:"severity"`
	ACPVersion       string `json:"acp_version"`
	Spec             string `json:"spec"`
	ConformanceLevel string `json:"conformance_level"`
	Description      string `json:"description"`
	Note             string `json:"note"`
}

type Policy struct {
	AutonomyLevel          int    `json:"autonomy_level"`
	ApprovedMax            int    `json:"approved_max"`
	EscalatedMax           int    `json:"escalated_max"`
	AnomalyRule1ThresholdN int    `json:"anomaly_rule1_threshold_n"`
	AnomalyRule2ThresholdX int    `json:"anomaly_rule2_threshold_x"`
	AnomalyRule3ThresholdY int    `json:"anomaly_rule3_threshold_y"`
	CooldownTriggerDenials int    `json:"cooldown_trigger_denials"`
	CooldownPeriodSeconds  int    `json:"cooldown_period_seconds"`
	PolicyHash             string `json:"policy_hash"`
}

type ContextInput struct {
	ExternalIP     bool `json:"external_ip"`
	OffHours       bool `json:"off_hours"`
	NonBusinessDay bool `json:"non_business_day"`
	GeoOutside     bool `json:"geo_outside"`
	TimestampDrift bool `json:"timestamp_drift"`
	UntrustedDevice bool `json:"untrusted_device"`
}

type HistoryInput struct {
	DenialRateHigh        bool `json:"denial_rate_high"`
	UnresolvedEscalations bool `json:"unresolved_escalations"`
	RecentDenial          bool `json:"recent_denial"`
	FreqAnomaly           bool `json:"freq_anomaly"`
	AmountNearLimit       bool `json:"amount_near_limit"`
	NoHistory             bool `json:"no_history"`
}

type AnomalyInput struct {
	Rule1Count     int  `json:"rule1_count"`
	Rule2Count     int  `json:"rule2_count"`
	Rule3Count     int  `json:"rule3_count"`
	CooldownActive bool `json:"cooldown_active"`
}

type Input struct {
	AgentID       string       `json:"agent_id"`
	Capability    string       `json:"capability"`
	Resource      string       `json:"resource"`
	ResourceClass string       `json:"resource_class"`
	Context       ContextInput `json:"context"`
	History       HistoryInput `json:"history"`
	Anomaly       AnomalyInput `json:"anomaly"`
}

type Factors struct {
	Base     int `json:"base"`
	Context  int `json:"context"`
	History  int `json:"history"`
	Resource int `json:"resource"`
	Anomaly  int `json:"anomaly"`
}

type AnomalyDetail struct {
	Rule1Triggered bool `json:"rule1_triggered"`
	Rule2Triggered bool `json:"rule2_triggered"`
	Rule3Triggered bool `json:"rule3_triggered"`
}

type Expected struct {
	Factors       Factors       `json:"factors"`
	RSRaw         int           `json:"rs_raw"`
	RSFinal       int           `json:"rs_final"`
	Decision      string        `json:"decision"`
	AnomalyDetail AnomalyDetail `json:"anomaly_detail"`
	DeniedReason  string        `json:"denied_reason,omitempty"`
}

type Vector struct {
	Meta     Meta     `json:"meta"`
	Policy   Policy   `json:"policy"`
	Input    Input    `json:"input"`
	Expected Expected `json:"expected"`
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

const unsignedNote = "Unsigned vector — tests deterministic formula only, not cryptographic pipeline"
const defaultPolicyHash = "sha256:test-policy-v1-default"

func defaultPolicy() Policy {
	return Policy{
		AutonomyLevel:          2,
		ApprovedMax:            39,
		EscalatedMax:           69,
		AnomalyRule1ThresholdN: 10,
		AnomalyRule2ThresholdX: 3,
		AnomalyRule3ThresholdY: 3,
		CooldownTriggerDenials: 3,
		CooldownPeriodSeconds:  300,
		PolicyHash:             defaultPolicyHash,
	}
}

func noCtx() ContextInput  { return ContextInput{} }
func noHist() HistoryInput { return HistoryInput{} }
func noAnom() AnomalyInput { return AnomalyInput{} }

func min100(v int) int {
	if v > 100 {
		return 100
	}
	return v
}

// capBase returns B(c) per ACP-RISK-2.0 §3.2.
func capBase(cap string) int {
	switch cap {
	case "acp:cap:data.read", "acp:cap:data.monitor":
		return 0
	case "acp:cap:data.write":
		return 10
	case "acp:cap:data.notify":
		return 5
	case "acp:cap:financial.payment":
		return 35
	case "acp:cap:financial.transfer":
		return 40
	case "acp:cap:infrastructure.delete":
		return 55
	case "acp:cap:agent.revoke":
		return 40
	default:
		return 40
	}
}

// resScore returns F_res(r) per ACP-RISK-2.0 §3.4.
func resScore(class string) int {
	switch class {
	case "public":
		return 0
	case "internal":
		return 5
	case "sensitive":
		return 15
	case "critical":
		return 30
	case "restricted":
		return 45
	default:
		return 15 // unclassified → sensitive (RISK-003)
	}
}

// ctxScore returns F_ctx(x).
func ctxScore(c ContextInput) int {
	s := 0
	if c.ExternalIP {
		s += 20
	}
	if c.OffHours {
		s += 15
	}
	if c.NonBusinessDay {
		s += 10
	}
	if c.GeoOutside {
		s += 25
	}
	if c.TimestampDrift {
		s += 30
	}
	if c.UntrustedDevice {
		s += 10
	}
	return s
}

// histScore returns F_hist(h).
func histScore(h HistoryInput) int {
	s := 0
	if h.DenialRateHigh {
		s += 15
	}
	if h.UnresolvedEscalations {
		s += 10
	}
	if h.RecentDenial {
		s += 20
	}
	if h.FreqAnomaly {
		s += 15
	}
	if h.AmountNearLimit {
		s += 20
	}
	if h.NoHistory {
		s += 10
	}
	return s
}

// anomScore returns F_anom(a) given counts and policy thresholds.
func anomScore(a AnomalyInput, p Policy) (int, AnomalyDetail) {
	detail := AnomalyDetail{}
	s := 0
	if a.Rule1Count > p.AnomalyRule1ThresholdN {
		detail.Rule1Triggered = true
		s += 20
	}
	if a.Rule2Count >= p.AnomalyRule2ThresholdX {
		detail.Rule2Triggered = true
		s += 15
	}
	if a.Rule3Count >= p.AnomalyRule3ThresholdY {
		detail.Rule3Triggered = true
		s += 15
	}
	return s, detail
}

// decision applies autonomy-level-aware thresholds.
func decision(rsFinal int, p Policy) string {
	var approvedMax, escalatedMax int
	switch p.AutonomyLevel {
	case 0:
		return "DENIED"
	case 1:
		approvedMax, escalatedMax = 19, 100
	case 2:
		approvedMax, escalatedMax = 39, 69
	case 3:
		approvedMax, escalatedMax = 59, 79
	case 4:
		approvedMax, escalatedMax = 79, 89
	default:
		approvedMax, escalatedMax = p.ApprovedMax, p.EscalatedMax
	}
	if rsFinal <= approvedMax {
		return "APPROVED"
	}
	if rsFinal <= escalatedMax {
		return "ESCALATED"
	}
	return "DENIED"
}

// compute calculates all expected values for a vector.
func compute(cap, class string, ctx ContextInput, hist HistoryInput, anom AnomalyInput, p Policy) Expected {
	base := capBase(cap)
	fctx := ctxScore(ctx)
	fhist := histScore(hist)
	fres := resScore(class)
	fanom, anomDetail := anomScore(anom, p)
	rsRaw := base + fctx + fhist + fres + fanom
	rsFinal := min100(rsRaw)
	dec := decision(rsFinal, p)
	return Expected{
		Factors:       Factors{Base: base, Context: fctx, History: fhist, Resource: fres, Anomaly: fanom},
		RSRaw:         rsRaw,
		RSFinal:       rsFinal,
		Decision:      dec,
		AnomalyDetail: anomDetail,
	}
}

func mkVector(id, desc, cap, res, class string, ctx ContextInput, hist HistoryInput, anom AnomalyInput, p Policy) Vector {
	exp := compute(cap, class, ctx, hist, anom, p)
	return Vector{
		Meta: Meta{
			ID: id, Layer: "RISK2", Severity: "mandatory",
			ACPVersion: "2.0", Spec: "ACP-RISK-2.0", ConformanceLevel: "L2",
			Description: desc, Note: unsignedNote,
		},
		Policy: p,
		Input: Input{
			AgentID:       "acp:agent:org.example:agent-001",
			Capability:    cap,
			Resource:      "org.example/" + res,
			ResourceClass: class,
			Context:       ctx,
			History:       hist,
			Anomaly:       anom,
		},
		Expected: exp,
	}
}

// ─── Vector Definitions ────────────────────────────────────────────────────────

func allVectors() []Vector {
	p := defaultPolicy()
	var vv []Vector

	// ── Block 1: Base cases (capability × resource) ──────────────────────────

	vv = append(vv, mkVector("TS-RISK2-POS-001",
		"read + public: RS=0 → APPROVED",
		"acp:cap:data.read", "reports/Q1", "public", noCtx(), noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-002",
		"read + sensitive: RS=15 → APPROVED",
		"acp:cap:data.read", "pii/customers", "sensitive", noCtx(), noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-003",
		"read + restricted: RS=45 → ESCALATED",
		"acp:cap:data.read", "secrets/vault", "restricted", noCtx(), noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-004",
		"write + public: RS=10 → APPROVED",
		"acp:cap:data.write", "logs/app", "public", noCtx(), noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-005",
		"write + sensitive: RS=25 → APPROVED",
		"acp:cap:data.write", "records/HR", "sensitive", noCtx(), noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-006",
		"write + restricted: RS=55 → ESCALATED",
		"acp:cap:data.write", "config/production", "restricted", noCtx(), noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-007",
		"financial.payment + public: RS=35 → APPROVED",
		"acp:cap:financial.payment", "payments/low-risk", "public", noCtx(), noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-008",
		"financial.payment + sensitive: RS=50 → ESCALATED",
		"acp:cap:financial.payment", "accounts/ACC-001", "sensitive", noCtx(), noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-009",
		"financial.payment + restricted: RS=80 → DENIED",
		"acp:cap:financial.payment", "accounts/ACC-001", "restricted", noCtx(), noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-010",
		"infrastructure.delete + restricted: RS=100 → DENIED",
		"acp:cap:infrastructure.delete", "infra/prod-cluster", "restricted", noCtx(), noHist(), noAnom(), p))

	// ── Block 2: Context factors ──────────────────────────────────────────────

	vv = append(vv, mkVector("TS-RISK2-POS-011",
		"read + public + external_ip: RS=20 → APPROVED",
		"acp:cap:data.read", "reports/Q1", "public",
		ContextInput{ExternalIP: true}, noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-012",
		"read + public + off_hours: RS=15 → APPROVED",
		"acp:cap:data.read", "reports/Q1", "public",
		ContextInput{OffHours: true}, noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-013",
		"read + public + off_hours + non_business_day: RS=25 → APPROVED",
		"acp:cap:data.read", "reports/Q1", "public",
		ContextInput{OffHours: true, NonBusinessDay: true}, noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-014",
		"write + sensitive + external_ip: RS=45 → ESCALATED",
		"acp:cap:data.write", "records/HR", "sensitive",
		ContextInput{ExternalIP: true}, noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-015",
		"payment + public + external_ip: RS=55 → ESCALATED",
		"acp:cap:financial.payment", "payments/batch", "public",
		ContextInput{ExternalIP: true}, noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-016",
		"payment + sensitive + external_ip: RS=70 → DENIED",
		"acp:cap:financial.payment", "accounts/ACC-001", "sensitive",
		ContextInput{ExternalIP: true}, noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-017",
		"payment + restricted + off_hours: RS=95 → DENIED",
		"acp:cap:financial.payment", "accounts/ACC-001", "restricted",
		ContextInput{OffHours: true}, noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-018",
		"read + public + geo_outside: RS=25 → APPROVED",
		"acp:cap:data.read", "reports/Q1", "public",
		ContextInput{GeoOutside: true}, noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-019",
		"read + public + timestamp_drift: RS=30 → APPROVED",
		"acp:cap:data.read", "reports/Q1", "public",
		ContextInput{TimestampDrift: true}, noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-020",
		"payment + public + timestamp_drift + off_hours: RS=80 → DENIED",
		"acp:cap:financial.payment", "payments/batch", "public",
		ContextInput{TimestampDrift: true, OffHours: true}, noHist(), noAnom(), p))

	// ── Block 3: History factors ──────────────────────────────────────────────

	vv = append(vv, mkVector("TS-RISK2-POS-021",
		"read + public + recent_denial: RS=20 → APPROVED",
		"acp:cap:data.read", "reports/Q1", "public",
		noCtx(), HistoryInput{RecentDenial: true}, noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-022",
		"write + sensitive + recent_denial: RS=45 → ESCALATED",
		"acp:cap:data.write", "records/HR", "sensitive",
		noCtx(), HistoryInput{RecentDenial: true}, noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-023",
		"payment + public + denial_rate_high: RS=50 → ESCALATED",
		"acp:cap:financial.payment", "payments/batch", "public",
		noCtx(), HistoryInput{DenialRateHigh: true}, noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-024",
		"payment + sensitive + denial_rate_high: RS=65 → ESCALATED",
		"acp:cap:financial.payment", "accounts/ACC-001", "sensitive",
		noCtx(), HistoryInput{DenialRateHigh: true}, noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-025",
		"payment + sensitive + recent_denial: RS=70 → DENIED",
		"acp:cap:financial.payment", "accounts/ACC-001", "sensitive",
		noCtx(), HistoryInput{RecentDenial: true}, noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-026",
		"payment + restricted + no_history: RS=90 → DENIED",
		"acp:cap:financial.payment", "accounts/ACC-001", "restricted",
		noCtx(), HistoryInput{NoHistory: true}, noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-027",
		"read + public + no_history: RS=10 → APPROVED",
		"acp:cap:data.read", "reports/Q1", "public",
		noCtx(), HistoryInput{NoHistory: true}, noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-028",
		"payment + public + unresolved_escalations: RS=45 → ESCALATED",
		"acp:cap:financial.payment", "payments/batch", "public",
		noCtx(), HistoryInput{UnresolvedEscalations: true}, noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-029",
		"payment + public + amount_near_limit: RS=55 → ESCALATED",
		"acp:cap:financial.payment", "payments/batch", "public",
		noCtx(), HistoryInput{AmountNearLimit: true}, noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-POS-030",
		"payment + restricted + recent_denial + denial_rate_high: RS=100 (cap) → DENIED",
		"acp:cap:financial.payment", "accounts/ACC-001", "restricted",
		noCtx(), HistoryInput{RecentDenial: true, DenialRateHigh: true}, noAnom(), p))

	// ── Block 4: F_anom rules + boundaries ───────────────────────────────────

	vv = append(vv, mkVector("TS-RISK2-POS-031",
		"Rule1 triggered (count=11 > N=10): F_anom=20 → RS=20 → APPROVED",
		"acp:cap:data.read", "reports/Q1", "public",
		noCtx(), noHist(), AnomalyInput{Rule1Count: 11}, p))

	vv = append(vv, mkVector("TS-RISK2-POS-032",
		"Rule2 triggered (count=3 >= X=3): write+sensitive+F_anom=15 → RS=40 → ESCALATED",
		"acp:cap:data.write", "records/HR", "sensitive",
		noCtx(), noHist(), AnomalyInput{Rule2Count: 3}, p))

	vv = append(vv, mkVector("TS-RISK2-POS-033",
		"Rule3 triggered (count=3 >= Y=3): payment+public+F_anom=15 → RS=50 → ESCALATED",
		"acp:cap:financial.payment", "payments/batch", "public",
		noCtx(), noHist(), AnomalyInput{Rule3Count: 3}, p))

	vv = append(vv, mkVector("TS-RISK2-POS-034",
		"Rule1+Rule2 triggered: payment+sensitive+F_anom=35 → RS=85 → DENIED",
		"acp:cap:financial.payment", "accounts/ACC-001", "sensitive",
		noCtx(), noHist(), AnomalyInput{Rule1Count: 11, Rule2Count: 3}, p))

	vv = append(vv, mkVector("TS-RISK2-POS-035",
		"Rule1+Rule3 triggered: payment+sensitive+F_anom=35 → RS=85 → DENIED",
		"acp:cap:financial.payment", "accounts/ACC-001", "sensitive",
		noCtx(), noHist(), AnomalyInput{Rule1Count: 15, Rule3Count: 5}, p))

	vv = append(vv, mkVector("TS-RISK2-POS-036",
		"Rule2+Rule3 triggered: payment+sensitive+F_anom=30 → RS=80 → DENIED",
		"acp:cap:financial.payment", "accounts/ACC-001", "sensitive",
		noCtx(), noHist(), AnomalyInput{Rule2Count: 4, Rule3Count: 4}, p))

	vv = append(vv, mkVector("TS-RISK2-POS-037",
		"All 3 rules triggered: F_anom=50 (max). payment+sensitive → RS=100 → DENIED",
		"acp:cap:financial.payment", "accounts/ACC-001", "sensitive",
		noCtx(), noHist(), AnomalyInput{Rule1Count: 15, Rule2Count: 5, Rule3Count: 5}, p))

	vv = append(vv, mkVector("TS-RISK2-POS-038",
		"Rule1 NOT triggered: count=10 is NOT > N=10 (boundary). RS=0 → APPROVED",
		"acp:cap:data.read", "reports/Q1", "public",
		noCtx(), noHist(), AnomalyInput{Rule1Count: 10}, p))

	vv = append(vv, mkVector("TS-RISK2-POS-039",
		"Rule2 NOT triggered: count=2 < X=3 (boundary). RS=15 → APPROVED",
		"acp:cap:data.write", "records/internal", "internal",
		noCtx(), noHist(), AnomalyInput{Rule2Count: 2}, p))

	vv = append(vv, mkVector("TS-RISK2-POS-040",
		"Rule3 NOT triggered: count=2 < Y=3 (boundary). RS=35 → APPROVED",
		"acp:cap:financial.payment", "payments/batch", "public",
		noCtx(), noHist(), AnomalyInput{Rule3Count: 2}, p))

	// ── Block 5: Complex mix ──────────────────────────────────────────────────

	vv = append(vv, mkVector("TS-RISK2-MIX-001",
		"payment+restricted+external_ip+recent_denial+Rule2: RS=100 (cap) → DENIED",
		"acp:cap:financial.payment", "accounts/ACC-001", "restricted",
		ContextInput{ExternalIP: true}, HistoryInput{RecentDenial: true},
		AnomalyInput{Rule2Count: 3}, p))

	vv = append(vv, mkVector("TS-RISK2-MIX-002",
		"write+sensitive+off_hours+denial_rate_high+Rule1: RS=75 → DENIED",
		"acp:cap:data.write", "records/HR", "sensitive",
		ContextInput{OffHours: true}, HistoryInput{DenialRateHigh: true},
		AnomalyInput{Rule1Count: 12}, p))

	vv = append(vv, mkVector("TS-RISK2-MIX-003",
		"read+internal+external_ip+no_history: RS=35 → APPROVED",
		"acp:cap:data.read", "records/internal", "internal",
		ContextInput{ExternalIP: true}, HistoryInput{NoHistory: true}, noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-MIX-004",
		"payment+public+off_hours+unresolved_escalations: RS=60 → ESCALATED",
		"acp:cap:financial.payment", "payments/batch", "public",
		ContextInput{OffHours: true}, HistoryInput{UnresolvedEscalations: true}, noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-MIX-005",
		"payment+sensitive+geo_outside+recent_denial: RS=95 → DENIED",
		"acp:cap:financial.payment", "accounts/ACC-001", "sensitive",
		ContextInput{GeoOutside: true}, HistoryInput{RecentDenial: true}, noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-MIX-006",
		"write+restricted+timestamp_drift: RS=85 → DENIED",
		"acp:cap:data.write", "config/production", "restricted",
		ContextInput{TimestampDrift: true}, noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-MIX-007",
		"read+sensitive+external_ip+Rule2: RS=50 → ESCALATED",
		"acp:cap:data.read", "pii/customers", "sensitive",
		ContextInput{ExternalIP: true}, noHist(), AnomalyInput{Rule2Count: 3}, p))

	vv = append(vv, mkVector("TS-RISK2-MIX-008",
		"agent.revoke+internal+off_hours: RS=60 → ESCALATED",
		"acp:cap:agent.revoke", "agents/agent-001", "internal",
		ContextInput{OffHours: true}, noHist(), noAnom(), p))

	vv = append(vv, mkVector("TS-RISK2-MIX-009",
		"agent.revoke+restricted+external_ip+Rule1: RS=100 (cap) → DENIED",
		"acp:cap:agent.revoke", "agents/agent-001", "restricted",
		ContextInput{ExternalIP: true}, noHist(), AnomalyInput{Rule1Count: 11}, p))

	vv = append(vv, mkVector("TS-RISK2-MIX-010",
		"infrastructure.delete+public: RS=55 → ESCALATED",
		"acp:cap:infrastructure.delete", "infra/staging", "public",
		noCtx(), noHist(), noAnom(), p))

	// ── Block 6: NEG — autonomy overrides, cooldown, anti-gaming, errors ──────

	// Autonomy level 0 — always DENIED
	p0 := defaultPolicy()
	p0.AutonomyLevel = 0
	v0 := mkVector("TS-RISK2-NEG-001",
		"Autonomy level 0: DENIED always regardless of RS (RISK-006)",
		"acp:cap:financial.payment", "payments/batch", "public", noCtx(), noHist(), noAnom(), p0)
	v0.Expected.Decision = "DENIED"
	v0.Expected.DeniedReason = "AUTONOMY_LEVEL_0"
	vv = append(vv, v0)

	// Autonomy level 1 — RS=15 → APPROVED (threshold ≤19)
	p1 := defaultPolicy()
	p1.AutonomyLevel = 1
	vv = append(vv, mkVector("TS-RISK2-NEG-002",
		"Autonomy level 1: RS=15 → APPROVED (threshold ≤19)",
		"acp:cap:data.read", "reports/Q1", "public",
		ContextInput{OffHours: true}, noHist(), noAnom(), p1))

	// Autonomy level 1 — RS=20 → ESCALATED (boundary: 20 ≥ 20)
	vv = append(vv, mkVector("TS-RISK2-NEG-003",
		"Autonomy level 1: RS=20 → ESCALATED (boundary: exactly at threshold 20)",
		"acp:cap:data.read", "reports/Q1", "public",
		ContextInput{ExternalIP: true}, noHist(), noAnom(), p1))

	// Autonomy level 4 — RS=80 → ESCALATED (threshold 80-89)
	p4 := defaultPolicy()
	p4.AutonomyLevel = 4
	vv = append(vv, mkVector("TS-RISK2-NEG-004",
		"Autonomy level 4: RS=80 → ESCALATED (80-89 range for autonomy=4)",
		"acp:cap:financial.payment", "accounts/ACC-001", "restricted",
		noCtx(), noHist(), noAnom(), p4))

	// Autonomy level 4 — RS=90 → DENIED
	vv = append(vv, mkVector("TS-RISK2-NEG-005",
		"Autonomy level 4: RS=90 → DENIED (≥90 for autonomy=4)",
		"acp:cap:financial.payment", "accounts/ACC-001", "restricted",
		ContextInput{ExternalIP: true}, noHist(), noAnom(), p4))

	// Cooldown active — DENIED without RS computation
	pCool := defaultPolicy()
	vCool := mkVector("TS-RISK2-NEG-006",
		"Cooldown active: DENIED without executing risk function (RISK-007)",
		"acp:cap:data.read", "reports/Q1", "public", noCtx(), noHist(),
		AnomalyInput{CooldownActive: true}, pCool)
	vCool.Expected.Decision = "DENIED"
	vCool.Expected.DeniedReason = "COOLDOWN_ACTIVE"
	vCool.Expected.Factors = Factors{}
	vCool.Expected.RSRaw = 0
	vCool.Expected.RSFinal = 0
	vv = append(vv, vCool)

	// Anti-gaming: fragmented requests — Rule3 detects same pattern key
	vv = append(vv, mkVector("TS-RISK2-NEG-007",
		"Anti-gaming: Rule3 catches repeated same (agent, cap, resource) pattern. 3rd attempt triggers Rule3.",
		"acp:cap:financial.payment", "accounts/ACC-001", "restricted",
		noCtx(), noHist(), AnomalyInput{Rule3Count: 3}, p))

	// Anti-gaming: burst attempts — Rule1 triggers on high rate
	vv = append(vv, mkVector("TS-RISK2-NEG-008",
		"Anti-gaming: burst of 15 requests in 60s triggers Rule1 (+20)",
		"acp:cap:data.read", "reports/Q1", "public",
		noCtx(), noHist(), AnomalyInput{Rule1Count: 15}, p))

	// Anti-gaming: agent backs off rate — Rule1 stops triggering
	vv = append(vv, mkVector("TS-RISK2-NEG-009",
		"Anti-gaming: agent reduces rate to 9 req/60s. Rule1 no longer triggered (9 <= 10). RS=0.",
		"acp:cap:data.read", "reports/Q1", "public",
		noCtx(), noHist(), AnomalyInput{Rule1Count: 9}, p))

	// Rule2 exactly at threshold — triggered
	vv = append(vv, mkVector("TS-RISK2-NEG-010",
		"Rule2 exact threshold: count=3 = X=3 → triggered (≥X, not >X)",
		"acp:cap:data.read", "reports/Q1", "public",
		noCtx(), noHist(), AnomalyInput{Rule2Count: 3}, p))

	// Rule2 one below threshold — not triggered
	vv = append(vv, mkVector("TS-RISK2-NEG-011",
		"Rule2 one below threshold: count=2 < X=3 → not triggered",
		"acp:cap:data.read", "reports/Q1", "public",
		noCtx(), noHist(), AnomalyInput{Rule2Count: 2}, p))

	// RS cap at 100
	vv = append(vv, mkVector("TS-RISK2-NEG-012",
		"RS cap: all factors sum to 150 but rs_final must be capped at 100",
		"acp:cap:financial.payment", "accounts/ACC-001", "restricted",
		ContextInput{ExternalIP: true, OffHours: true},
		HistoryInput{RecentDenial: true},
		AnomalyInput{Rule1Count: 15, Rule2Count: 5, Rule3Count: 5}, p))

	// Unclassified resource → treated as sensitive (RISK-003)
	vv = append(vv, mkVector("TS-RISK2-NEG-013",
		"RISK-003: resource_class=unclassified → treated as sensitive (F_res=15). RS=50 → ESCALATED",
		"acp:cap:financial.payment", "accounts/ACC-001", "unclassified",
		noCtx(), noHist(), noAnom(), p))

	// Complex: write + critical + off_hours + denial_rate_high + Rule1 + Rule2
	vv = append(vv, mkVector("TS-RISK2-NEG-014",
		"Complex: write+critical+off_hours+denial_rate_high+Rule1+Rule2: RS=100 (cap) → DENIED",
		"acp:cap:data.write", "data/critical-store", "critical",
		ContextInput{OffHours: true},
		HistoryInput{DenialRateHigh: true},
		AnomalyInput{Rule1Count: 11, Rule2Count: 4}, p))

	// Custom policy: N=5 (stricter rate threshold)
	pStrict := defaultPolicy()
	pStrict.AnomalyRule1ThresholdN = 5
	pStrict.PolicyHash = "sha256:test-policy-v2-strict"
	vv = append(vv, mkVector("TS-RISK2-NEG-015",
		"Custom policy: N=5 (stricter). count=6 > N=5 → Rule1 triggered. Same input as POS-038 but different policy.",
		"acp:cap:data.read", "reports/Q1", "public",
		noCtx(), noHist(), AnomalyInput{Rule1Count: 6}, pStrict))

	return vv
}

// ─── Main ──────────────────────────────────────────────────────────────────────

func main() {
	outDir := flag.String("out", "../../compliance/test-vectors/risk-2.0/", "output directory")
	flag.Parse()

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("mkdir %s: %v", *outDir, err)
	}

	vectors := allVectors()

	for _, v := range vectors {
		data, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			log.Fatalf("marshal %s: %v", v.Meta.ID, err)
		}
		path := filepath.Join(*outDir, v.Meta.ID+".json")
		if err := os.WriteFile(path, data, 0644); err != nil {
			log.Fatalf("write %s: %v", path, err)
		}
	}

	fmt.Printf("Generated %d vectors in %s\n", len(vectors), *outDir)

	// Print summary
	byDecision := map[string]int{}
	for _, v := range vectors {
		byDecision[v.Expected.Decision]++
	}
	fmt.Printf("  APPROVED:  %d\n", byDecision["APPROVED"])
	fmt.Printf("  ESCALATED: %d\n", byDecision["ESCALATED"])
	fmt.Printf("  DENIED:    %d\n", byDecision["DENIED"])
}
