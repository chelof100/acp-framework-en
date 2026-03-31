// Package risk implements the ACP-RISK deterministic risk assessment engine.
//
// v1.0 API (Assess/Request/Assessment) is preserved unchanged for backward compatibility.
// v2.0 API (Evaluate/EvalRequest/EvalResult) adds F_anom (3 deterministic rules),
// Cooldown mechanism, LedgerQuerier interface, and full factor breakdown per
// ACP-RISK-2.0 specification.
// v3.0 (ACP-RISK-3.0): Rule 1 redefined to use context-scoped CountPattern,
// eliminating cross-context state-mixing vulnerability.
package risk

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// ── ACP-RISK-1.0 API (preserved for backward compatibility) ──────────────────

// Level represents a risk classification.
type Level int

const (
	LevelLow      Level = iota // Routine operations, read-only, low-value resources
	LevelMedium                // Write operations, moderate-value resources
	LevelHigh                  // Financial, sensitive PII, high-value resources
	LevelCritical              // Irreversible or high-impact financial transactions
)

// String returns the level name for logging and API responses.
func (l Level) String() string {
	switch l {
	case LevelLow:
		return "low"
	case LevelMedium:
		return "medium"
	case LevelHigh:
		return "high"
	case LevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Request represents an authorization request for risk assessment.
type Request struct {
	AgentID    string
	Capability string
	Resource   string
	Amount     *float64
}

// Assessment is the output of the v1.0 risk engine.
type Assessment struct {
	Level       Level
	Score       int
	RequiresMFA bool
	Approved    bool
}

const thresholdMFA = 60
const thresholdDeny = 90

// Assess computes a deterministic risk score (v1.0 API).
func Assess(req Request) Assessment {
	score := baseCapabilityScore(req.Capability)
	score += resourceScopeScore(req.Resource)
	if req.Amount != nil {
		score += amountScore(*req.Amount)
	}
	if score > 100 {
		score = 100
	}
	level := scoreToLevel(score)
	return Assessment{
		Level:       level,
		Score:       score,
		RequiresMFA: score >= thresholdMFA,
		Approved:    score < thresholdDeny,
	}
}

func baseCapabilityScore(cap string) int {
	switch {
	case strings.HasPrefix(cap, "acp:cap:financial."):
		return 50
	case strings.HasPrefix(cap, "acp:cap:data.write"):
		return 30
	case strings.HasPrefix(cap, "acp:cap:data.read"):
		return 10
	case strings.HasPrefix(cap, "acp:cap:system."):
		return 40
	default:
		return 20
	}
}

func resourceScopeScore(resource string) int {
	parts := strings.Split(resource, "/")
	switch len(parts) {
	case 1:
		return 20
	case 2:
		return 10
	case 3:
		return 5
	default:
		return 0
	}
}

func amountScore(amount float64) int {
	switch {
	case amount > 100000:
		return 30
	case amount > 10000:
		return 20
	case amount > 1000:
		return 10
	default:
		return 0
	}
}

func scoreToLevel(score int) Level {
	switch {
	case score >= 75:
		return LevelCritical
	case score >= 50:
		return LevelHigh
	case score >= 25:
		return LevelMedium
	default:
		return LevelLow
	}
}

// ── ACP-RISK-2.0 API ─────────────────────────────────────────────────────────

// Decision represents an authorization decision.
type Decision string

const (
	APPROVED  Decision = "APPROVED"
	ESCALATED Decision = "ESCALATED"
	DENIED    Decision = "DENIED"
)

// AutonomyLevel is the agent's configured autonomy level (0–4).
type AutonomyLevel int

// ResourceClass categorizes the sensitivity of the target resource.
type ResourceClass string

const (
	ResourcePublic     ResourceClass = "public"
	ResourceSensitive  ResourceClass = "sensitive"
	ResourceRestricted ResourceClass = "restricted"
)

// Context carries environmental signals for F_ctx.
type Context struct {
	ExternalIP      bool `json:"external_ip"`
	OffHours        bool `json:"off_hours"`
	NonBusinessDay  bool `json:"non_business_day"`
	GeoOutside      bool `json:"geo_outside"`
	TimestampDrift  bool `json:"timestamp_drift"`
	UntrustedDevice bool `json:"untrusted_device"`
}

// History carries behavioural history signals for F_hist.
type History struct {
	DenialRateHigh         bool `json:"denial_rate_high"`
	UnresolvedEscalations  bool `json:"unresolved_escalations"`
	RecentDenial           bool `json:"recent_denial"`
	FreqAnomaly            bool `json:"freq_anomaly"`
	AmountNearLimit        bool `json:"amount_near_limit"`
	NoHistory              bool `json:"no_history"`
}

// AnomalyIn carries pre-computed anomaly rule counts and cooldown state.
// When using InMemoryQuerier, pass zero values and let Evaluate derive them.
type AnomalyIn struct {
	Rule1Count     int  `json:"rule1_count"`
	Rule2Count     int  `json:"rule2_count"`
	Rule3Count     int  `json:"rule3_count"`
	CooldownActive bool `json:"cooldown_active"`
}

// PolicyConfig holds all configurable thresholds for ACP-RISK-2.0.
// See ACP-RISK-2.0 Appendix A for parameter semantics.
type PolicyConfig struct {
	AutonomyLevel          int    // 0–4
	ApprovedMax            int    // RS ≤ ApprovedMax → APPROVED
	EscalatedMax           int    // RS ≤ EscalatedMax → ESCALATED; else DENIED
	AnomalyRule1ThresholdN int    // Rule 1 (RISK-3.0): context-scoped pattern count in 60s > N → +20
	AnomalyRule2ThresholdX int    // Rule 2: denial count in 24h ≥ X → +15
	AnomalyRule3ThresholdY int    // Rule 3: pattern count in 5min ≥ Y → +15
	CooldownTriggerDenials int    // Denials in 10min to trigger cooldown
	CooldownPeriodSeconds  int    // Duration of cooldown block in seconds
	PolicyHash             string // SHA-256 reference for this policy config
}

// DefaultPolicyConfig returns the reference policy configuration from ACP-RISK-2.0 §Appendix A.
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		AutonomyLevel:          2,
		ApprovedMax:            39,
		EscalatedMax:           69,
		AnomalyRule1ThresholdN: 10,
		AnomalyRule2ThresholdX: 3,
		AnomalyRule3ThresholdY: 3,
		CooldownTriggerDenials: 3,
		CooldownPeriodSeconds:  300,
		PolicyHash:             "sha256:test-policy-v1-default",
	}
}

// Factors is the full factor breakdown for forensic reproducibility (ACP-RISK-2.0 §6).
type Factors struct {
	Base     int `json:"base"`
	Context  int `json:"context"`
	History  int `json:"history"`
	Resource int `json:"resource"`
	Anomaly  int `json:"anomaly"`
}

// AnomalyDetail records which F_anom rules triggered.
type AnomalyDetail struct {
	Rule1Triggered bool `json:"rule1_triggered"`
	Rule2Triggered bool `json:"rule2_triggered"`
	Rule3Triggered bool `json:"rule3_triggered"`
}

// EvalRequest is the full input to ACP-RISK-2.0 Evaluate.
type EvalRequest struct {
	AgentID       string
	Capability    string
	Resource      string
	ResourceClass ResourceClass
	Context       Context
	History       History
	Anomaly       AnomalyIn
	Policy        PolicyConfig
	Now           time.Time
}

// EvalResult is the full output of ACP-RISK-2.0 Evaluate.
type EvalResult struct {
	RSRaw        int
	RSFinal      int
	Decision     Decision
	DeniedReason string
	Factors      Factors
	AnomalyDetail AnomalyDetail
	PolicyHash   string
}

// LedgerQuerier provides read access to ledger state needed by F_anom and Cooldown.
// Implementations MUST be fail-closed: if unavailable, Evaluate returns an error
// (RISK-008). Use InMemoryQuerier for tests and demonstrations.
type LedgerQuerier interface {
	// CountRequests returns the number of requests by agentID in the sliding window ending at now.
	CountRequests(agentID string, window time.Duration, now time.Time) (int, error)
	// CountDenials returns the number of DENIED decisions for agentID since cutoff.
	CountDenials(agentID string, since time.Time) (int, error)
	// CountPattern returns the number of times pattern_key appeared since cutoff.
	CountPattern(patternKey string, since time.Time) (int, error)
	// CooldownActive returns true if agentID is currently in cooldown at now.
	CooldownActive(agentID string, now time.Time) bool
	// CooldownUntil returns when the cooldown expires (zero if not active).
	CooldownUntil(agentID string) time.Time
}

// ── Base scores (ACP-RISK-2.0 §3.1) ─────────────────────────────────────────

func capabilityBase(cap string) int {
	switch {
	case strings.HasPrefix(cap, "acp:cap:admin."):
		return 60
	case strings.HasPrefix(cap, "acp:cap:financial."):
		return 35
	case strings.HasPrefix(cap, "acp:cap:data.write"):
		return 10
	case strings.HasPrefix(cap, "acp:cap:data.read"):
		return 0
	default:
		return 20
	}
}

func resourceScore(rc ResourceClass) int {
	switch rc {
	case ResourceRestricted:
		return 45
	case ResourceSensitive:
		return 15
	default: // public
		return 0
	}
}

// contextScore computes F_ctx from environment signals (ACP-RISK-2.0 §3.2).
func contextScore(ctx Context) int {
	score := 0
	if ctx.ExternalIP {
		score += 20
	}
	if ctx.OffHours {
		score += 15
	}
	if ctx.NonBusinessDay {
		score += 10
	}
	if ctx.GeoOutside {
		score += 15
	}
	if ctx.TimestampDrift {
		score += 10
	}
	if ctx.UntrustedDevice {
		score += 10
	}
	return score
}

// historyScore computes F_hist from behavioural history (ACP-RISK-2.0 §3.3).
func historyScore(h History) int {
	score := 0
	if h.RecentDenial {
		score += 20
	}
	if h.DenialRateHigh {
		score += 15
	}
	if h.FreqAnomaly {
		score += 15
	}
	if h.UnresolvedEscalations {
		score += 10
	}
	if h.AmountNearLimit {
		score += 10
	}
	if h.NoHistory {
		score += 5
	}
	return score
}

// PatternKey returns the 32-hex-character pattern key for F_anom Rule 3.
// key = SHA-256(agentID || "|" || capability || "|" || resource)[:32]
func PatternKey(agentID, capability, resource string) string {
	h := sha256.Sum256([]byte(agentID + "|" + capability + "|" + resource))
	return fmt.Sprintf("%x", h[:16]) // 32 hex chars = first 16 bytes
}

// anomalyScore computes F_anom using the LedgerQuerier (ACP-RISK-2.0 §3.4).
// Returns (score, detail, error). Error signals unavailable querier (RISK-008).
func anomalyScore(req EvalRequest, querier LedgerQuerier) (int, AnomalyDetail, error) {
	if querier == nil {
		return 0, AnomalyDetail{}, errors.New("RISK-008: LedgerQuerier unavailable (nil) — fail-closed")
	}

	now := req.Now
	detail := AnomalyDetail{}
	score := 0

	// ACP-RISK-3.0: context key precomputed — shared by Rule 1 and Rule 3.
	// Rule 1 is redefined to operate over context-scoped pattern counts,
	// eliminating cross-context state-mixing (see §state-mixing).
	// Global denial history (Rule 2) remains agent-scoped.
	patKey := PatternKey(req.AgentID, req.Capability, req.Resource)

	// Rule 1: context-scoped rate — count(pattern_key, sliding 60s) > N → +20
	// ACP-RISK-3.0: scoped to interaction context, not agent-global.
	count1, err := querier.CountPattern(patKey, now.Add(-60*time.Second))
	if err != nil {
		return 0, AnomalyDetail{}, fmt.Errorf("RISK-008: Rule1 query failed: %w", err)
	}
	if count1 > req.Policy.AnomalyRule1ThresholdN {
		detail.Rule1Triggered = true
		score += 20
	}

	// Rule 2: recent denials — count(DENIED[agentID], last 24h) ≥ X → +15
	// Global (agent-scoped): cross-context denial history is a valid signal.
	count2, err := querier.CountDenials(req.AgentID, now.Add(-24*time.Hour))
	if err != nil {
		return 0, AnomalyDetail{}, fmt.Errorf("RISK-008: Rule2 query failed: %w", err)
	}
	if count2 >= req.Policy.AnomalyRule2ThresholdX {
		detail.Rule2Triggered = true
		score += 15
	}

	// Rule 3: repeated pattern — count(pattern_key, last 5min) ≥ Y → +15
	// Unchanged: already context-scoped via PatternKey.
	count3, err := querier.CountPattern(patKey, now.Add(-5*time.Minute))
	if err != nil {
		return 0, AnomalyDetail{}, fmt.Errorf("RISK-008: Rule3 query failed: %w", err)
	}
	if count3 >= req.Policy.AnomalyRule3ThresholdY {
		detail.Rule3Triggered = true
		score += 15
	}

	return score, detail, nil
}

// Evaluate runs the full ACP-RISK-2.0 evaluation pipeline.
//
// Evaluation order:
//  1. Autonomy level 0 → immediate DENIED (RISK-006)
//  2. Cooldown active → immediate DENIED with DeniedReason="COOLDOWN_ACTIVE" (RISK-007)
//  3. Compute RS = min(100, B + F_ctx + F_hist + F_res + F_anom)
//  4. Apply autonomy-level thresholds → APPROVED / ESCALATED / DENIED
//
// Returns error only on querier unavailability (fail-closed, RISK-008).
func Evaluate(req EvalRequest, querier LedgerQuerier) (*EvalResult, error) {
	if req.Now.IsZero() {
		req.Now = time.Now()
	}

	// Step 1: Autonomy level 0 — always DENIED without executing risk function.
	if req.Policy.AutonomyLevel == 0 {
		return &EvalResult{
			RSRaw:        0,
			RSFinal:      0,
			Decision:     DENIED,
			DeniedReason: "AUTONOMY_LEVEL_0",
			Factors:      Factors{},
			AnomalyDetail: AnomalyDetail{},
			PolicyHash:   req.Policy.PolicyHash,
		}, nil
	}

	// Step 2: Cooldown check (before risk function).
	if querier != nil && querier.CooldownActive(req.AgentID, req.Now) {
		return &EvalResult{
			RSRaw:        0,
			RSFinal:      0,
			Decision:     DENIED,
			DeniedReason: "COOLDOWN_ACTIVE",
			Factors:      Factors{},
			AnomalyDetail: AnomalyDetail{},
			PolicyHash:   req.Policy.PolicyHash,
		}, nil
	}

	// Step 3: Compute RS = min(100, B + F_ctx + F_hist + F_res + F_anom)
	fBase := capabilityBase(req.Capability)
	fCtx := contextScore(req.Context)
	fHist := historyScore(req.History)
	fRes := resourceScore(req.ResourceClass)

	fAnom, detail, err := anomalyScore(req, querier)
	if err != nil {
		return nil, err
	}

	rsRaw := fBase + fCtx + fHist + fRes + fAnom
	rsFinal := rsRaw
	if rsFinal > 100 {
		rsFinal = 100
	}

	factors := Factors{
		Base:     fBase,
		Context:  fCtx,
		History:  fHist,
		Resource: fRes,
		Anomaly:  fAnom,
	}

	// Step 4: Apply thresholds per autonomy level.
	decision := applyThresholds(rsFinal, req.Policy)

	return &EvalResult{
		RSRaw:        rsRaw,
		RSFinal:      rsFinal,
		Decision:     decision,
		Factors:      factors,
		AnomalyDetail: detail,
		PolicyHash:   req.Policy.PolicyHash,
	}, nil
}

// applyThresholds maps RS to APPROVED/ESCALATED/DENIED based on autonomy level.
func applyThresholds(rs int, policy PolicyConfig) Decision {
	// Autonomy level 1: no autonomous approvals — always ESCALATED or DENIED.
	if policy.AutonomyLevel == 1 {
		if rs <= policy.EscalatedMax {
			return ESCALATED
		}
		return DENIED
	}
	// Levels 2–4: standard threshold ladder.
	if rs <= policy.ApprovedMax {
		return APPROVED
	}
	if rs <= policy.EscalatedMax {
		return ESCALATED
	}
	return DENIED
}

// ShouldEnterCooldown checks whether agentID has triggered the cooldown threshold.
// Returns (true, nil) if the agent should enter cooldown, (false, nil) if not,
// or (false, error) if the querier is unavailable.
func ShouldEnterCooldown(agentID string, policy PolicyConfig, querier LedgerQuerier, now time.Time) (bool, error) {
	if querier == nil {
		return false, errors.New("RISK-008: LedgerQuerier unavailable (nil)")
	}
	// Already in cooldown — no need to re-trigger.
	if querier.CooldownActive(agentID, now) {
		return false, nil
	}
	cutoff := now.Add(-10 * time.Minute)
	count, err := querier.CountDenials(agentID, cutoff)
	if err != nil {
		return false, fmt.Errorf("RISK-008: cooldown check failed: %w", err)
	}
	return count >= policy.CooldownTriggerDenials, nil
}

// ── InMemoryQuerier — reference implementation for tests and demos ────────────

// InMemoryQuerier is a thread-safe in-memory implementation of LedgerQuerier.
// All state is stored in slices/maps; no external dependencies required.
type InMemoryQuerier struct {
	mu       sync.Mutex
	requests map[string][]time.Time // agentID → request timestamps
	denials  map[string][]time.Time // agentID → denial timestamps
	patterns map[string][]time.Time // patternKey → timestamps
	cooldown map[string]time.Time   // agentID → cooldown expiry
}

// NewInMemoryQuerier returns a fresh InMemoryQuerier.
func NewInMemoryQuerier() *InMemoryQuerier {
	return &InMemoryQuerier{
		requests: make(map[string][]time.Time),
		denials:  make(map[string][]time.Time),
		patterns: make(map[string][]time.Time),
		cooldown: make(map[string]time.Time),
	}
}

// AddRequest records a request timestamp for agentID.
func (q *InMemoryQuerier) AddRequest(agentID string, t time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.requests[agentID] = append(q.requests[agentID], t)
}

// AddDenial records a denial timestamp for agentID.
func (q *InMemoryQuerier) AddDenial(agentID string, t time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.denials[agentID] = append(q.denials[agentID], t)
}

// AddPattern records a pattern hit timestamp for patternKey.
func (q *InMemoryQuerier) AddPattern(patternKey string, t time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.patterns[patternKey] = append(q.patterns[patternKey], t)
}

// SetCooldown sets agentID into cooldown until the given time.
func (q *InMemoryQuerier) SetCooldown(agentID string, until time.Time) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.cooldown[agentID] = until
}

// CountRequests returns the count of requests in the sliding window ending at now.
func (q *InMemoryQuerier) CountRequests(agentID string, window time.Duration, now time.Time) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	cutoff := now.Add(-window)
	count := 0
	for _, t := range q.requests[agentID] {
		if !t.Before(cutoff) {
			count++
		}
	}
	return count, nil
}

// CountDenials returns the count of denials since the given cutoff time.
func (q *InMemoryQuerier) CountDenials(agentID string, since time.Time) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	count := 0
	for _, t := range q.denials[agentID] {
		if !t.Before(since) {
			count++
		}
	}
	return count, nil
}

// CountPattern returns the count of pattern hits since the given cutoff time.
func (q *InMemoryQuerier) CountPattern(patternKey string, since time.Time) (int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	count := 0
	for _, t := range q.patterns[patternKey] {
		if !t.Before(since) {
			count++
		}
	}
	return count, nil
}

// CooldownActive returns true if agentID is in cooldown at the given time.
func (q *InMemoryQuerier) CooldownActive(agentID string, now time.Time) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	until, ok := q.cooldown[agentID]
	return ok && now.Before(until)
}

// CooldownUntil returns the cooldown expiry time for agentID (zero if not in cooldown).
func (q *InMemoryQuerier) CooldownUntil(agentID string) time.Time {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.cooldown[agentID]
}
