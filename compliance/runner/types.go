package main

// RunnerContext maps to risk.Context — all boolean environment signals.
type RunnerContext struct {
	ExternalIP      bool `json:"external_ip"`
	OffHours        bool `json:"off_hours"`
	NonBusinessDay  bool `json:"non_business_day"`
	GeoOutside      bool `json:"geo_outside"`
	TimestampDrift  bool `json:"timestamp_drift"`
	UntrustedDevice bool `json:"untrusted_device"`
}

// RunnerHistory maps to risk.History — all boolean behavioural signals.
type RunnerHistory struct {
	DenialRateHigh        bool `json:"denial_rate_high"`
	UnresolvedEscalations bool `json:"unresolved_escalations"`
	RecentDenial          bool `json:"recent_denial"`
	FreqAnomaly           bool `json:"freq_anomaly"`
	AmountNearLimit       bool `json:"amount_near_limit"`
	NoHistory             bool `json:"no_history"`
}

// RunnerRequest is the per-step input to the Backend.
// Matches risk.EvalRequest field-for-field (except Policy and Now, which are managed by the backend).
type RunnerRequest struct {
	AgentID       string        `json:"agent_id"`
	Capability    string        `json:"capability"`
	Resource      string        `json:"resource"`
	ResourceClass string        `json:"resource_class"` // "public" | "sensitive" | "restricted"
	Context       RunnerContext `json:"context"`
	History       RunnerHistory `json:"history"`
}

// Expected declares what a step must produce.
// RiskScore is optional (nil = skip validation). DeniedReason is only checked when non-empty.
type Expected struct {
	Decision     string `json:"decision"`
	RiskScore    *int   `json:"risk_score,omitempty"`
	DeniedReason string `json:"denied_reason,omitempty"`
}

// Step is one element of a TestCase — a request plus its expected outcome.
type Step struct {
	RunnerRequest
	Expected Expected `json:"expected"`
}

// TestCase is a sequence of steps sharing the same agent state.
// The backend is Reset() before the first step of each test case.
type TestCase struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Steps       []Step `json:"steps"`
}

// ACPResponse is the normalized output of a Backend.Evaluate call.
type ACPResponse struct {
	Decision     string `json:"decision"`
	RiskScore    int    `json:"risk_score"`
	DeniedReason string `json:"denied_reason,omitempty"`
}

// StepResult records the outcome of a single step.
type StepResult struct {
	Index    int         `json:"index"`
	Status   string      `json:"status"` // PASS | FAIL | ERROR
	Expected Expected    `json:"expected"`
	Got      ACPResponse `json:"got"`
	Message  string      `json:"message,omitempty"`
}

// TestCaseResult records the full outcome of a test case.
type TestCaseResult struct {
	ID      string       `json:"id"`
	Status  string       `json:"status"` // PASS | FAIL | ERROR
	Steps   []StepResult `json:"steps"`
	Message string       `json:"message,omitempty"`
}

// Report is the final JSON output of the runner.
type Report struct {
	Mode      string           `json:"mode"`
	Total     int              `json:"total"`
	Passed    int              `json:"passed"`
	Failed    int              `json:"failed"`
	Status    string           `json:"status"` // CONFORMANT | NON_CONFORMANT
	Timestamp string           `json:"timestamp"`
	TestCases []TestCaseResult `json:"test_cases"`
}
