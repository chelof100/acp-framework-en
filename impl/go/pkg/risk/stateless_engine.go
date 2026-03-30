package risk

// StatelessEngine evaluates requests using only static base scoring,
// with no access to historical state, anomaly accumulation, or cooldown.
// Used as a baseline to demonstrate the structural necessity of stateful enforcement.
type StatelessEngine struct {
	policy PolicyConfig
}

func NewStatelessEngine(policy PolicyConfig) *StatelessEngine {
	return &StatelessEngine{policy: policy}
}

// Evaluate applies identical scoring and thresholds as ACP-RISK-2.0,
// but with a NullQuerier: F_anom is always 0, cooldown is never active.
// State is the only variable that differs from the full ACP engine.
func (s *StatelessEngine) Evaluate(req EvalRequest) (*EvalResult, error) {
	req.Policy = s.policy
	return Evaluate(req, &NullQuerier{})
}
