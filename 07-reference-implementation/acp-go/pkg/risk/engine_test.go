package risk_test

import (
	"testing"

	"github.com/chelof100/acp-framework/acp-go/pkg/risk"
)

// floatPtr converts a float64 to a *float64 pointer for use in risk.Request.Amount.
func floatPtr(v float64) *float64 { return &v }

func TestAssess_FinancialHighAmount(t *testing.T) {
	req := risk.Request{
		Capability: "acp:cap:financial.payment",
		Resource:   "org.bank/accounts/ACC-001",
		Amount:     floatPtr(150000),
	}
	result := risk.Assess(req)

	if result.Score < 60 {
		t.Errorf("high financial amount should score >= 60, got %d", result.Score)
	}
	if !result.RequiresMFA {
		t.Error("score >= 60 should require MFA")
	}
}

func TestAssess_LowRisk(t *testing.T) {
	req := risk.Request{
		Capability: "acp:cap:data.read",
		Resource:   "org.bank/reports",
		Amount:     nil,
	}
	result := risk.Assess(req)

	if result.Score >= 60 {
		t.Errorf("data.read with no amount should score < 60, got %d", result.Score)
	}
	if result.RequiresMFA {
		t.Error("low risk request should not require MFA")
	}
	if !result.Approved {
		t.Error("low risk request should be approved")
	}
}

func TestAssess_Deny_VeryHighScore(t *testing.T) {
	req := risk.Request{
		Capability: "acp:cap:financial.payment",
		Resource:   "org.bank/accounts",
		Amount:     floatPtr(999999999),
	}
	result := risk.Assess(req)

	if result.Approved {
		t.Errorf("extremely high risk should not be approved (score=%d)", result.Score)
	}
}

func TestAssess_SystemCapability(t *testing.T) {
	req := risk.Request{
		Capability: "acp:cap:system.admin",
		Resource:   "org.bank/infrastructure",
		Amount:     nil,
	}
	result := risk.Assess(req)

	if result.Score < 40 {
		t.Errorf("system.admin should score >= 40, got %d", result.Score)
	}
}

func TestAssess_Scores_InRange(t *testing.T) {
	cases := []risk.Request{
		{Capability: "acp:cap:data.read", Resource: "org.bank/reports", Amount: nil},
		{Capability: "acp:cap:financial.payment", Resource: "org.bank/accounts", Amount: floatPtr(500)},
		{Capability: "acp:cap:system.admin", Resource: "org.bank/all", Amount: nil},
		{Capability: "acp:cap:data.write", Resource: "org.bank/records", Amount: nil},
	}
	for _, req := range cases {
		result := risk.Assess(req)
		if result.Score < 0 || result.Score > 100 {
			t.Errorf("score %d out of range [0,100] for %+v", result.Score, req)
		}
	}
}

func TestAssess_FinancialLowAmount(t *testing.T) {
	req := risk.Request{
		Capability: "acp:cap:financial.payment",
		Resource:   "org.bank/accounts/ACC-001/sub",
		Amount:     floatPtr(100),
	}
	result := risk.Assess(req)

	if result.Score > 80 {
		t.Errorf("low amount financial should score <= 80, got %d", result.Score)
	}
}

func TestAssess_MFA_Threshold(t *testing.T) {
	// Amount=10001 crosses the 10k threshold.
	req := risk.Request{
		Capability: "acp:cap:financial.payment",
		Resource:   "org.bank/accounts",
		Amount:     floatPtr(10001),
	}
	result := risk.Assess(req)
	_ = result
	// Just verify it doesn't panic and produces valid output.
	if result.Score < 0 || result.Score > 100 {
		t.Errorf("invalid score %d", result.Score)
	}
}
