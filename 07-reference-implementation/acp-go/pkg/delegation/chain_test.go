package delegation_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	acpcrypto "github.com/chelof100/acp-framework/acp-go/pkg/crypto"
	"github.com/chelof100/acp-framework/acp-go/pkg/delegation"
	"github.com/chelof100/acp-framework/acp-go/pkg/tokens"
)

// hashToken returns a base64url SHA-256 hash of the token JSON
// for use as parent_hash in delegation chains.
func hashToken(tok *tokens.CapabilityToken) string {
	b, _ := json.Marshal(tok)
	h := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func makeToken(issuer *acpcrypto.AgentIdentity, subject string, caps []string, resource string, expOffset int64, delegAllowed bool, maxDepth int, parentHash *string) *tokens.CapabilityToken {
	now := time.Now().Unix()
	return &tokens.CapabilityToken{
		Version:    "1.0",
		Issuer:     acpcrypto.DeriveAgentID(issuer.PublicKey),
		Subject:    subject,
		Cap:        caps,
		Resource:   resource,
		IssuedAt:   now,
		Expiration: now + expOffset,
		Nonce:      "test-nonce-" + subject[:4],
		Deleg:      tokens.Delegation{Allowed: delegAllowed, MaxDepth: maxDepth},
		ParentHash: parentHash,
	}
}

func TestValidate_RootToken(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	agent := acpcrypto.DeriveAgentID(issuer.PublicKey)

	root := makeToken(issuer, agent, []string{"acp:cap:financial.payment"}, "org.bank/accounts", 3600, false, 0, nil)
	c := delegation.NewChain([]*tokens.CapabilityToken{root})

	if err := c.Validate(); err != nil {
		t.Errorf("root token chain validation failed: %v", err)
	}
}

func TestValidate_ValidDelegation(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	agent1ID := acpcrypto.DeriveAgentID(issuer.PublicKey)

	agent2, _ := acpcrypto.GenerateIdentity()
	agent2ID := acpcrypto.DeriveAgentID(agent2.PublicKey)

	root := makeToken(issuer, agent1ID, []string{"acp:cap:financial.payment"}, "org.bank/accounts", 3600, true, 2, nil)
	rootHash := hashToken(root)
	delegated := makeToken(issuer, agent2ID, []string{"acp:cap:financial.payment"}, "org.bank/accounts/ACC-001", 1800, false, 0, &rootHash)

	c := delegation.NewChain([]*tokens.CapabilityToken{root, delegated})
	if err := c.Validate(); err != nil {
		t.Errorf("valid delegation chain failed: %v", err)
	}
}

func TestValidate_CapabilityEscalation_Rejected(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	agent1ID := acpcrypto.DeriveAgentID(issuer.PublicKey)
	agent2, _ := acpcrypto.GenerateIdentity()
	agent2ID := acpcrypto.DeriveAgentID(agent2.PublicKey)

	root := makeToken(issuer, agent1ID, []string{"acp:cap:data.read"}, "org.bank/accounts", 3600, true, 2, nil)
	rootHash := hashToken(root)
	// Delegated claims cap NOT in parent.
	delegated := makeToken(issuer, agent2ID, []string{"acp:cap:financial.payment"}, "org.bank/accounts", 1800, false, 0, &rootHash)

	c := delegation.NewChain([]*tokens.CapabilityToken{root, delegated})
	if err := c.Validate(); err == nil {
		t.Error("capability escalation should be rejected")
	}
}

func TestValidate_ResourceEscalation_Rejected(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	agent1ID := acpcrypto.DeriveAgentID(issuer.PublicKey)
	agent2, _ := acpcrypto.GenerateIdentity()
	agent2ID := acpcrypto.DeriveAgentID(agent2.PublicKey)

	root := makeToken(issuer, agent1ID, []string{"acp:cap:financial.payment"}, "org.bank/accounts/ACC-001", 3600, true, 2, nil)
	rootHash := hashToken(root)
	// Delegated claims BROADER resource than parent (escalation).
	delegated := makeToken(issuer, agent2ID, []string{"acp:cap:financial.payment"}, "org.bank/accounts", 1800, false, 0, &rootHash)

	c := delegation.NewChain([]*tokens.CapabilityToken{root, delegated})
	if err := c.Validate(); err == nil {
		t.Error("resource escalation should be rejected")
	}
}

func TestValidate_ExpiryEscalation_Rejected(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	agent1ID := acpcrypto.DeriveAgentID(issuer.PublicKey)
	agent2, _ := acpcrypto.GenerateIdentity()
	agent2ID := acpcrypto.DeriveAgentID(agent2.PublicKey)

	root := makeToken(issuer, agent1ID, []string{"acp:cap:financial.payment"}, "org.bank/accounts", 1800, true, 2, nil)
	rootHash := hashToken(root)
	// Delegated expires AFTER parent.
	delegated := makeToken(issuer, agent2ID, []string{"acp:cap:financial.payment"}, "org.bank/accounts", 9999, false, 0, &rootHash)

	c := delegation.NewChain([]*tokens.CapabilityToken{root, delegated})
	if err := c.Validate(); err == nil {
		t.Error("expiry escalation (delegated exp > parent exp) should be rejected")
	}
}

func TestValidate_MaxDepthExhausted_Rejected(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	agentID := acpcrypto.DeriveAgentID(issuer.PublicKey)

	root := makeToken(issuer, agentID, []string{"acp:cap:financial.payment"}, "org.bank/accounts", 3600, true, 0, nil)
	rootHash := hashToken(root)
	// max_depth=0 means no further delegation allowed.
	delegated := makeToken(issuer, agentID, []string{"acp:cap:financial.payment"}, "org.bank/accounts", 1800, false, 0, &rootHash)

	c := delegation.NewChain([]*tokens.CapabilityToken{root, delegated})
	if err := c.Validate(); err == nil {
		t.Error("delegation from token with max_depth=0 should be rejected")
	}
}

func TestValidate_AbsoluteDepthLimit(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()

	// Build a chain of 10 tokens — exceeds MaxDelegationDepth=8.
	chain := make([]*tokens.CapabilityToken, 10)
	for i := 0; i < 10; i++ {
		agent, _ := acpcrypto.GenerateIdentity()
		agentID := acpcrypto.DeriveAgentID(agent.PublicKey)
		var parentHash *string
		if i > 0 {
			h := hashToken(chain[i-1])
			parentHash = &h
		}
		chain[i] = makeToken(issuer, agentID, []string{"acp:cap:financial.payment"}, "org.bank/accounts", 3600, true, 8, parentHash)
	}

	c := delegation.NewChain(chain)
	if err := c.Validate(); err == nil {
		t.Error("chain of 10 tokens should exceed MaxDelegationDepth=8 and be rejected")
	}
}

func TestNewChain_EmptyChain_Rejected(t *testing.T) {
	c := delegation.NewChain([]*tokens.CapabilityToken{})
	if err := c.Validate(); err == nil {
		t.Error("empty chain should be rejected")
	}
}
