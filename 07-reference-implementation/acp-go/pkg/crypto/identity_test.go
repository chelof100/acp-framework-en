package crypto_test

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/chelof100/acp-framework/acp-go/pkg/crypto"
)

func TestGenerateIdentity(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity() error = %v", err)
	}
	if id == nil {
		t.Fatal("GenerateIdentity() returned nil")
	}
	if len(id.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("PrivateKey len = %d, want %d", len(id.PrivateKey), ed25519.PrivateKeySize)
	}
	if len(id.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("PublicKey len = %d, want %d", len(id.PublicKey), ed25519.PublicKeySize)
	}
}

func TestDeriveAgentID(t *testing.T) {
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}

	agentID := crypto.DeriveAgentID(id.PublicKey)

	if agentID == "" {
		t.Fatal("DeriveAgentID returned empty string")
	}
	if len(agentID) < 40 || len(agentID) > 50 {
		t.Errorf("AgentID length %d out of expected range [40,50]: %s", len(agentID), agentID)
	}

	// Deterministic: same key → same ID.
	agentID2 := crypto.DeriveAgentID(id.PublicKey)
	if agentID != agentID2 {
		t.Errorf("DeriveAgentID not deterministic: %s vs %s", agentID, agentID2)
	}
}

func TestDeriveAgentID_DifferentKeys(t *testing.T) {
	id1, _ := crypto.GenerateIdentity()
	id2, _ := crypto.GenerateIdentity()

	a1 := crypto.DeriveAgentID(id1.PublicKey)
	a2 := crypto.DeriveAgentID(id2.PublicKey)

	if a1 == a2 {
		t.Error("two different keys produced the same AgentID (collision)")
	}
}

func TestValidateAgentID(t *testing.T) {
	id, _ := crypto.GenerateIdentity()
	validID := crypto.DeriveAgentID(id.PublicKey)

	tests := []struct {
		name    string
		agentID string
		wantErr bool
	}{
		{"valid", validID, false},
		{"empty", "", true},
		{"too short", "abc", true},
		{"spaces", "abc def ghi jkl mno pqrs tuv", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := crypto.ValidateAgentID(tt.agentID)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAgentID(%q) error = %v, wantErr = %v", tt.agentID, err, tt.wantErr)
			}
		})
	}
}

func TestSignAndVerify(t *testing.T) {
	id, _ := crypto.GenerateIdentity()
	msg := []byte(`{"test":"value","num":42}`)

	sigB64 := id.Sign(msg)
	if sigB64 == "" {
		t.Fatal("Sign returned empty string")
	}
	// No padding in base64url.
	if strings.Contains(sigB64, "=") {
		t.Errorf("signature contains padding: %s", sigB64)
	}

	ok := crypto.Verify(id.PublicKey, msg, sigB64)
	if !ok {
		t.Error("Verify returned false for a valid signature")
	}
}

func TestVerify_TamperedMessage(t *testing.T) {
	id, _ := crypto.GenerateIdentity()
	msg := []byte(`{"test":"value"}`)
	sigB64 := id.Sign(msg)

	tampered := []byte(`{"test":"tampered"}`)
	ok := crypto.Verify(id.PublicKey, tampered, sigB64)
	if ok {
		t.Error("Verify returned true for tampered message")
	}
}

func TestVerify_WrongKey(t *testing.T) {
	id1, _ := crypto.GenerateIdentity()
	id2, _ := crypto.GenerateIdentity()
	msg := []byte(`{"test":"value"}`)
	sigB64 := id1.Sign(msg)

	ok := crypto.Verify(id2.PublicKey, msg, sigB64)
	if ok {
		t.Error("Verify returned true with wrong public key")
	}
}

func TestNewIdentityFromPrivateKey(t *testing.T) {
	id1, _ := crypto.GenerateIdentity()
	seed := id1.PrivateKey.Seed()

	id2, err := crypto.NewIdentityFromPrivateKey(seed)
	if err != nil {
		t.Fatalf("NewIdentityFromPrivateKey error = %v", err)
	}

	if crypto.DeriveAgentID(id1.PublicKey) != crypto.DeriveAgentID(id2.PublicKey) {
		t.Error("AgentIDs differ for same seed")
	}
}
