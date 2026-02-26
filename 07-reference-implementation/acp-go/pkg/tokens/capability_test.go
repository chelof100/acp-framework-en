package tokens_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	acpcrypto "github.com/chelof100/acp-framework/acp-go/pkg/crypto"
	"github.com/chelof100/acp-framework/acp-go/pkg/tokens"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

func freshNonce() string {
	b := make([]byte, 16)
	// Use a fixed nonce for test reproducibility; each test should use a unique one.
	return base64.RawURLEncoding.EncodeToString(b)
}

// signToken creates and signs a minimal valid token for testing.
// In production, tokens are signed by the institutional issuer, not the agent.
func signToken(t *testing.T, issuer *acpcrypto.AgentIdentity, tok *tokens.CapabilityToken) string {
	t.Helper()
	payload, _ := json.Marshal(tok)
	var m map[string]interface{}
	json.Unmarshal(payload, &m)
	delete(m, "sig")
	// Use sorted JSON as a simplified canonical form for tests.
	// Production code uses JCS via github.com/gowebpki/jcs.
	canonical, _ := json.Marshal(m)
	tok.Signature = issuer.Sign(canonical)
	j, _ := json.Marshal(tok)
	return string(j)
}

func validTok(issuer *acpcrypto.AgentIdentity) *tokens.CapabilityToken {
	now := time.Now().Unix()
	return &tokens.CapabilityToken{
		Version:    "1.0",
		Issuer:     acpcrypto.DeriveAgentID(issuer.PublicKey),
		Subject:    acpcrypto.DeriveAgentID(issuer.PublicKey),
		Cap:        []string{"acp:cap:financial.payment"},
		Resource:   "org.bank/accounts",
		IssuedAt:   now,
		Expiration: now + 3600,
		Nonce:      base64.RawURLEncoding.EncodeToString([]byte("validnonce12345a")),
		Deleg:      tokens.Delegation{Allowed: false, MaxDepth: 0},
		Constraints: map[string]interface{}{
			"max_amount_usd": float64(5000),
		},
	}
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestParseAndVerify_ValidToken(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer)
	tokJSON := signToken(t, issuer, tok)

	store := tokens.NewInMemoryNonceStore()
	opts := tokens.VerifyOptions{
		IssuerPublicKey: issuer.PublicKey,
		NonceStore:      store,
	}
	result, err := tokens.ParseAndVerify(tokJSON, opts)
	if err != nil {
		t.Fatalf("ParseAndVerify() unexpected error: %v", err)
	}
	if result.Subject != tok.Subject {
		t.Errorf("subject mismatch: got %s, want %s", result.Subject, tok.Subject)
	}
}

func TestParseAndVerify_CT001_InvalidJSON(t *testing.T) {
	opts := tokens.VerifyOptions{
		IssuerPublicKey: make([]byte, 32),
		NonceStore:      tokens.NewInMemoryNonceStore(),
	}
	_, err := tokens.ParseAndVerify("{not valid json", opts)
	assertCode(t, err, "CT-001")
}

func TestParseAndVerify_CT002_UnknownVersion(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer)
	tok.Version = "99.9"
	tok.Nonce = base64.RawURLEncoding.EncodeToString([]byte("versiontestnonce"))
	j := signToken(t, issuer, tok)

	opts := tokens.VerifyOptions{IssuerPublicKey: issuer.PublicKey, NonceStore: tokens.NewInMemoryNonceStore()}
	_, err := tokens.ParseAndVerify(j, opts)
	assertCode(t, err, "CT-002")
}

func TestParseAndVerify_CT003_Expired(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	now := time.Now().Unix()
	tok := validTok(issuer)
	tok.IssuedAt = now - 7200
	tok.Expiration = now - 3600 // expired 1 hour ago
	tok.Nonce = base64.RawURLEncoding.EncodeToString([]byte("expirednonce123a"))
	j := signToken(t, issuer, tok)

	opts := tokens.VerifyOptions{IssuerPublicKey: issuer.PublicKey, NonceStore: tokens.NewInMemoryNonceStore()}
	_, err := tokens.ParseAndVerify(j, opts)
	assertCode(t, err, "CT-003")
}

func TestParseAndVerify_CT004_IssuedInFuture(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	now := time.Now().Unix()
	tok := validTok(issuer)
	tok.IssuedAt = now + 9999
	tok.Expiration = now + 99999
	tok.Nonce = base64.RawURLEncoding.EncodeToString([]byte("futurenonce1234a"))
	j := signToken(t, issuer, tok)

	opts := tokens.VerifyOptions{IssuerPublicKey: issuer.PublicKey, NonceStore: tokens.NewInMemoryNonceStore()}
	_, err := tokens.ParseAndVerify(j, opts)
	assertCode(t, err, "CT-004")
}

func TestParseAndVerify_CT006_InvalidSignature(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	wrongIssuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer)
	tok.Nonce = base64.RawURLEncoding.EncodeToString([]byte("badsignonce1234a"))
	j := signToken(t, issuer, tok)

	// Verify with wrong public key → CT-006
	opts := tokens.VerifyOptions{IssuerPublicKey: wrongIssuer.PublicKey, NonceStore: tokens.NewInMemoryNonceStore()}
	_, err := tokens.ParseAndVerify(j, opts)
	assertCode(t, err, "CT-006")
}

func TestParseAndVerify_CT008_EmptyCapabilities(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer)
	tok.Cap = []string{}
	tok.Nonce = base64.RawURLEncoding.EncodeToString([]byte("nocapsnonce1234a"))
	j := signToken(t, issuer, tok)

	opts := tokens.VerifyOptions{IssuerPublicKey: issuer.PublicKey, NonceStore: tokens.NewInMemoryNonceStore()}
	_, err := tokens.ParseAndVerify(j, opts)
	assertCode(t, err, "CT-008")
}

func TestParseAndVerify_CT009_EmptyResource(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer)
	tok.Resource = ""
	tok.Nonce = base64.RawURLEncoding.EncodeToString([]byte("noresource12345a"))
	j := signToken(t, issuer, tok)

	opts := tokens.VerifyOptions{IssuerPublicKey: issuer.PublicKey, NonceStore: tokens.NewInMemoryNonceStore()}
	_, err := tokens.ParseAndVerify(j, opts)
	assertCode(t, err, "CT-009")
}

func TestParseAndVerify_CT012_NonceReplay(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer)
	tok.Nonce = base64.RawURLEncoding.EncodeToString([]byte("replaynonce1234a"))
	tokJSON := signToken(t, issuer, tok)

	store := tokens.NewInMemoryNonceStore()
	opts := tokens.VerifyOptions{IssuerPublicKey: issuer.PublicKey, NonceStore: store}

	// First use: OK.
	if _, err := tokens.ParseAndVerify(tokJSON, opts); err != nil {
		t.Fatalf("first use failed: %v", err)
	}

	// Second use: CT-012 replay.
	_, err := tokens.ParseAndVerify(tokJSON, opts)
	assertCode(t, err, "CT-012")
}

func TestComputeTokenHash_Deterministic(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer)
	j := signToken(t, issuer, tok)

	h1 := tokens.ComputeTokenHash(j)
	h2 := tokens.ComputeTokenHash(j)

	if h1 == "" {
		t.Fatal("ComputeTokenHash returned empty string")
	}
	if h1 != h2 {
		t.Error("ComputeTokenHash is not deterministic")
	}
}

// assertCode checks that err contains the given ACP error code.
func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", code)
	}
	if !contains(err.Error(), code) {
		t.Errorf("expected error code %q in: %q", code, err.Error())
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
