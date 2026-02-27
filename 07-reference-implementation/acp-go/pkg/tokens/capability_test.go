package tokens_test

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/gowebpki/jcs"

	acpcrypto "github.com/chelof100/acp-framework/acp-go/pkg/crypto"
	"github.com/chelof100/acp-framework/acp-go/pkg/tokens"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// signToken creates a properly signed token JSON for testing.
// Uses JCS (RFC 8785) — same canonical form that ParseAndVerify uses internally.
func signToken(t *testing.T, issuer *acpcrypto.AgentIdentity, tok *tokens.CapabilityToken) string {
	t.Helper()

	// Marshal to map, remove sig field, then JCS-canonicalize.
	data, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("signToken: marshal failed: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("signToken: unmarshal to map failed: %v", err)
	}
	delete(m, "sig")

	mBytes, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("signToken: JSON marshal for JCS failed: %v", err)
	}
	canonical, err := jcs.Transform(mBytes)
	if err != nil {
		t.Fatalf("signToken: JCS transform failed: %v", err)
	}
	// issuer.Sign internally computes SHA-256(canonical) before signing.
	// Do NOT pre-hash here — that would produce a double-hash mismatch.
	tok.Signature = issuer.Sign(canonical)

	j, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("signToken: final marshal failed: %v", err)
	}
	return string(j)
}

// validTok builds a minimal valid CapabilityToken for a given issuer.
func validTok(issuer *acpcrypto.AgentIdentity, nonce string) *tokens.CapabilityToken {
	now := time.Now().Unix()
	return &tokens.CapabilityToken{
		Version:    "1.0",
		Issuer:     acpcrypto.DeriveAgentID(issuer.PublicKey),
		Subject:    acpcrypto.DeriveAgentID(issuer.PublicKey),
		Cap:        []string{"acp:cap:financial.payment"},
		Resource:   "org.bank/accounts",
		IssuedAt:   now,
		Expiration: now + 3600,
		Nonce:      nonce,
		Deleg:      tokens.Delegation{Allowed: false, MaxDepth: 0},
		Constraints: map[string]interface{}{
			"max_amount_usd": float64(5000),
		},
	}
}

// verify is a convenience wrapper with sensible defaults for tests.
func verify(t *testing.T, tokJSON string, issuerPubKey []byte, store tokens.NonceStore) (*tokens.CapabilityToken, error) {
	t.Helper()
	return tokens.ParseAndVerify([]byte(tokJSON), issuerPubKey, tokens.VerificationRequest{
		NonceStore: store,
	})
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestParseAndVerify_ValidToken(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer, base64.RawURLEncoding.EncodeToString([]byte("validnonce12345a")))
	tokJSON := signToken(t, issuer, tok)

	store := tokens.NewInMemoryNonceStore()
	result, err := verify(t, tokJSON, issuer.PublicKey, store)
	if err != nil {
		t.Fatalf("ParseAndVerify() unexpected error: %v", err)
	}
	if result.Subject != tok.Subject {
		t.Errorf("subject mismatch: got %s, want %s", result.Subject, tok.Subject)
	}
}

// TestParseAndVerify_InvalidJSON verifies that malformed JSON returns an error.
// Production returns the raw json.Unmarshal error (no CT-xxx code).
func TestParseAndVerify_InvalidJSON(t *testing.T) {
	store := tokens.NewInMemoryNonceStore()
	_, err := verify(t, "{not valid json", make([]byte, 32), store)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

// TestParseAndVerify_CT001_UnsupportedVersion — ver != "1.0" → CT-001.
func TestParseAndVerify_CT001_UnsupportedVersion(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer, base64.RawURLEncoding.EncodeToString([]byte("versiontestnonce")))
	tok.Version = "99.9"
	j := signToken(t, issuer, tok)

	_, err := verify(t, j, issuer.PublicKey, tokens.NewInMemoryNonceStore())
	assertCode(t, err, "CT-001")
}

// TestParseAndVerify_CT002_InvalidSignature — wrong issuer public key → CT-002.
func TestParseAndVerify_CT002_InvalidSignature(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	wrongIssuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer, base64.RawURLEncoding.EncodeToString([]byte("badsignonce1234a")))
	j := signToken(t, issuer, tok)

	// Verify with wrong public key → CT-002.
	_, err := verify(t, j, wrongIssuer.PublicKey, tokens.NewInMemoryNonceStore())
	assertCode(t, err, "CT-002")
}

// TestParseAndVerify_CT003_Expired — exp in the past → CT-003.
func TestParseAndVerify_CT003_Expired(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	now := time.Now().Unix()
	tok := validTok(issuer, base64.RawURLEncoding.EncodeToString([]byte("expirednonce123a")))
	tok.IssuedAt = now - 7200
	tok.Expiration = now - 3600 // expired 1 hour ago
	j := signToken(t, issuer, tok)

	_, err := verify(t, j, issuer.PublicKey, tokens.NewInMemoryNonceStore())
	assertCode(t, err, "CT-003")
}

// TestParseAndVerify_CT004_IssuedInFuture — iat far in the future → CT-004.
func TestParseAndVerify_CT004_IssuedInFuture(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	now := time.Now().Unix()
	tok := validTok(issuer, base64.RawURLEncoding.EncodeToString([]byte("futurenonce1234a")))
	tok.IssuedAt = now + 9999
	tok.Expiration = now + 99999
	j := signToken(t, issuer, tok)

	_, err := verify(t, j, issuer.PublicKey, tokens.NewInMemoryNonceStore())
	assertCode(t, err, "CT-004")
}

// TestParseAndVerify_CT005_CapabilityNotPresent — requesting a cap not in the token → CT-005.
func TestParseAndVerify_CT005_CapabilityNotPresent(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer, base64.RawURLEncoding.EncodeToString([]byte("nocapnonce12345a")))
	j := signToken(t, issuer, tok)

	_, err := tokens.ParseAndVerify([]byte(j), issuer.PublicKey, tokens.VerificationRequest{
		RequestedCapability: "acp:cap:data.delete", // not in token
		NonceStore:          tokens.NewInMemoryNonceStore(),
	})
	assertCode(t, err, "CT-005")
}

// TestParseAndVerify_CT006_ResourceNotCovered — token resource does not cover requested resource → CT-006.
func TestParseAndVerify_CT006_ResourceNotCovered(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer, base64.RawURLEncoding.EncodeToString([]byte("noresource12345a")))
	tok.Resource = "org.bank/accounts/ACC-001" // narrow resource
	j := signToken(t, issuer, tok)

	_, err := tokens.ParseAndVerify([]byte(j), issuer.PublicKey, tokens.VerificationRequest{
		RequestedResource: "org.bank/accounts", // broader than token resource → not covered
		NonceStore:        tokens.NewInMemoryNonceStore(),
	})
	assertCode(t, err, "CT-006")
}

// TestParseAndVerify_CT012_EmptyCapArray — cap=[] → CT-012.
func TestParseAndVerify_CT012_EmptyCapabilities(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer, base64.RawURLEncoding.EncodeToString([]byte("nocapsnonce1234a")))
	tok.Cap = []string{}
	j := signToken(t, issuer, tok)

	_, err := verify(t, j, issuer.PublicKey, tokens.NewInMemoryNonceStore())
	assertCode(t, err, "CT-012")
}

// TestParseAndVerify_CT011_NonceReplay — second use of same nonce → CT-011.
func TestParseAndVerify_CT011_NonceReplay(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer, base64.RawURLEncoding.EncodeToString([]byte("replaynonce1234a")))
	tokJSON := signToken(t, issuer, tok)

	store := tokens.NewInMemoryNonceStore()

	// First use: OK.
	if _, err := verify(t, tokJSON, issuer.PublicKey, store); err != nil {
		t.Fatalf("first use failed: %v", err)
	}

	// Second use with same store → CT-011 (replay detected).
	_, err := verify(t, tokJSON, issuer.PublicKey, store)
	assertCode(t, err, "CT-011")
}

// TestComputeTokenHash_Deterministic — same input must always produce same hash.
func TestComputeTokenHash_Deterministic(t *testing.T) {
	issuer, _ := acpcrypto.GenerateIdentity()
	tok := validTok(issuer, base64.RawURLEncoding.EncodeToString([]byte("hashtest12345a__")))

	h1, err := tokens.ComputeTokenHash(tok)
	if err != nil {
		t.Fatalf("ComputeTokenHash returned error: %v", err)
	}
	h2, err := tokens.ComputeTokenHash(tok)
	if err != nil {
		t.Fatalf("ComputeTokenHash returned error: %v", err)
	}

	if h1 == "" {
		t.Fatal("ComputeTokenHash returned empty string")
	}
	if h1 != h2 {
		t.Error("ComputeTokenHash is not deterministic")
	}
}

// ─── Assertion helpers ────────────────────────────────────────────────────────

// assertCode checks that err contains the given ACP error code (e.g., "CT-001").
func assertCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", code)
	}
	if !containsStr(err.Error(), code) {
		t.Errorf("expected error code %q in: %q", code, err.Error())
	}
}

// containsStr reports whether s contains sub.
func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
