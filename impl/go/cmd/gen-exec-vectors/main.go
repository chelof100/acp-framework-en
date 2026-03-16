// Command gen-exec-vectors generates compliance/test-vectors/TS-EXEC-*.json.
//
// Produces 2 positive and 7 negative test vectors covering ACP-EXEC-1.0
// token verification (EXEC-001 through EXEC-007).
// Uses the same RFC 8037 test key A as gen-ledger-vectors.
//
// Run from the impl/go module root:
//
//	go run ./cmd/gen-exec-vectors <output_dir>
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chelof100/acp-framework/acp-go/pkg/execution"
	"github.com/gowebpki/jcs"
)

// RFC 8037 test key A — same seed as gen-ledger-vectors.
const testKeySeedHex = "9d61b19deffd59985ba34a442fa1c54cd044c9c565b66f2699171d66c9682252"

// Fixed timestamps — ensures reproducible vectors.
// issuedAt = 2026-03-16T00:00:00Z, expiresAt = issuedAt + 60
const issuedAt int64 = 1773993600
const expiresAt int64 = issuedAt + 60

// verifyAt is within the valid window.
const verifyAt int64 = issuedAt + 30

// verifyAtExpired is after the window.
const verifyAtExpired int64 = issuedAt + 120

// ─── Test Vector Schema ───────────────────────────────────────────────────────

type TestVector struct {
	Meta     VectorMeta     `json:"meta"`
	Input    VectorInput    `json:"input"`
	Expected VectorExpected `json:"expected"`
}

type VectorMeta struct {
	ID               string `json:"id"`
	Layer            string `json:"layer"`
	Severity         string `json:"severity"`
	ACPVersion       string `json:"acp_version"`
	ConformanceLevel string `json:"conformance_level"`
	Description      string `json:"description"`
}

type VectorInput struct {
	InstitutionPublicKey string         `json:"institution_public_key"`
	Token                map[string]any `json:"token"`
	VerifyAt             int64          `json:"verify_at"`
	ExpectedAgentID      string         `json:"expected_agent_id,omitempty"`
	ExpectedResource     string         `json:"expected_resource,omitempty"`
	ExpectedParamsHash   string         `json:"expected_params_hash,omitempty"`
}

type VectorExpected struct {
	Decision  string  `json:"decision"`
	ErrorCode *string `json:"error_code"`
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func loadKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed, err := hex.DecodeString(testKeySeedHex)
	if err != nil {
		panic(err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

func pubKeyB64(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// signToken signs a token map (all fields except "sig") using Ed25519(SHA-256(JCS(signable))).
func signToken(m map[string]any, priv ed25519.PrivateKey) string {
	signable := make(map[string]any, len(m))
	for k, v := range m {
		if k != "sig" {
			signable[k] = v
		}
	}
	raw, _ := json.Marshal(signable)
	canonical, _ := jcs.Transform(raw)
	digest := sha256.Sum256(canonical)
	sig := ed25519.Sign(priv, digest[:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

// hashParams computes base64url(SHA-256(JCS(params))) — ACP-EXEC-1.0 §5.6.
func hashParams(params map[string]any) string {
	raw, _ := json.Marshal(params)
	canonical, _ := jcs.Transform(raw)
	digest := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// baseToken returns a canonical valid token map.
func baseToken(pub ed25519.PublicKey, priv ed25519.PrivateKey) map[string]any {
	params := map[string]any{"amount": 500.0, "currency": "USD"}
	ph := hashParams(params)
	tok := map[string]any{
		"ver":                    "1.0",
		"et_id":                  "a1b2c3d4-0000-4000-8000-000000000001",
		"agent_id":               "agent.example.banking",
		"authorization_id":       "auth-req-0000-0001",
		"capability":             "acp:cap:financial.payment",
		"resource":               "bank://accounts/12345",
		"action_parameters_hash": ph,
		"issued_at":              issuedAt,
		"expires_at":             expiresAt,
		"used":                   false,
	}
	tok["sig"] = signToken(tok, priv)
	return tok
}

func errCode(s string) *string { return &s }

func write(outDir, id string, vec TestVector) {
	data, err := json.MarshalIndent(vec, "", "  ")
	if err != nil {
		panic(err)
	}
	path := filepath.Join(outDir, id+".json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		panic(err)
	}
	fmt.Printf("wrote %s\n", path)
}

// ─── main ─────────────────────────────────────────────────────────────────────

func main() {
	outDir := "../../compliance/test-vectors"
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		panic(err)
	}

	pub, priv := loadKey()
	pubB64 := pubKeyB64(pub)

	// Verify the package builds correctly by issuing a token through the official API.
	{
		req := execution.IssueRequest{
			AgentID:          "agent.example.banking",
			AuthorizationID:  "auth-req-0000-0001",
			Capability:       "acp:cap:financial.payment",
			Resource:         "bank://accounts/12345",
			ActionParameters: map[string]interface{}{"amount": 500.0, "currency": "USD"},
		}
		if _, err := execution.Issue(req, priv); err != nil {
			fmt.Fprintf(os.Stderr, "sanity check failed: %v\n", err)
			os.Exit(1)
		}
	}

	// ── POS-001 · Valid ET, signed, within window ─────────────────────────────
	{
		tok := baseToken(pub, priv)
		write(outDir, "TS-EXEC-POS-001", TestVector{
			Meta: VectorMeta{
				ID: "TS-EXEC-POS-001", Layer: "EXEC", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "Valid execution token — signature correct, not expired, not consumed",
			},
			Input: VectorInput{
				InstitutionPublicKey: pubB64,
				Token:                tok,
				VerifyAt:             verifyAt,
				ExpectedAgentID:      tok["agent_id"].(string),
				ExpectedResource:     tok["resource"].(string),
				ExpectedParamsHash:   tok["action_parameters_hash"].(string),
			},
			Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
		})
	}

	// ── POS-002 · Valid ET, different capability (data.read, 300s window) ─────
	{
		params := map[string]any{"query": "SELECT * FROM logs"}
		ph := hashParams(params)
		tok := map[string]any{
			"ver":                    "1.0",
			"et_id":                  "a1b2c3d4-0000-4000-8000-000000000002",
			"agent_id":               "agent.example.analytics",
			"authorization_id":       "auth-req-0000-0002",
			"capability":             "acp:cap:data.read",
			"resource":               "db://reports/daily",
			"action_parameters_hash": ph,
			"issued_at":              issuedAt,
			"expires_at":             issuedAt + 300,
			"used":                   false,
		}
		tok["sig"] = signToken(tok, priv)
		write(outDir, "TS-EXEC-POS-002", TestVector{
			Meta: VectorMeta{
				ID: "TS-EXEC-POS-002", Layer: "EXEC", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "Valid execution token — data.read capability with 300s window",
			},
			Input: VectorInput{
				InstitutionPublicKey: pubB64,
				Token:                tok,
				VerifyAt:             verifyAt,
				ExpectedAgentID:      tok["agent_id"].(string),
				ExpectedResource:     tok["resource"].(string),
				ExpectedParamsHash:   tok["action_parameters_hash"].(string),
			},
			Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
		})
	}

	// ── NEG-001 · EXEC-001 · Unsupported version ──────────────────────────────
	{
		tok := baseToken(pub, priv)
		tok["ver"] = "2.0"
		tok["sig"] = signToken(tok, priv) // re-sign to isolate EXEC-001 from EXEC-002
		write(outDir, "TS-EXEC-NEG-001", TestVector{
			Meta: VectorMeta{
				ID: "TS-EXEC-NEG-001", Layer: "EXEC", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "Invalid execution token — ver=2.0 (unsupported version)",
			},
			Input: VectorInput{
				InstitutionPublicKey: pubB64,
				Token:                tok,
				VerifyAt:             verifyAt,
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("EXEC-001")},
		})
	}

	// ── NEG-002 · EXEC-002 · Invalid signature ────────────────────────────────
	{
		tok := baseToken(pub, priv)
		// Tamper sig: replace last char to corrupt it
		origSig := tok["sig"].(string)
		last := origSig[len(origSig)-1]
		if last == 'A' {
			origSig = origSig[:len(origSig)-1] + "B"
		} else {
			origSig = origSig[:len(origSig)-1] + "A"
		}
		tok["sig"] = origSig
		write(outDir, "TS-EXEC-NEG-002", TestVector{
			Meta: VectorMeta{
				ID: "TS-EXEC-NEG-002", Layer: "EXEC", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "Invalid execution token — sig last byte corrupted",
			},
			Input: VectorInput{
				InstitutionPublicKey: pubB64,
				Token:                tok,
				VerifyAt:             verifyAt,
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("EXEC-002")},
		})
	}

	// ── NEG-003 · EXEC-003 · Expired ET ──────────────────────────────────────
	{
		tok := baseToken(pub, priv)
		write(outDir, "TS-EXEC-NEG-003", TestVector{
			Meta: VectorMeta{
				ID: "TS-EXEC-NEG-003", Layer: "EXEC", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "Invalid execution token — verify_at is 120s after issued_at (expires_at = issued_at+60)",
			},
			Input: VectorInput{
				InstitutionPublicKey: pubB64,
				Token:                tok,
				VerifyAt:             verifyAtExpired,
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("EXEC-003")},
		})
	}

	// ── NEG-004 · EXEC-004 · ET already consumed (used=true in registry) ─────
	{
		tok := baseToken(pub, priv)
		// Note: the test runner MUST pre-register this token as consumed before verifying.
		// The token itself is valid; the consumed state lives in the registry.
		// Test convention: input.token_state = "used" signals pre-consumed state.
		tokWithState := make(map[string]any, len(tok)+1)
		for k, v := range tok {
			tokWithState[k] = v
		}
		tokWithState["_test_state"] = "used" // test-runner hint (not part of ET spec)
		write(outDir, "TS-EXEC-NEG-004", TestVector{
			Meta: VectorMeta{
				ID: "TS-EXEC-NEG-004", Layer: "EXEC", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "Invalid execution token — ET was already consumed (registry state = used)",
			},
			Input: VectorInput{
				InstitutionPublicKey: pubB64,
				Token:                tokWithState,
				VerifyAt:             verifyAt,
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("EXEC-004")},
		})
	}

	// ── NEG-005 · EXEC-005 · agent_id mismatch ───────────────────────────────
	{
		tok := baseToken(pub, priv)
		write(outDir, "TS-EXEC-NEG-005", TestVector{
			Meta: VectorMeta{
				ID: "TS-EXEC-NEG-005", Layer: "EXEC", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "Invalid execution token — expected_agent_id differs from token agent_id",
			},
			Input: VectorInput{
				InstitutionPublicKey: pubB64,
				Token:                tok,
				VerifyAt:             verifyAt,
				ExpectedAgentID:      "agent.malicious.actor", // mismatch
				ExpectedResource:     tok["resource"].(string),
				ExpectedParamsHash:   tok["action_parameters_hash"].(string),
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("EXEC-005")},
		})
	}

	// ── NEG-006 · EXEC-006 · resource mismatch ───────────────────────────────
	{
		tok := baseToken(pub, priv)
		write(outDir, "TS-EXEC-NEG-006", TestVector{
			Meta: VectorMeta{
				ID: "TS-EXEC-NEG-006", Layer: "EXEC", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "Invalid execution token — expected_resource differs from token resource",
			},
			Input: VectorInput{
				InstitutionPublicKey: pubB64,
				Token:                tok,
				VerifyAt:             verifyAt,
				ExpectedAgentID:      tok["agent_id"].(string),
				ExpectedResource:     "bank://accounts/99999", // mismatch
				ExpectedParamsHash:   tok["action_parameters_hash"].(string),
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("EXEC-006")},
		})
	}

	// ── NEG-007 · EXEC-007 · action_parameters_hash mismatch ─────────────────
	{
		tok := baseToken(pub, priv)
		// Use a different params hash (SHA-256 of empty object)
		fakeHash := hashParams(map[string]any{"amount": 0.0})
		write(outDir, "TS-EXEC-NEG-007", TestVector{
			Meta: VectorMeta{
				ID: "TS-EXEC-NEG-007", Layer: "EXEC", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "Invalid execution token — expected_params_hash differs from token action_parameters_hash",
			},
			Input: VectorInput{
				InstitutionPublicKey: pubB64,
				Token:                tok,
				VerifyAt:             verifyAt,
				ExpectedAgentID:      tok["agent_id"].(string),
				ExpectedResource:     tok["resource"].(string),
				ExpectedParamsHash:   fakeHash, // mismatch
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("EXEC-007")},
		})
	}

	fmt.Println("done — 9 EXEC test vectors written")
}
