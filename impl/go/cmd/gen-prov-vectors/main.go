// Command gen-prov-vectors generates compliance/test-vectors/TS-PROV-*.json.
//
// Produces 2 positive and 7 negative test vectors covering ACP-PROVENANCE-1.0
// validation (PROV-001 through PROV-009, skipping PROV-006 which requires a
// live policy store).
// Uses the same RFC 8037 test key A as other vector generators for the
// institutional key.  Two additional deterministic keys (agent A, agent B)
// are derived from fixed seeds for delegation step signatures.
//
// Run from the impl/go module root:
//
//	go run ./cmd/gen-prov-vectors
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

	"github.com/gowebpki/jcs"
)

// ─── Key seeds ────────────────────────────────────────────────────────────────

// Institution key — RFC 8037 test key A (same as other generators).
const instKeySeedHex = "9d61b19deffd5998b34a442fa1c54cd044c9c565b66f2699171d66c968225234"

// Agent A key — deterministic test seed.
const agentAKeySeedHex = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

// Agent B key — deterministic test seed.
const agentBKeySeedHex = "2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"

// ─── Fixed timestamps (2026-03-16T12:00:00Z) ─────────────────────────────────

const capturedAt int64 = 1774036800
const delegatedAt int64 = capturedAt - 3600  // 1h before captured_at
const validUntil int64 = delegatedAt + 86400  // valid 24h from delegatedAt
const etExpiresAt int64 = capturedAt + 60

// ─── Fixed identifiers ───────────────────────────────────────────────────────

const executionID = "et-prov-test-0000-0000-0001"
const provenanceID = "prov-0000-0000-0000-0001"
const principalID = "org.bank.institution"
const agentAID = "agent.bank.controller"
const agentBID = "agent.bank.executor"

// ─── Helpers ─────────────────────────────────────────────────────────────────

func loadKey(seedHex string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		panic(fmt.Sprintf("bad seed hex %q: %v", seedHex, err))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

func pubB64(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

// sign signs a map (excluding the named field) with Ed25519(SHA-256(JCS(m))).
func sign(m map[string]any, excludeField string, priv ed25519.PrivateKey) string {
	signable := make(map[string]any, len(m))
	for k, v := range m {
		if k != excludeField {
			signable[k] = v
		}
	}
	raw, err := json.Marshal(signable)
	if err != nil {
		panic(err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(canonical)
	sig := ed25519.Sign(priv, digest[:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

// makeStep creates a DelegationStep map and signs it with delegatorPriv.
func makeStep(n int, delegator, executor, delID, cap string, delAt, valUntil int64, delegatorPriv ed25519.PrivateKey) map[string]any {
	s := map[string]any{
		"step":              n,
		"delegator":         delegator,
		"executor":          executor,
		"delegation_id":     delID,
		"capability_subset": cap,
		"delegated_at":      delAt,
		"valid_until":       valUntil,
	}
	s["delegation_sig"] = sign(s, "delegation_sig", delegatorPriv)
	return s
}

// makeProvenance builds a full AuthorityProvenance map and signs it.
func makeProvenance(id, execID string, captAt int64, principal, executor, scope string,
	chain []map[string]any, policyRef, policyHash string, instPriv ed25519.PrivateKey) map[string]any {

	chainAny := make([]any, len(chain))
	for i, s := range chain {
		chainAny[i] = s
	}
	ap := map[string]any{
		"ver":            "1.0",
		"provenance_id":  id,
		"execution_id":   execID,
		"captured_at":    captAt,
		"principal":      principal,
		"executor":       executor,
		"authority_scope": scope,
		"chain":          chainAny,
		"policy_ref":     policyRef,
		"policy_hash":    policyHash,
	}
	ap["sig"] = sign(ap, "sig", instPriv)
	return ap
}

// fakeHash returns a deterministic hex string (SHA-256 of the input).
func fakeHash(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

func errCode(s string) *string { return &s }

// ─── Vector schema ────────────────────────────────────────────────────────────

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
	Provenance           map[string]any `json:"provenance"`
	VerifyAt             int64          `json:"verify_at"`
	ETExpiresAt          int64          `json:"et_expires_at"`
}

type VectorExpected struct {
	Decision  string  `json:"decision"`
	ErrorCode *string `json:"error_code"`
}

type TestVector struct {
	Meta     VectorMeta     `json:"meta"`
	Input    VectorInput    `json:"input"`
	Expected VectorExpected `json:"expected"`
}

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

	instPub, instPriv := loadKey(instKeySeedHex)
	_, agentAPriv := loadKey(agentAKeySeedHex)
	_, _ = loadKey(agentBKeySeedHex) // agentB key — not used for signing in these vectors

	instPubB64 := pubB64(instPub)
	policyRef := "payment_policy:v3"
	policyHash := fakeHash("payment_policy_v3_document_content")

	// Standard 2-hop chain: institution → agentA → agentB
	buildValidChain := func() []map[string]any {
		step1 := makeStep(1, principalID, agentAID, "DEL-PROV-001",
			"acp:cap:financial.payment", delegatedAt, validUntil, instPriv)
		step2 := makeStep(2, agentAID, agentBID, "DEL-PROV-002",
			"acp:cap:financial.payment", delegatedAt, validUntil, agentAPriv)
		return []map[string]any{step1, step2}
	}

	// ── POS-001 · Valid 2-hop chain ───────────────────────────────────────────
	{
		chain := buildValidChain()
		ap := makeProvenance(provenanceID, executionID, capturedAt,
			principalID, agentBID, "acp:cap:financial.payment",
			chain, policyRef, policyHash, instPriv)

		write(outDir, "TS-PROV-POS-001", TestVector{
			Meta: VectorMeta{
				ID: "TS-PROV-POS-001", Layer: "PROV", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "Valid 2-hop provenance chain: institution → agent.bank.controller → agent.bank.executor",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Provenance:           ap,
				VerifyAt:             capturedAt,
				ETExpiresAt:          etExpiresAt,
			},
			Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
		})
	}

	// ── POS-002 · Minimal provenance (no delegation, direct institution) ──────
	{
		ap := makeProvenance("prov-minimal-0000-0001", "et-prov-test-0000-0000-0002",
			capturedAt, principalID, agentAID, "acp:cap:data.read",
			[]map[string]any{}, // chain: [] — direct institutional authorization
			policyRef, policyHash, instPriv)

		write(outDir, "TS-PROV-POS-002", TestVector{
			Meta: VectorMeta{
				ID: "TS-PROV-POS-002", Layer: "PROV", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L2",
				Description: "Valid minimal provenance (chain: []) — direct institutional authorization with no intermediate delegation",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Provenance:           ap,
				VerifyAt:             capturedAt,
				ETExpiresAt:          etExpiresAt,
			},
			Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
		})
	}

	// ── NEG-001 · PROV-001 · Chain incomplete — step executor ≠ next step delegator ──
	{
		step1 := makeStep(1, principalID, agentAID, "DEL-PROV-001",
			"acp:cap:financial.payment", delegatedAt, validUntil, instPriv)
		// step2 has a wrong delegator (break in chain continuity)
		step2 := makeStep(2, "agent.unknown.intruder", agentBID, "DEL-PROV-002",
			"acp:cap:financial.payment", delegatedAt, validUntil, agentAPriv)

		ap := makeProvenance(provenanceID, executionID, capturedAt,
			principalID, agentBID, "acp:cap:financial.payment",
			[]map[string]any{step1, step2}, policyRef, policyHash, instPriv)

		write(outDir, "TS-PROV-NEG-001", TestVector{
			Meta: VectorMeta{
				ID: "TS-PROV-NEG-001", Layer: "PROV", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "PROV-001: chain break — step[1].executor (agentA) ≠ step[2].delegator (agent.unknown.intruder)",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Provenance:           ap,
				VerifyAt:             capturedAt,
				ETExpiresAt:          etExpiresAt,
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PROV-001")},
		})
	}

	// ── NEG-002 · PROV-002 · Capability escalation at step 2 ─────────────────
	{
		step1 := makeStep(1, principalID, agentAID, "DEL-PROV-001",
			"acp:cap:data.read", delegatedAt, validUntil, instPriv)
		// step2 escalates capability from data.read to financial.payment
		step2 := makeStep(2, agentAID, agentBID, "DEL-PROV-002",
			"acp:cap:financial.payment", delegatedAt, validUntil, agentAPriv)

		ap := makeProvenance(provenanceID, executionID, capturedAt,
			principalID, agentBID, "acp:cap:financial.payment",
			[]map[string]any{step1, step2}, policyRef, policyHash, instPriv)

		write(outDir, "TS-PROV-NEG-002", TestVector{
			Meta: VectorMeta{
				ID: "TS-PROV-NEG-002", Layer: "PROV", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "PROV-002: capability escalation — step[2] claims financial.payment but step[1] only granted data.read",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Provenance:           ap,
				VerifyAt:             capturedAt,
				ETExpiresAt:          etExpiresAt,
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PROV-002")},
		})
	}

	// ── NEG-003 · PROV-003 · Expired delegation step ─────────────────────────
	{
		expiredUntil := capturedAt - 600 // expired 10 min before capturedAt
		step1 := makeStep(1, principalID, agentAID, "DEL-PROV-001",
			"acp:cap:financial.payment", delegatedAt, expiredUntil, instPriv)
		step2 := makeStep(2, agentAID, agentBID, "DEL-PROV-002",
			"acp:cap:financial.payment", delegatedAt, validUntil, agentAPriv)

		ap := makeProvenance(provenanceID, executionID, capturedAt,
			principalID, agentBID, "acp:cap:financial.payment",
			[]map[string]any{step1, step2}, policyRef, policyHash, instPriv)

		write(outDir, "TS-PROV-NEG-003", TestVector{
			Meta: VectorMeta{
				ID: "TS-PROV-NEG-003", Layer: "PROV", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "PROV-003: step[1].valid_until expired 600s before captured_at",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Provenance:           ap,
				VerifyAt:             capturedAt,
				ETExpiresAt:          etExpiresAt,
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PROV-003")},
		})
	}

	// ── NEG-004 · PROV-004 · Invalid step delegation_sig ─────────────────────
	{
		chain := buildValidChain()
		// Corrupt step[0].delegation_sig — tamper last byte
		origSig := chain[0]["delegation_sig"].(string)
		last := origSig[len(origSig)-1]
		var tampered string
		if last == 'A' {
			tampered = origSig[:len(origSig)-1] + "B"
		} else {
			tampered = origSig[:len(origSig)-1] + "A"
		}
		chain[0]["delegation_sig"] = tampered

		ap := makeProvenance(provenanceID, executionID, capturedAt,
			principalID, agentBID, "acp:cap:financial.payment",
			chain, policyRef, policyHash, instPriv)

		write(outDir, "TS-PROV-NEG-004", TestVector{
			Meta: VectorMeta{
				ID: "TS-PROV-NEG-004", Layer: "PROV", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "PROV-004: step[0].delegation_sig last byte corrupted — invalid step signature",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Provenance:           ap,
				VerifyAt:             capturedAt,
				ETExpiresAt:          etExpiresAt,
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PROV-004")},
		})
	}

	// ── NEG-005 · PROV-005 · Invalid institutional signature ─────────────────
	{
		chain := buildValidChain()
		ap := makeProvenance(provenanceID, executionID, capturedAt,
			principalID, agentBID, "acp:cap:financial.payment",
			chain, policyRef, policyHash, instPriv)

		// Corrupt the top-level sig
		origSig := ap["sig"].(string)
		last := origSig[len(origSig)-1]
		if last == 'A' {
			ap["sig"] = origSig[:len(origSig)-1] + "B"
		} else {
			ap["sig"] = origSig[:len(origSig)-1] + "A"
		}

		write(outDir, "TS-PROV-NEG-005", TestVector{
			Meta: VectorMeta{
				ID: "TS-PROV-NEG-005", Layer: "PROV", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "PROV-005: institutional sig last byte corrupted — invalid provenance signature",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Provenance:           ap,
				VerifyAt:             capturedAt,
				ETExpiresAt:          etExpiresAt,
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PROV-005")},
		})
	}

	// ── NEG-006 · PROV-007 · execution_id mismatch ───────────────────────────
	{
		chain := buildValidChain()
		ap := makeProvenance(provenanceID, "et-different-0000-0000-9999", capturedAt,
			principalID, agentBID, "acp:cap:financial.payment",
			chain, policyRef, policyHash, instPriv)

		write(outDir, "TS-PROV-NEG-006", TestVector{
			Meta: VectorMeta{
				ID: "TS-PROV-NEG-006", Layer: "PROV", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "PROV-007: provenance.execution_id does not match the bound ET id",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Provenance:           ap,
				VerifyAt:             capturedAt,
				ETExpiresAt:          etExpiresAt,
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PROV-007")},
		})
	}

	// ── NEG-007 · PROV-009 · Executor mismatch ───────────────────────────────
	{
		chain := buildValidChain()
		// chain[last].executor is agentBID, but ap.executor is set to a different agent
		ap := makeProvenance(provenanceID, executionID, capturedAt,
			principalID, "agent.wrong.executor", "acp:cap:financial.payment",
			chain, policyRef, policyHash, instPriv)

		write(outDir, "TS-PROV-NEG-007", TestVector{
			Meta: VectorMeta{
				ID: "TS-PROV-NEG-007", Layer: "PROV", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "PROV-009: ap.executor (agent.wrong.executor) ≠ chain[last].executor (agent.bank.executor)",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Provenance:           ap,
				VerifyAt:             capturedAt,
				ETExpiresAt:          etExpiresAt,
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PROV-009")},
		})
	}

	fmt.Println("done — 9 PROV test vectors written (2 POS + 7 NEG)")
}
