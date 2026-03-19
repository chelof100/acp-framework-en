// Command gen-policyctx-vectors generates compliance/test-vectors/TS-PCTX-*.json.
//
// Produces 4 positive and 9 negative test vectors covering ACP-POLICY-CTX-1.1
// validation (PCTX-001 through PCTX-009), including backward compatibility with
// ver "1.0" and the hybrid freshness enforcement model.
//
// Uses the RFC 8037 test key A (same seed as all other vector generators)
// for the institutional signature.
//
// Run from the impl/go module root:
//
//	go run ./cmd/gen-policyctx-vectors
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

// ─── Key seed ────────────────────────────────────────────────────────────────

// Institution key — RFC 8037 test key A (same as all other generators).
const instKeySeedHex = "9d61b19deffd5998b34a442fa1c54cd044c9c565b66f2699171d66c968225234"

// ─── Fixed timestamps ─────────────────────────────────────────────────────────
//
// Base epoch: 1741200000 = 2025-03-05T12:00:00Z (deterministic, used across vectors)
//
//	et_issued_at     = 1741200000
//	et_expires_at    = 1741200300   (+ 300s)
//	snapshot_at      = 1741200100   (inside ET window)
//	policy_captured_at (normal) = 1741200070  (diff = 30s)

const (
	etIssuedAt   int64 = 1741200000
	etExpiresAt  int64 = 1741200300
	snapshotAt   int64 = 1741200100
	capturedAt30 int64 = 1741200070 // diff = 30s (< 60s delta_max → valid)
	capturedAt60 int64 = 1741200040 // diff = 60s (= delta_max → valid borderline)
	capturedAt80 int64 = 1741200020 // diff = 80s (> 60s verifier_max → PCTX-009 for NEG-009)
)

// ─── Fixed identifiers ───────────────────────────────────────────────────────

const (
	executionID  = "et-pctx-test-0000-0000-0001"
	snapshotID   = "snap-pctx-0000-0000-0000-0001"
	provenanceID = "prov-pctx-0000-0000-0001"
	agentID      = "agent.test.executor"
)

// ─── Helpers ─────────────────────────────────────────────────────────────────

func loadKey(seedHex string) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		panic(fmt.Sprintf("bad seed hex: %v", err))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return pub, priv
}

func pubB64(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub)
}

func fakeHash(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}

// signSnapshot signs a PolicyContextSnapshot map (excluding "sig").
func signSnapshot(m map[string]any, priv ed25519.PrivateKey) string {
	signable := make(map[string]any, len(m))
	for k, v := range m {
		if k != "sig" {
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

type VerifierConfig struct {
	DeltaMaxAllowed int64 `json:"delta_max_allowed"`
}

type VectorInput struct {
	InstitutionPublicKey string         `json:"institution_public_key"`
	Snapshot             map[string]any `json:"snapshot"`
	ETIssuedAt           int64          `json:"et_issued_at"`
	ETExpiresAt          int64          `json:"et_expires_at"`
	VerifierConfig       VerifierConfig `json:"verifier_config"`
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

// ─── Snapshot builders ────────────────────────────────────────────────────────

func basePolicy() map[string]any {
	return map[string]any{
		"policy_id":      "payment_policy",
		"policy_version": "v3",
		"policy_hash":    fakeHash("payment_policy_v3_document_content"),
		"policy_engine":  "opa",
	}
}

func baseEvalContext() map[string]any {
	return map[string]any{
		"agent_id":             agentID,
		"requested_capability": "acp:cap:financial.payment",
		"resource":             "payment:transfer:USD",
		"risk_score":           0.2,
		"delegation_active":    true,
	}
}

func baseEvalResult() map[string]any {
	return map[string]any{
		"decision":      "APPROVED",
		"checks":        []any{},
		"denial_reason": nil,
	}
}

// makeSnapshot creates a signed PolicyContextSnapshot map (ver 1.1).
func makeSnapshot(
	snapID, execID, provID string,
	snapAt, captAt, deltaMax int64,
	policy map[string]any,
	evalCtx map[string]any,
	evalResult map[string]any,
	priv ed25519.PrivateKey,
) map[string]any {
	m := map[string]any{
		"ver":                "1.1",
		"snapshot_id":        snapID,
		"execution_id":       execID,
		"provenance_id":      provID,
		"snapshot_at":        snapAt,
		"policy_captured_at": captAt,
		"delta_max":          deltaMax,
		"policy":             policy,
		"evaluation_context": evalCtx,
		"evaluation_result":  evalResult,
	}
	m["sig"] = signSnapshot(m, priv)
	return m
}

// makeSnapshotV10 creates a signed PolicyContextSnapshot map (ver 1.0, no freshness fields).
func makeSnapshotV10(
	snapID, execID, provID string,
	snapAt int64,
	policy map[string]any,
	evalCtx map[string]any,
	evalResult map[string]any,
	priv ed25519.PrivateKey,
) map[string]any {
	m := map[string]any{
		"ver":                "1.0",
		"snapshot_id":        snapID,
		"execution_id":       execID,
		"provenance_id":      provID,
		"snapshot_at":        snapAt,
		"policy":             policy,
		"evaluation_context": evalCtx,
		"evaluation_result":  evalResult,
	}
	m["sig"] = signSnapshot(m, priv)
	return m
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
	instPubB64 := pubB64(instPub)

	// ── POS-001 · Valid normal (diff=30s, delta_max=60s) ─────────────────────
	{
		snap := makeSnapshot(snapshotID, executionID, provenanceID,
			snapshotAt, capturedAt30, 60,
			basePolicy(), baseEvalContext(), baseEvalResult(), instPriv)

		write(outDir, "TS-PCTX-POS-001", TestVector{
			Meta: VectorMeta{
				ID: "TS-PCTX-POS-001", Layer: "PCTX", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L3",
				Description: "Valid snapshot: ver 1.1, freshness=30s < delta_max=60s",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Snapshot:             snap,
				ETIssuedAt:           etIssuedAt,
				ETExpiresAt:          etExpiresAt,
				VerifierConfig:       VerifierConfig{DeltaMaxAllowed: 300},
			},
			Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
		})
	}

	// ── POS-002 · Borderline snapshot delta (diff=60s = delta_max=60s) ───────
	{
		snap := makeSnapshot(snapshotID, executionID, provenanceID,
			snapshotAt, capturedAt60, 60,
			basePolicy(), baseEvalContext(), baseEvalResult(), instPriv)

		write(outDir, "TS-PCTX-POS-002", TestVector{
			Meta: VectorMeta{
				ID: "TS-PCTX-POS-002", Layer: "PCTX", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L3",
				Description: "Borderline producer limit: freshness=60s exactly equals snapshot.delta_max=60s",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Snapshot:             snap,
				ETIssuedAt:           etIssuedAt,
				ETExpiresAt:          etExpiresAt,
				VerifierConfig:       VerifierConfig{DeltaMaxAllowed: 300},
			},
			Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
		})
	}

	// ── POS-003 · Backward compat ver 1.0 (no freshness fields) ──────────────
	{
		snap := makeSnapshotV10(snapshotID, executionID, provenanceID,
			snapshotAt, basePolicy(), baseEvalContext(), baseEvalResult(), instPriv)

		write(outDir, "TS-PCTX-POS-003", TestVector{
			Meta: VectorMeta{
				ID: "TS-PCTX-POS-003", Layer: "PCTX", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L3",
				Description: "Backward compatibility: ver 1.0 snapshot without freshness fields MUST pass (§12)",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Snapshot:             snap,
				ETIssuedAt:           etIssuedAt,
				ETExpiresAt:          etExpiresAt,
				VerifierConfig:       VerifierConfig{DeltaMaxAllowed: 300},
			},
			Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
		})
	}

	// ── POS-004 · Borderline verifier delta (diff=60s = verifier_max=60s) ────
	{
		// snapshot.delta_max=300s (producer is permissive), verifier clamps to 60s
		// diff=60s exactly equals verifier_max=60s → VALID (mirror of NEG-009 where diff=80s)
		snap := makeSnapshot(snapshotID, executionID, provenanceID,
			snapshotAt, capturedAt60, 300,
			basePolicy(), baseEvalContext(), baseEvalResult(), instPriv)

		write(outDir, "TS-PCTX-POS-004", TestVector{
			Meta: VectorMeta{
				ID: "TS-PCTX-POS-004", Layer: "PCTX", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L3",
				Description: "Borderline verifier limit: freshness=60s exactly equals verifier.delta_max_allowed=60s",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Snapshot:             snap,
				ETIssuedAt:           etIssuedAt,
				ETExpiresAt:          etExpiresAt,
				VerifierConfig:       VerifierConfig{DeltaMaxAllowed: 60},
			},
			Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
		})
	}

	// ── NEG-001 · execution_id mismatch (PCTX-001) ───────────────────────────
	{
		snap := makeSnapshot(snapshotID, "et-wrong-execution-id", provenanceID,
			snapshotAt, capturedAt30, 60,
			basePolicy(), baseEvalContext(), baseEvalResult(), instPriv)

		write(outDir, "TS-PCTX-NEG-001", TestVector{
			Meta: VectorMeta{
				ID: "TS-PCTX-NEG-001", Layer: "PCTX", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L3",
				Description: "PCTX-001: execution_id in snapshot does not match the bound Execution Token",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Snapshot:             snap,
				ETIssuedAt:           etIssuedAt,
				ETExpiresAt:          etExpiresAt,
				VerifierConfig:       VerifierConfig{DeltaMaxAllowed: 300},
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PCTX-001")},
		})
	}

	// ── NEG-002 · snapshot_at outside ET window (PCTX-002) ───────────────────
	{
		// snapshot_at = etExpiresAt + 60 → outside window
		outsideAt := etExpiresAt + 60
		snap := makeSnapshot(snapshotID, executionID, provenanceID,
			outsideAt, outsideAt-30, 60,
			basePolicy(), baseEvalContext(), baseEvalResult(), instPriv)

		write(outDir, "TS-PCTX-NEG-002", TestVector{
			Meta: VectorMeta{
				ID: "TS-PCTX-NEG-002", Layer: "PCTX", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L3",
				Description: "PCTX-002: snapshot_at is outside the ET validity window",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Snapshot:             snap,
				ETIssuedAt:           etIssuedAt,
				ETExpiresAt:          etExpiresAt,
				VerifierConfig:       VerifierConfig{DeltaMaxAllowed: 300},
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PCTX-002")},
		})
	}

	// ── NEG-003 · policy_hash corrupted (PCTX-004) ───────────────────────────
	{
		pol := basePolicy()
		originalHash := pol["policy_hash"].(string)
		// Flip last byte of hex string
		corrupted := originalHash[:len(originalHash)-2] + "ff"
		if corrupted == originalHash {
			corrupted = originalHash[:len(originalHash)-2] + "00"
		}
		pol["policy_hash"] = corrupted

		snap := makeSnapshot(snapshotID, executionID, provenanceID,
			snapshotAt, capturedAt30, 60,
			pol, baseEvalContext(), baseEvalResult(), instPriv)

		write(outDir, "TS-PCTX-NEG-003", TestVector{
			Meta: VectorMeta{
				ID: "TS-PCTX-NEG-003", Layer: "PCTX", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L3",
				Description: "PCTX-004: policy_hash is corrupted — last byte modified",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Snapshot:             snap,
				ETIssuedAt:           etIssuedAt,
				ETExpiresAt:          etExpiresAt,
				VerifierConfig:       VerifierConfig{DeltaMaxAllowed: 300},
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PCTX-004")},
		})
	}

	// ── NEG-004 · institutional sig invalid (PCTX-006) ───────────────────────
	{
		snap := makeSnapshot(snapshotID, executionID, provenanceID,
			snapshotAt, capturedAt30, 60,
			basePolicy(), baseEvalContext(), baseEvalResult(), instPriv)

		// Corrupt sig: flip last character
		origSig := snap["sig"].(string)
		var tampered string
		if origSig[len(origSig)-1] == 'A' {
			tampered = origSig[:len(origSig)-1] + "B"
		} else {
			tampered = origSig[:len(origSig)-1] + "A"
		}
		snap["sig"] = tampered

		write(outDir, "TS-PCTX-NEG-004", TestVector{
			Meta: VectorMeta{
				ID: "TS-PCTX-NEG-004", Layer: "PCTX", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L3",
				Description: "PCTX-006: institutional signature has one byte modified",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Snapshot:             snap,
				ETIssuedAt:           etIssuedAt,
				ETExpiresAt:          etExpiresAt,
				VerifierConfig:       VerifierConfig{DeltaMaxAllowed: 300},
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PCTX-006")},
		})
	}

	// ── NEG-005 · required field missing (PCTX-007) ───────────────────────────
	{
		snap := makeSnapshot("", executionID, provenanceID,
			snapshotAt, capturedAt30, 60,
			basePolicy(), baseEvalContext(), baseEvalResult(), instPriv)
		// snapshot_id is empty — required field missing
		snap["snapshot_id"] = ""

		write(outDir, "TS-PCTX-NEG-005", TestVector{
			Meta: VectorMeta{
				ID: "TS-PCTX-NEG-005", Layer: "PCTX", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L3",
				Description: "PCTX-007: snapshot_id is empty — required field missing",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Snapshot:             snap,
				ETIssuedAt:           etIssuedAt,
				ETExpiresAt:          etExpiresAt,
				VerifierConfig:       VerifierConfig{DeltaMaxAllowed: 300},
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PCTX-007")},
		})
	}

	// ── NEG-006 · policy_captured_at absent (PCTX-009) ────────────────────────
	{
		// Build snapshot with ver 1.1 but no policy_captured_at
		m := map[string]any{
			"ver":                "1.1",
			"snapshot_id":        snapshotID,
			"execution_id":       executionID,
			"provenance_id":      provenanceID,
			"snapshot_at":        snapshotAt,
			// policy_captured_at intentionally absent
			"delta_max":          int64(60),
			"policy":             basePolicy(),
			"evaluation_context": baseEvalContext(),
			"evaluation_result":  baseEvalResult(),
		}
		m["sig"] = signSnapshot(m, instPriv)

		write(outDir, "TS-PCTX-NEG-006", TestVector{
			Meta: VectorMeta{
				ID: "TS-PCTX-NEG-006", Layer: "PCTX", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L3",
				Description: "PCTX-009: ver 1.1 snapshot missing policy_captured_at",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Snapshot:             m,
				ETIssuedAt:           etIssuedAt,
				ETExpiresAt:          etExpiresAt,
				VerifierConfig:       VerifierConfig{DeltaMaxAllowed: 300},
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PCTX-009")},
		})
	}

	// ── NEG-007 · freshness exceeded (PCTX-009) ───────────────────────────────
	{
		// diff = snapshotAt - capturedAt = 100 - (-20) overflow? Let's use explicit:
		// snapshot_at=1741200100, policy_captured_at=1741199980 → diff=120s > delta_max=60s
		staleAt := snapshotAt - 120
		snap := makeSnapshot(snapshotID, executionID, provenanceID,
			snapshotAt, staleAt, 60,
			basePolicy(), baseEvalContext(), baseEvalResult(), instPriv)

		write(outDir, "TS-PCTX-NEG-007", TestVector{
			Meta: VectorMeta{
				ID: "TS-PCTX-NEG-007", Layer: "PCTX", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L3",
				Description: "PCTX-009: freshness=120s exceeds snapshot.delta_max=60s",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Snapshot:             snap,
				ETIssuedAt:           etIssuedAt,
				ETExpiresAt:          etExpiresAt,
				VerifierConfig:       VerifierConfig{DeltaMaxAllowed: 300},
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PCTX-009")},
		})
	}

	// ── NEG-008 · clock skew exceeded (PCTX-009) ─────────────────────────────
	{
		// policy_captured_at = snapshot_at + 10 → skew = 10s > 5s tolerance
		skewedCapturedAt := snapshotAt + 10
		snap := makeSnapshot(snapshotID, executionID, provenanceID,
			snapshotAt, skewedCapturedAt, 60,
			basePolicy(), baseEvalContext(), baseEvalResult(), instPriv)

		write(outDir, "TS-PCTX-NEG-008", TestVector{
			Meta: VectorMeta{
				ID: "TS-PCTX-NEG-008", Layer: "PCTX", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L3",
				Description: "PCTX-009: clock skew=10s exceeds 5s tolerance (policy_captured_at > snapshot_at)",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Snapshot:             snap,
				ETIssuedAt:           etIssuedAt,
				ETExpiresAt:          etExpiresAt,
				VerifierConfig:       VerifierConfig{DeltaMaxAllowed: 300},
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PCTX-009")},
		})
	}

	// ── NEG-009 · verifier limit dominates (PCTX-009) ────────────────────────
	{
		// snapshot.delta_max=300s (producer permissive) but verifier_max=60s
		// diff=80s > verifier_max=60s → PCTX-009 (verifier limit MUST dominate)
		// This is the negative mirror of POS-004 (diff=60s = verifier_max → VALID)
		snap := makeSnapshot(snapshotID, executionID, provenanceID,
			snapshotAt, capturedAt80, 300,
			basePolicy(), baseEvalContext(), baseEvalResult(), instPriv)

		write(outDir, "TS-PCTX-NEG-009", TestVector{
			Meta: VectorMeta{
				ID: "TS-PCTX-NEG-009", Layer: "PCTX", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L3",
				Description: "PCTX-009: snapshot.delta_max=300s > verifier.delta_max_allowed=60s; freshness=80s — verifier limit dominates",
			},
			Input: VectorInput{
				InstitutionPublicKey: instPubB64,
				Snapshot:             snap,
				ETIssuedAt:           etIssuedAt,
				ETExpiresAt:          etExpiresAt,
				VerifierConfig:       VerifierConfig{DeltaMaxAllowed: 60},
			},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("PCTX-009")},
		})
	}

	fmt.Println("done — 13 vectors written")
}
