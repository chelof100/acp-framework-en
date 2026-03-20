// Command gen-reputation-vectors generates compliance/test-vectors/TS-REP-*.json.
//
// Produces 3 positive and 6 negative test vectors covering ACP-REP-PORTABILITY-1.1
// validation (REP-001, REP-002, REP-004, REP-010, REP-011), including backward
// compatibility with ver "1.0".
//
// Uses the RFC 8037 test key A (same seed as all other vector generators)
// for the issuer signature.
//
// Run from the impl/go module root:
//
//	go run ./cmd/gen-reputation-vectors
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

// Issuer key — RFC 8037 test key A (same as all other generators).
const issuerKeySeedHex = "9d61b19deffd5998b34a442fa1c54cd044c9c565b66f2699171d66c968225234"

// ─── Fixed timestamps ─────────────────────────────────────────────────────────
//
// Base epoch: 1741200000 = 2025-03-05T12:00:00Z (deterministic, used across vectors)

const (
	evalAt      = int64(1741200000) // evaluated_at
	validUntil  = int64(1741203600) // +1 hour (3600s)
	nowValid    = int64(1741201800) // +30 min — inside window (POS)
	nowBorder   = validUntil        // exactly == valid_until (POS-002)
	nowExpired  = int64(1741204000) // after valid_until (NEG-002)
)

// ─── Fixed identifiers ───────────────────────────────────────────────────────

const (
	repID    = "3f7a1c9e-0b2d-4e8a-a5f6-000000000001"
	subject  = "agent.test.subject"
	issuerID = "inst-test-alpha"
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

// signSnapshot signs a ReputationSnapshot map (excluding "signature").
// Procedure: json.Marshal → JCS (RFC 8785) → SHA-256 → Ed25519 → base64url (no padding).
func signSnapshot(m map[string]any, priv ed25519.PrivateKey) string {
	signable := make(map[string]any, len(m))
	for k, v := range m {
		if k != "signature" {
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

type VectorInput struct {
	IssuerPublicKey string         `json:"issuer_public_key"`
	Snapshot        map[string]any `json:"snapshot"`
}

type VectorContext struct {
	CurrentTime int64 `json:"current_time"`
}

type VectorExpected struct {
	Decision  string  `json:"decision"`
	ErrorCode *string `json:"error_code"`
}

type TestVector struct {
	Meta     VectorMeta     `json:"meta"`
	Input    VectorInput    `json:"input"`
	Context  VectorContext  `json:"context"`
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

// makeSnapshot builds a signed v1.1 ReputationSnapshot map.
func makeSnapshot(
	id, subjectID, issuer string,
	score float64, scale, modelID string,
	evaluatedAt, validUntilTs int64,
	priv ed25519.PrivateKey,
) map[string]any {
	m := map[string]any{
		"ver":          "1.1",
		"rep_id":       id,
		"subject_id":   subjectID,
		"issuer":       issuer,
		"score":        score,
		"scale":        scale,
		"model_id":     modelID,
		"evaluated_at": evaluatedAt,
		"valid_until":  validUntilTs,
	}
	m["signature"] = signSnapshot(m, priv)
	return m
}

// makeSnapshotV10 builds a signed v1.0 ReputationSnapshot map (no expiration fields).
func makeSnapshotV10(
	id, subjectID, issuer string,
	score float64,
	evaluatedAt int64,
	priv ed25519.PrivateKey,
) map[string]any {
	m := map[string]any{
		"ver":          "1.0",
		"rep_id":       id,
		"subject_id":   subjectID,
		"issuer":       issuer,
		"score":        score,
		"evaluated_at": evaluatedAt,
	}
	m["signature"] = signSnapshot(m, priv)
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

	issuerPub, issuerPriv := loadKey(issuerKeySeedHex)
	issuerPubB64 := pubB64(issuerPub)

	// ── POS-001 · Valid v1.1 snapshot, score=0.82, scale="0-1" ──────────────
	{
		snap := makeSnapshot(repID, subject, issuerID,
			0.82, "0-1", "risk-v3",
			evalAt, validUntil, issuerPriv)

		write(outDir, "TS-REP-POS-001", TestVector{
			Meta: VectorMeta{
				ID: "TS-REP-POS-001", Layer: "REP", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L4",
				Description: "Valid v1.1 snapshot: score=0.82, scale=0-1, real Ed25519 signature",
			},
			Input:   VectorInput{IssuerPublicKey: issuerPubB64, Snapshot: snap},
			Context: VectorContext{CurrentTime: nowValid},
			Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
		})
	}

	// ── POS-002 · Borderline: now == valid_until ──────────────────────────────
	{
		snap := makeSnapshot(repID, subject, issuerID,
			0.75, "0-1", "risk-v3",
			evalAt, validUntil, issuerPriv)

		write(outDir, "TS-REP-POS-002", TestVector{
			Meta: VectorMeta{
				ID: "TS-REP-POS-002", Layer: "REP", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L4",
				Description: "Borderline expiration: now == valid_until (limit is inclusive per §5.2)",
			},
			Input:   VectorInput{IssuerPublicKey: issuerPubB64, Snapshot: snap},
			Context: VectorContext{CurrentTime: nowBorder},
			Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
		})
	}

	// ── POS-003 · ver="1.0" — no valid_until enforcement ─────────────────────
	{
		snap := makeSnapshotV10(repID, subject, issuerID, 0.60, evalAt, issuerPriv)

		write(outDir, "TS-REP-POS-003", TestVector{
			Meta: VectorMeta{
				ID: "TS-REP-POS-003", Layer: "REP", Severity: "mandatory",
				ACPVersion: "1.0", ConformanceLevel: "L4",
				Description: "Backward compatibility: ver=1.0 snapshot — expiration NOT enforced (§12)",
			},
			Input:   VectorInput{IssuerPublicKey: issuerPubB64, Snapshot: snap},
			Context: VectorContext{CurrentTime: nowExpired},
			Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
		})
	}

	// ── NEG-001 · evaluated_at > valid_until (REP-001) ───────────────────────
	{
		// Build with inverted timestamps — sign before corrupting would sign invalid data,
		// so we build with valid order, sign, then swap timestamps.
		// Actually: build map directly with the invalid temporal order and sign it —
		// the signature is over the invalid payload (NEG tests verify logic, not sig correctness).
		m := map[string]any{
			"ver":          "1.1",
			"rep_id":       repID,
			"subject_id":   subject,
			"issuer":       issuerID,
			"score":        float64(0.82),
			"scale":        "0-1",
			"model_id":     "risk-v3",
			"evaluated_at": validUntil + 100, // evaluated_at > valid_until
			"valid_until":  validUntil,
		}
		m["signature"] = signSnapshot(m, issuerPriv)

		write(outDir, "TS-REP-NEG-001", TestVector{
			Meta: VectorMeta{
				ID: "TS-REP-NEG-001", Layer: "REP", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L4",
				Description: "REP-001: evaluated_at > valid_until (temporal order violated)",
			},
			Input:   VectorInput{IssuerPublicKey: issuerPubB64, Snapshot: m},
			Context: VectorContext{CurrentTime: nowValid},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("REP-001")},
		})
	}

	// ── NEG-002 · now > valid_until (REP-011) ────────────────────────────────
	{
		snap := makeSnapshot(repID, subject, issuerID,
			0.82, "0-1", "risk-v3",
			evalAt, validUntil, issuerPriv)

		write(outDir, "TS-REP-NEG-002", TestVector{
			Meta: VectorMeta{
				ID: "TS-REP-NEG-002", Layer: "REP", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L4",
				Description: "REP-011: snapshot expired — now > valid_until",
			},
			Input:   VectorInput{IssuerPublicKey: issuerPubB64, Snapshot: snap},
			Context: VectorContext{CurrentTime: nowExpired},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("REP-011")},
		})
	}

	// ── NEG-003 · score out of bounds (REP-002) ───────────────────────────────
	{
		m := map[string]any{
			"ver":          "1.1",
			"rep_id":       repID,
			"subject_id":   subject,
			"issuer":       issuerID,
			"score":        float64(1.5), // > 1.0 for scale "0-1"
			"scale":        "0-1",
			"model_id":     "risk-v3",
			"evaluated_at": evalAt,
			"valid_until":  validUntil,
		}
		m["signature"] = signSnapshot(m, issuerPriv)

		write(outDir, "TS-REP-NEG-003", TestVector{
			Meta: VectorMeta{
				ID: "TS-REP-NEG-003", Layer: "REP", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L4",
				Description: "REP-002: score=1.5 exceeds scale=0-1 upper bound",
			},
			Input:   VectorInput{IssuerPublicKey: issuerPubB64, Snapshot: m},
			Context: VectorContext{CurrentTime: nowValid},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("REP-002")},
		})
	}

	// ── NEG-004 · issuer="" (REP-004) ─────────────────────────────────────────
	{
		m := map[string]any{
			"ver":          "1.1",
			"rep_id":       repID,
			"subject_id":   subject,
			"issuer":       "",
			"score":        float64(0.82),
			"scale":        "0-1",
			"model_id":     "risk-v3",
			"evaluated_at": evalAt,
			"valid_until":  validUntil,
		}
		m["signature"] = signSnapshot(m, issuerPriv)

		write(outDir, "TS-REP-NEG-004", TestVector{
			Meta: VectorMeta{
				ID: "TS-REP-NEG-004", Layer: "REP", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L4",
				Description: "REP-004: issuer field is empty",
			},
			Input:   VectorInput{IssuerPublicKey: issuerPubB64, Snapshot: m},
			Context: VectorContext{CurrentTime: nowValid},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("REP-004")},
		})
	}

	// ── NEG-005 · signature="" (REP-010) ─────────────────────────────────────
	{
		snap := makeSnapshot(repID, subject, issuerID,
			0.82, "0-1", "risk-v3",
			evalAt, validUntil, issuerPriv)
		snap["signature"] = ""

		write(outDir, "TS-REP-NEG-005", TestVector{
			Meta: VectorMeta{
				ID: "TS-REP-NEG-005", Layer: "REP", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L4",
				Description: "REP-010: signature field is empty",
			},
			Input:   VectorInput{IssuerPublicKey: issuerPubB64, Snapshot: snap},
			Context: VectorContext{CurrentTime: nowValid},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("REP-010")},
		})
	}

	// ── NEG-006 · scale="unknown" (REP-002) ──────────────────────────────────
	{
		m := map[string]any{
			"ver":          "1.1",
			"rep_id":       repID,
			"subject_id":   subject,
			"issuer":       issuerID,
			"score":        float64(0.82),
			"scale":        "unknown",
			"model_id":     "risk-v3",
			"evaluated_at": evalAt,
			"valid_until":  validUntil,
		}
		m["signature"] = signSnapshot(m, issuerPriv)

		write(outDir, "TS-REP-NEG-006", TestVector{
			Meta: VectorMeta{
				ID: "TS-REP-NEG-006", Layer: "REP", Severity: "mandatory",
				ACPVersion: "1.1", ConformanceLevel: "L4",
				Description: "REP-002: scale=unknown is not a supported scale value",
			},
			Input:   VectorInput{IssuerPublicKey: issuerPubB64, Snapshot: m},
			Context: VectorContext{CurrentTime: nowValid},
			Expected: VectorExpected{Decision: "INVALID", ErrorCode: errCode("REP-002")},
		})
	}

	fmt.Println("done — 9 vectors written")
}
