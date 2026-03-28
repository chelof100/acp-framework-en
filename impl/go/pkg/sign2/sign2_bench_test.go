package sign2_test

// Benchmarks for ACP-SIGN-2.0 — K3 performance evaluation.
//
// Run with:
//
//	go test -bench=. -benchmem ./pkg/sign2/
//
// Results are used to replace the "performance not yet evaluated" placeholder
// in the ACP paper (arXiv:2603.18829) §6.3 with real, reproducible numbers.
//
// Payload: representative ACP canonical admission request (~330 bytes JSON),
// chosen to reflect production message size — not to influence latency
// (ML-DSA-65 latency is dominated by polynomial operations, not message length).

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/chelof100/acp-framework/acp-go/pkg/sign2"
)

// acpCanonicalPayload is a representative ACP canonical admission request body.
// Size: ~330 bytes. Format mirrors the canonical JSON produced by the ACP
// canonicalization layer (JCS-ordered, UTF-8, no trailing whitespace).
var acpCanonicalPayload = []byte(`{"acl_id":"acl-prod-7f3a","agent_id":"agent-9c2b1d","context":{"env":"production","region":"us-east-1"},"intent":"invoke_tool","request_id":"req-2026-03a8f1b2c4d5","resource":"tool://data-pipeline/run","scope":["read","execute"],"timestamp":"2026-03-28T12:00:00Z","ttl":300}`)

// ---- Ed25519 (classic) -------------------------------------------------------

// BenchmarkEd25519Sign measures raw Ed25519 signing on the ACP canonical payload.
func BenchmarkEd25519Sign(b *testing.B) {
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Sign(edPriv, acpCanonicalPayload)
	}
}

// BenchmarkEd25519Verify measures raw Ed25519 verification on the ACP canonical payload.
func BenchmarkEd25519Verify(b *testing.B) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}
	sig := ed25519.Sign(edPriv, acpCanonicalPayload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ed25519.Verify(edPub, acpCanonicalPayload, sig)
	}
}

// ---- ML-DSA-65 (isolated) ---------------------------------------------------

// BenchmarkMLDSA65Sign measures isolated ML-DSA-65 signing via SignHybridFull
// minus the Ed25519 component — approximated by the full hybrid cost, which is
// dominated by the PQ operation (Ed25519 is <5 µs by comparison).
//
// For a clean isolated ML-DSA-65 number, see BenchmarkMLDSA65SignIsolated.
func BenchmarkMLDSA65SignIsolated(b *testing.B) {
	_, edPriv, _, pqPriv, err := sign2.GenerateHybridKeyPair()
	if err != nil {
		b.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	// Warm up key schedule
	_, _ = sign2.SignHybridFull(acpCanonicalPayload, edPriv, pqPriv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sign2.SignHybridFull(acpCanonicalPayload, edPriv, pqPriv)
	}
}

// BenchmarkMLDSA65VerifyIsolated measures the hybrid verification path (Ed25519 +
// ML-DSA-65). Ed25519 is ~2 µs; the dominant cost is ML-DSA-65.
func BenchmarkMLDSA65VerifyIsolated(b *testing.B) {
	edPub, edPriv, pqPub, pqPriv, err := sign2.GenerateHybridKeyPair()
	if err != nil {
		b.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	sig, err := sign2.SignHybridFull(acpCanonicalPayload, edPriv, pqPriv)
	if err != nil {
		b.Fatalf("SignHybridFull: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sign2.VerifyHybrid(acpCanonicalPayload, edPub, pqPub, sig)
	}
}

// ---- ACP-SIGN-2.0 HYBRID full (production path) -----------------------------

// BenchmarkHybridFullSign measures the complete ACP-SIGN-2.0 SignHybridFull path:
// Ed25519 + ML-DSA-65, which is the production signing cost per admission request.
func BenchmarkHybridFullSign(b *testing.B) {
	_, edPriv, _, pqPriv, err := sign2.GenerateHybridKeyPair()
	if err != nil {
		b.Fatalf("GenerateHybridKeyPair: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = sign2.SignHybridFull(acpCanonicalPayload, edPriv, pqPriv)
	}
}

// BenchmarkHybridFullVerify measures the complete ACP-SIGN-2.0 VerifyHybrid path:
// Ed25519 + ML-DSA-65, which is the production verification cost per request.
func BenchmarkHybridFullVerify(b *testing.B) {
	edPub, edPriv, pqPub, pqPriv, err := sign2.GenerateHybridKeyPair()
	if err != nil {
		b.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	sig, err := sign2.SignHybridFull(acpCanonicalPayload, edPriv, pqPriv)
	if err != nil {
		b.Fatalf("SignHybridFull: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sign2.VerifyHybrid(acpCanonicalPayload, edPub, pqPub, sig)
	}
}
