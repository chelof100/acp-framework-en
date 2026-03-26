package sign2_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/chelof100/acp-framework/acp-go/pkg/sign2"
)

// TestSignHybrid_ClassicPath verifies the backward-compatible transition path:
// SignHybrid produces a valid Ed25519 signature with PQCSig nil.
func TestSignHybrid_ClassicPath(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	msg := []byte("acp-sign2-classic-path")
	sig, err := sign2.SignHybrid(msg, edPriv)
	if err != nil {
		t.Fatalf("SignHybrid: %v", err)
	}

	if sig.PQCSig != nil {
		t.Error("classic path: expected PQCSig nil")
	}
	if sig.Mode != sign2.ModeHybrid {
		t.Errorf("mode: got %q, want %q", sig.Mode, sign2.ModeHybrid)
	}

	// VerifyHybrid with pqPub=nil — accepted in transition period
	if err := sign2.VerifyHybrid(msg, edPub, nil, sig); err != nil {
		t.Errorf("VerifyHybrid (classic path): %v", err)
	}
}

// TestSignHybridFull_PQPath verifies the full ML-DSA-65 hybrid path:
// SignHybridFull produces real Ed25519 + ML-DSA-65 signatures, both verify.
func TestSignHybridFull_PQPath(t *testing.T) {
	edPub, edPriv, pqPub, pqPriv, err := sign2.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}

	msg := []byte("acp-sign2-hybrid-pq-path")
	sig, err := sign2.SignHybridFull(msg, edPriv, pqPriv)
	if err != nil {
		t.Fatalf("SignHybridFull: %v", err)
	}

	if sig.PQCSig == nil {
		t.Fatal("full PQ path: expected non-nil PQCSig")
	}
	if len(sig.Ed25519Sig) == 0 {
		t.Fatal("full PQ path: expected non-empty Ed25519Sig")
	}
	if sig.Mode != sign2.ModeHybrid {
		t.Errorf("mode: got %q, want %q", sig.Mode, sign2.ModeHybrid)
	}

	// Both signatures must verify
	if err := sign2.VerifyHybrid(msg, edPub, pqPub, sig); err != nil {
		t.Errorf("VerifyHybrid (full PQ path): %v", err)
	}
}

// TestVerifyHybrid_TamperedMessage verifies that a tampered message fails both paths.
func TestVerifyHybrid_TamperedMessage(t *testing.T) {
	edPub, edPriv, pqPub, pqPriv, err := sign2.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}

	msg := []byte("original-message")
	sig, err := sign2.SignHybridFull(msg, edPriv, pqPriv)
	if err != nil {
		t.Fatalf("SignHybridFull: %v", err)
	}

	tampered := []byte("tampered-message")
	if err := sign2.VerifyHybrid(tampered, edPub, pqPub, sig); err == nil {
		t.Error("expected verification failure on tampered message, got nil")
	}
}

// TestVerifyHybrid_PQCSigPresentNoPQPub verifies SIGN-013: PQCSig present but no PQ key.
func TestVerifyHybrid_PQCSigPresentNoPQPub(t *testing.T) {
	edPub, edPriv, _, pqPriv, err := sign2.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}

	msg := []byte("acp-sign2-error-path")
	sig, err := sign2.SignHybridFull(msg, edPriv, pqPriv)
	if err != nil {
		t.Fatalf("SignHybridFull: %v", err)
	}

	// pqPub=nil with non-nil PQCSig must return SIGN-013 error
	if err := sign2.VerifyHybrid(msg, edPub, nil, sig); err == nil {
		t.Error("expected SIGN-013 error, got nil")
	}
}
