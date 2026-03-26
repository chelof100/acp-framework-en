// Package sign2 implements ACP-SIGN-2.0 hybrid signing.
//
// ACP-SIGN-2.0 defines three signing modes for the post-quantum transition:
//
//	CLASSIC_ONLY  — Ed25519 only (current production default)
//	HYBRID        — Ed25519 (real) + ML-DSA-65 (real, via circl, this package)
//	PQC_ONLY      — ML-DSA-65 only (future)
//
// This package provides HYBRID mode with two signing paths:
//
//   - SignHybrid: Ed25519 only, PQCSig nil (backward-compatible transition period).
//   - SignHybridFull: Ed25519 + ML-DSA-65 (Dilithium mode3 via github.com/cloudflare/circl).
//
// Verification is conditional: if PQCSig is non-nil, both signatures MUST verify.
// If PQCSig is nil, Ed25519 verification alone is sufficient (transition period).
//
// ACP-SIGN-2.0 §3.1 — HYBRID mode.
package sign2

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// Mode identifies the signing mode per ACP-SIGN-2.0 §2.
type Mode string

const (
	ModeClassicOnly Mode = "CLASSIC_ONLY"
	ModeHybrid      Mode = "HYBRID"
	ModePQCOnly     Mode = "PQC_ONLY"
)

// HybridSignature holds the output of SignHybrid or SignHybridFull.
//
// Ed25519Sig is always populated in HYBRID mode.
// PQCSig carries a real ML-DSA-65 (Dilithium mode3) signature when produced
// by SignHybridFull. It is nil when produced by SignHybrid (transition period).
//
// Wire format: alg "ed25519+ml-dsa-65" when PQCSig is non-nil.
type HybridSignature struct {
	Ed25519Sig []byte `json:"ed25519_sig"`
	PQCSig     []byte `json:"pqc_sig,omitempty"` // ML-DSA-65 (mode3), nil during transition
	Mode       Mode   `json:"mode"`
}

// SignHybrid signs msg with Ed25519 only (PQCSig is nil).
//
// Use this for backward-compatible deployments during the HYBRID transition period.
// Verifiers receiving this signature apply Ed25519 verification only.
//
// ACP-SIGN-2.0 §3.1 — HYBRID mode, transition path.
func SignHybrid(msg []byte, ed25519Key ed25519.PrivateKey) (*HybridSignature, error) {
	if len(ed25519Key) != ed25519.PrivateKeySize {
		return nil, errors.New("sign2: invalid Ed25519 private key size")
	}
	if len(msg) == 0 {
		return nil, errors.New("sign2: message must not be empty")
	}

	return &HybridSignature{
		Ed25519Sig: ed25519.Sign(ed25519Key, msg),
		PQCSig:     nil, // transition period: PQC not included
		Mode:       ModeHybrid,
	}, nil
}

// SignHybridFull signs msg with Ed25519 and ML-DSA-65 (Dilithium mode3).
//
// Both signatures are always produced. Verifiers receiving this output
// MUST verify both signatures (logical AND per ACP-SIGN-2.0 §4.2).
//
// ACP-SIGN-2.0 §3.1 — HYBRID mode, full post-quantum path.
func SignHybridFull(msg []byte, edKey ed25519.PrivateKey, pqKey *mode3.PrivateKey) (*HybridSignature, error) {
	if len(edKey) != ed25519.PrivateKeySize {
		return nil, errors.New("sign2: invalid Ed25519 private key size")
	}
	if pqKey == nil {
		return nil, errors.New("sign2: nil ML-DSA-65 private key")
	}
	if len(msg) == 0 {
		return nil, errors.New("sign2: message must not be empty")
	}

	// Ed25519 signature (ACP-SIGN-2.0 §3.1.a)
	edSig := ed25519.Sign(edKey, msg)

	// ML-DSA-65 signature via circl mode3 (ACP-SIGN-2.0 §3.1.b)
	// SignTo writes into a pre-allocated buffer of exactly mode3.SignatureSize bytes.
	pqSig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(pqKey, msg, pqSig)

	return &HybridSignature{
		Ed25519Sig: edSig,
		PQCSig:     pqSig,
		Mode:       ModeHybrid,
	}, nil
}

// GenerateHybridKeyPair generates a fresh Ed25519 keypair and a fresh ML-DSA-65 keypair.
//
// Intended for testing and key provisioning. Key management (storage, distribution)
// is the caller's responsibility per ACP-SIGN-2.0 §5.
func GenerateHybridKeyPair() (edPub ed25519.PublicKey, edPriv ed25519.PrivateKey, pqPub *mode3.PublicKey, pqPriv *mode3.PrivateKey, err error) {
	edPub, edPriv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return
	}
	pqPub, pqPriv, err = mode3.GenerateKey(rand.Reader)
	return
}

// VerifyHybrid verifies a HybridSignature against msg.
//
// Verification rules per ACP-SIGN-2.0 §4.2 (HYBRID mode):
//   - Ed25519 signature MUST always be valid.
//   - If sig.PQCSig is non-nil, pqPub MUST be provided and ML-DSA-65 MUST verify.
//   - If sig.PQCSig is nil, Ed25519 verification alone is sufficient (transition period).
//
// Passing pqPub=nil when sig.PQCSig is non-nil returns an error (SIGN-013).
func VerifyHybrid(msg []byte, edPub ed25519.PublicKey, pqPub *mode3.PublicKey, sig *HybridSignature) error {
	if sig == nil {
		return errors.New("sign2: nil signature")
	}
	if sig.Mode != ModeHybrid {
		return errors.New("sign2: expected HYBRID mode signature")
	}
	if len(msg) == 0 {
		return errors.New("sign2: message must not be empty")
	}

	// Ed25519 — always required (ACP-SIGN-2.0 §4.2.a)
	if !ed25519.Verify(edPub, msg, sig.Ed25519Sig) {
		return errors.New("sign2: Ed25519 verification failed (SIGN-011)")
	}

	// ML-DSA-65 — required when PQCSig is present (ACP-SIGN-2.0 §4.2.b)
	if sig.PQCSig != nil {
		if pqPub == nil {
			return errors.New("sign2: PQCSig present but no ML-DSA-65 public key provided (SIGN-013)")
		}
		if !mode3.Verify(pqPub, msg, sig.PQCSig) {
			return errors.New("sign2: ML-DSA-65 verification failed (SIGN-012)")
		}
	}

	return nil
}
