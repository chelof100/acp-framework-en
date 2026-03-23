// Package sign2 implements ACP-SIGN-2.0 hybrid signing.
//
// ACP-SIGN-2.0 defines three signing modes for the post-quantum transition:
//
//	CLASSIC_ONLY  — Ed25519 only (current production default)
//	HYBRID        — Ed25519 (real) + ML-DSA-65 (staged migration, this package)
//	PQC_ONLY      — ML-DSA-65 only (v1.18+, requires circl integration)
//
// This package provides HYBRID mode: Ed25519 signing is fully operational.
// ML-DSA-65 (NIST FIPS 204 / Dilithium3) is stubbed with a TODO marker for v1.18,
// when github.com/cloudflare/circl/sign/dilithium will be integrated.
//
// Narrative: crypto-agility by design — migration path defined, implementation staged.
// The HybridSignature wire format is stable; callers can begin using it now and
// receive PQC signatures transparently once the ML-DSA-65 integration lands.
//
// ACP-SIGN-2.0 §3.1 — HYBRID mode.
package sign2

import (
	"crypto/ed25519"
	"errors"
)

// Mode identifies the signing mode per ACP-SIGN-2.0 §2.
type Mode string

const (
	ModeClassicOnly Mode = "CLASSIC_ONLY"
	ModeHybrid      Mode = "HYBRID"
	ModePQCOnly     Mode = "PQC_ONLY"
)

// HybridSignature holds the output of SignHybrid.
//
// Ed25519Sig is always populated in HYBRID mode.
// PQCSig is nil until ML-DSA-65 integration (v1.18).
// When PQCSig is nil and Mode is HYBRID, verifiers MUST accept the signature
// (transition period per ACP-SIGN-2.0 §4.2).
type HybridSignature struct {
	Ed25519Sig []byte `json:"ed25519_sig"`
	PQCSig     []byte `json:"pqc_sig,omitempty"` // nil until v1.18
	Mode       Mode   `json:"mode"`
}

// SignHybrid signs msg with Ed25519 (operational) and ML-DSA-65 (stub, v1.18).
//
// ACP-SIGN-2.0 §3.1 — HYBRID mode signing procedure.
//
// Ed25519 uses the provided key directly (no prehash).
// ML-DSA-65 signature is currently nil — the TODO below tracks the integration point.
// Callers should store and transmit PQCSig as nil-safe; receivers must tolerate nil
// per the HYBRID transition rules in ACP-SIGN-2.0 §4.2.
func SignHybrid(msg []byte, ed25519Key ed25519.PrivateKey) (*HybridSignature, error) {
	if len(ed25519Key) != ed25519.PrivateKeySize {
		return nil, errors.New("sign2: invalid Ed25519 private key size")
	}
	if len(msg) == 0 {
		return nil, errors.New("sign2: message must not be empty")
	}

	// Ed25519 — real implementation (ACP-SIGN-2.0 §3.1.a)
	ed25519Sig := ed25519.Sign(ed25519Key, msg)

	// ML-DSA-65 — placeholder (ACP-SIGN-2.0 §3.1.b)
	// TODO(v1.18): integrate github.com/cloudflare/circl/sign/dilithium
	//   import "github.com/cloudflare/circl/sign/dilithium"
	//   scheme := dilithium.Mode3 // ML-DSA-65 / Dilithium3
	//   pqcKey := ... derive or store alongside ed25519Key
	//   pqcSig := scheme.Sign(pqcKey, msg)
	var pqcSig []byte // nil = PQC not yet active; HYBRID mode allows this

	return &HybridSignature{
		Ed25519Sig: ed25519Sig,
		PQCSig:     pqcSig,
		Mode:       ModeHybrid,
	}, nil
}

// VerifyHybrid verifies a HybridSignature against msg and the Ed25519 public key.
//
// Verification rules per ACP-SIGN-2.0 §4.2 (HYBRID transition):
//   - Ed25519 signature MUST be valid.
//   - If PQCSig is non-nil, it MUST also be valid (enforced in v1.18).
//   - If PQCSig is nil, the signature is accepted (transition period).
func VerifyHybrid(msg []byte, pub ed25519.PublicKey, sig *HybridSignature) error {
	if sig == nil {
		return errors.New("sign2: nil signature")
	}
	if sig.Mode != ModeHybrid {
		return errors.New("sign2: expected HYBRID mode signature")
	}

	// Verify Ed25519 (ACP-SIGN-2.0 §4.2.a)
	if !ed25519.Verify(pub, msg, sig.Ed25519Sig) {
		return errors.New("sign2: Ed25519 signature verification failed (SIGN-011)")
	}

	// TODO(v1.18): verify ML-DSA-65 when PQCSig != nil
	// if sig.PQCSig != nil {
	//     if !scheme.Verify(pqcPub, msg, sig.PQCSig) {
	//         return errors.New("sign2: ML-DSA-65 signature verification failed (SIGN-012)")
	//     }
	// }

	return nil
}
