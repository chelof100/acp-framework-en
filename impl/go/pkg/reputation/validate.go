// validate.go — ACP-REP-PORTABILITY-1.1 snapshot validation (§6).
package reputation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gowebpki/jcs"
)

// Validate checks the structural invariants of a ReputationSnapshot (§5, §6).
//
// This function does NOT verify the cryptographic signature — call VerifySig for that.
// The separation allows lightweight structural validation at ingestion time without
// requiring the issuer's public key.
//
// Backward compatibility: ver "1.0" snapshots skip expiration, temporal order,
// and scale bounds checks (§12).
func Validate(rep *ReputationSnapshot, now time.Time) error {
	if rep.Ver != "1.0" && rep.Ver != "1.1" {
		return fmt.Errorf("acp/reputation: unsupported version %q", rep.Ver)
	}

	// §5.4 — issuer not empty (all versions)
	if rep.Issuer == "" {
		return ErrIssuerMissing
	}

	if rep.Ver == "1.1" {
		// §5.1 — temporal order
		if rep.EvaluatedAt > rep.ValidUntil {
			return ErrInvalidTemporalOrder
		}
		// §5.2 — expiration
		if now.Unix() > rep.ValidUntil {
			return ErrExpired
		}
		// §5.3 — score within scale bounds
		if err := checkScaleBounds(rep.Score, rep.Scale); err != nil {
			return err
		}
	}

	// §5.5 — signature present (full cryptographic check is in VerifySig)
	if rep.Signature == "" {
		return ErrInvalidSignature
	}

	return nil
}

// VerifySig verifies the Ed25519 signature on a ReputationSnapshot.
//
// The signing procedure is: json.Marshal(signable) → JCS → SHA-256 → Ed25519.verify.
// This is identical to the procedure in ACP-POLICY-CTX-1.1 and ACP-SIGN-1.0.
func VerifySig(rep *ReputationSnapshot, pubKey ed25519.PublicKey) error {
	s := signableReputation{
		Ver:         rep.Ver,
		RepID:       rep.RepID,
		SubjectID:   rep.SubjectID,
		Issuer:      rep.Issuer,
		Score:       rep.Score,
		Scale:       rep.Scale,
		ModelID:     rep.ModelID,
		EvaluatedAt: rep.EvaluatedAt,
		ValidUntil:  rep.ValidUntil,
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("%w: marshal signable: %v", ErrInvalidSignature, err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return fmt.Errorf("%w: jcs: %v", ErrInvalidSignature, err)
	}
	digest := sha256.Sum256(canonical)
	sigBytes, err := base64.RawURLEncoding.DecodeString(rep.Signature)
	if err != nil {
		return fmt.Errorf("%w: decode: %v", ErrInvalidSignature, err)
	}
	if !ed25519.Verify(pubKey, digest[:], sigBytes) {
		return ErrInvalidSignature
	}
	return nil
}

// checkScaleBounds returns ErrScoreOutOfBounds if score is outside the scale's range
// or if scale is an unsupported value.
func checkScaleBounds(score float64, scale string) error {
	switch scale {
	case "0-1":
		if score < 0.0 || score > 1.0 {
			return fmt.Errorf("%w: score=%.4f outside 0-1", ErrScoreOutOfBounds, score)
		}
	case "0-100":
		if score < 0.0 || score > 100.0 {
			return fmt.Errorf("%w: score=%.4f outside 0-100", ErrScoreOutOfBounds, score)
		}
	default:
		return fmt.Errorf("%w: unsupported scale %q", ErrScoreOutOfBounds, scale)
	}
	return nil
}
