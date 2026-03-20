// capture.go — ACP-REP-PORTABILITY-1.1 snapshot issuance.
package reputation

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gowebpki/jcs"
)

// CaptureRequest holds the inputs for ReputationSnapshot creation.
type CaptureRequest struct {
	SubjectID string
	Issuer    string
	Score     float64
	Scale     string        // "0-1" or "0-100"
	ModelID   string
	ValidFor  time.Duration // e.g. 5*time.Minute
}

// Capture creates and signs a ReputationSnapshot (ACP-REP-PORTABILITY-1.1 §6).
//
// The signing procedure is: json.Marshal → JCS (RFC 8785) → SHA-256 → Ed25519.
// The Signature field is base64url-encoded (no padding), matching ACP-SIGN-1.0.
func Capture(req CaptureRequest, priv ed25519.PrivateKey) (*ReputationSnapshot, error) {
	if req.SubjectID == "" || req.Issuer == "" || req.Scale == "" {
		return nil, ErrInvalidRequest
	}

	repID, err := newRepUUID()
	if err != nil {
		return nil, fmt.Errorf("acp/reputation: generate rep_id: %w", err)
	}

	now := time.Now().Unix()
	rep := &ReputationSnapshot{
		Ver:         "1.1",
		RepID:       repID,
		SubjectID:   req.SubjectID,
		Issuer:      req.Issuer,
		Score:       req.Score,
		Scale:       req.Scale,
		ModelID:     req.ModelID,
		EvaluatedAt: now,
		ValidUntil:  now + int64(req.ValidFor.Seconds()),
	}

	sig, err := signReputation(rep, priv)
	if err != nil {
		return nil, fmt.Errorf("acp/reputation: sign: %w", err)
	}
	rep.Signature = sig

	return rep, nil
}

// signReputation computes Ed25519(SHA-256(JCS(signableReputation))).
// Encoding: base64url, no padding (RawURLEncoding).
func signReputation(rep *ReputationSnapshot, priv ed25519.PrivateKey) (string, error) {
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
		return "", fmt.Errorf("marshal: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("jcs: %w", err)
	}
	digest := sha256.Sum256(canonical)
	sig := ed25519.Sign(priv, digest[:])
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// newRepUUID generates a random UUID v4 for rep_id.
func newRepUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
