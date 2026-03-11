package handshake

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Errors
var (
	ErrPoPInvalidSignature = errors.New("acp/handshake: Proof-of-Possession signature invalid")
	ErrPoPMissingHeaders   = errors.New("acp/handshake: missing required ACP headers (X-ACP-Challenge, X-ACP-Signature)")
)

// PoPHeaders are the HTTP headers used in the ACP handshake.
const (
	HeaderChallenge  = "X-ACP-Challenge"
	HeaderSignature  = "X-ACP-Signature"
	HeaderAgentToken = "Authorization" // value: "Bearer <capability_token_json>"
)

// VerifyProofOfPossession validates the agent's Proof-of-Possession (PoP) for
// an incoming HTTP request. Implements ACP-HP-1.0 channel binding:
//
//	signed_payload = Method + "|" + Path + "|" + Challenge + "|" + base64url(SHA-256(body))
//	sig = Ed25519(sk_agent, SHA-256(signed_payload_bytes))
//
// The function:
//  1. Reads and restores r.Body for downstream handlers.
//  2. Consumes the challenge (single-use, anti-replay).
//  3. Reconstructs and verifies the signed payload.
func VerifyProofOfPossession(
	r *http.Request,
	store *ChallengeStore,
	agentPubKey ed25519.PublicKey,
) error {
	// Extract required headers.
	challenge := r.Header.Get(HeaderChallenge)
	sigB64 := r.Header.Get(HeaderSignature)
	if challenge == "" || sigB64 == "" {
		return ErrPoPMissingHeaders
	}

	// Consume challenge first — prevents replay even on subsequent errors.
	if err := store.ConsumeChallenge(challenge); err != nil {
		return fmt.Errorf("acp/handshake: %w", err)
	}

	// Read body and restore it for downstream handlers.
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		bodyBytes = []byte{}
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Build signed payload: Method|Path|Challenge|BodyHash.
	bodyHash := sha256.Sum256(bodyBytes)
	bodyHashB64 := base64.RawURLEncoding.EncodeToString(bodyHash[:])
	signedPayload := fmt.Sprintf("%s|%s|%s|%s",
		r.Method, r.URL.Path, challenge, bodyHashB64)

	// Decode signature.
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return ErrPoPInvalidSignature
	}

	// Verify Ed25519 over SHA-256(signed_payload).
	hash := sha256.Sum256([]byte(signedPayload))
	if !ed25519.Verify(agentPubKey, hash[:], sigBytes) {
		return ErrPoPInvalidSignature
	}
	return nil
}

// BuildPoPPayload constructs the string that must be signed by the agent.
// Exported for use by SDK implementations (e.g., acp-py).
// Format: Method + "|" + Path + "|" + Challenge + "|" + base64url(SHA-256(body))
func BuildPoPPayload(method, path, challenge string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	bodyHashB64 := base64.RawURLEncoding.EncodeToString(bodyHash[:])
	return fmt.Sprintf("%s|%s|%s|%s", method, path, challenge, bodyHashB64)
}
