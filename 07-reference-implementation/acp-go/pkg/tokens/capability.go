// Package tokens implements ACP Capability Token parsing and verification.
// Implements ACP-CT-1.0 §4–§8: full 9-step verification procedure.
package tokens

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"github.com/gowebpki/jcs"
)

// ─── Error codes per ACP-CT-1.0 §8 ─────────────────────────────────────────

var (
	ErrCT001UnsupportedVersion   = errors.New("CT-001: unsupported token version")
	ErrCT002InvalidSignature     = errors.New("CT-002: invalid token signature")
	ErrCT003TokenExpired         = errors.New("CT-003: token expired")
	ErrCT004TokenNotYetValid     = errors.New("CT-004: token not yet valid (iat in future)")
	ErrCT005CapabilityNotPresent = errors.New("CT-005: requested capability not present in token")
	ErrCT006ResourceNotCovered   = errors.New("CT-006: requested resource not covered by token")
	ErrCT007DelegationNotAllowed = errors.New("CT-007: delegation not permitted")
	ErrCT008MaxDepthExceeded     = errors.New("CT-008: max_depth exceeded (absolute limit: 8)")
	ErrCT009InvalidParentHash    = errors.New("CT-009: invalid parent_hash")
	ErrCT010TokenRevoked         = errors.New("CT-010: token revoked")
	ErrCT011ConstraintViolated   = errors.New("CT-011: constraint violated")
	ErrCT012EmptyCapArray        = errors.New("CT-012: cap array is empty")
	ErrCT013MalformedAgentID     = errors.New("CT-013: malformed AgentID")
)

// MaxDelegationDepth is the absolute delegation depth limit per ACP-CT-1.0 §7.
const MaxDelegationDepth = 8

// ─── Token Structures ────────────────────────────────────────────────────────

// Delegation defines capability chaining rules per ACP-CT-1.0 §5.9.
type Delegation struct {
	Allowed  bool `json:"allowed"`
	MaxDepth int  `json:"max_depth"`
}

// Revocation holds revocation check configuration per ACP-CT-1.0 §5.12.
type Revocation struct {
	Type string `json:"type"` // "endpoint" or "crl"
	URI  string `json:"uri"`
}

// CapabilityToken represents the full ACP-CT-1.0 §4 token structure.
type CapabilityToken struct {
	Version    string                 `json:"ver"`
	Issuer     string                 `json:"iss"`
	Subject    string                 `json:"sub"`
	Cap        []string               `json:"cap"`
	Resource   string                 `json:"res"`
	IssuedAt   int64                  `json:"iat"`
	Expiration int64                  `json:"exp"`
	Nonce      string                 `json:"nonce"`
	Deleg      Delegation             `json:"deleg"`
	ParentHash *string                `json:"parent_hash"`
	Constraints map[string]interface{} `json:"constraints"`
	Rev        *Revocation            `json:"rev,omitempty"`
	Signature  string                 `json:"sig,omitempty"`
}

// VerificationRequest holds the runtime context for token verification.
type VerificationRequest struct {
	// Capability being requested (must be in token.Cap)
	RequestedCapability string
	// Resource being accessed (must be covered by token.Res)
	RequestedResource string
	// RevocationChecker is called if token has a rev field (nil = skip check)
	RevocationChecker RevocationChecker
	// NonceStore prevents token replay (nil = skip check)
	NonceStore NonceStore
}

// RevocationChecker interface for ACP-REV-1.0 compliance.
type RevocationChecker interface {
	IsRevoked(tokenID string, rev *Revocation) (bool, error)
}

// NonceStore interface for token replay prevention.
type NonceStore interface {
	HasSeen(nonce string) bool
	MarkSeen(nonce string)
}

// ─── Parsing and Verification ────────────────────────────────────────────────

// ParseAndVerify parses a raw JSON capability token and executes the full
// 9-step verification procedure from ACP-CT-1.0 §6.
//
// issuerPubKey must be the Ed25519 public key of the token issuer.
// req contains runtime verification context (capability, resource, etc.).
//
// Returns the verified token or an error with the corresponding CT-xxx code.
func ParseAndVerify(rawJSON []byte, issuerPubKey ed25519.PublicKey, req VerificationRequest) (*CapabilityToken, error) {
	// ── Step 1: Parse and verify ver == "1.0" ────────────────────────────
	var rawMap map[string]interface{}
	if err := json.Unmarshal(rawJSON, &rawMap); err != nil {
		return nil, err
	}
	ver, _ := rawMap["ver"].(string)
	if ver != "1.0" {
		return nil, ErrCT001UnsupportedVersion
	}

	// ── Step 2: Verify Ed25519 signature (ACP-SIGN-1.0) ─────────────────
	// Extract sig and remove it before canonicalization (sig covers all fields except itself).
	sigStr, ok := rawMap["sig"].(string)
	if !ok || sigStr == "" {
		return nil, ErrCT002InvalidSignature
	}
	delete(rawMap, "sig")

	sigBytes, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		return nil, ErrCT002InvalidSignature
	}

	// Canonicalize with JCS (RFC 8785), hash with SHA-256, verify with Ed25519.
	// jcs.Transform requires JSON bytes, so marshal the map first.
	rawMapJSON, err := json.Marshal(rawMap)
	if err != nil {
		return nil, err
	}
	canonicalBytes, err := jcs.Transform(rawMapJSON)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(canonicalBytes)
	if !ed25519.Verify(issuerPubKey, hash[:], sigBytes) {
		return nil, ErrCT002InvalidSignature
	}

	// ── Unmarshal into typed struct after signature is verified ──────────
	var token CapabilityToken
	if err := json.Unmarshal(rawJSON, &token); err != nil {
		return nil, err
	}

	// ── Step 3: Verify current timestamp <= exp ──────────────────────────
	now := time.Now().Unix()
	if token.Expiration == 0 || now > token.Expiration {
		return nil, ErrCT003TokenExpired
	}

	// ── Step 4: Verify current timestamp >= iat - 300 (clock drift) ─────
	if token.IssuedAt == 0 || now < (token.IssuedAt-300) {
		return nil, ErrCT004TokenNotYetValid
	}

	// ── Step 5: Verify revocation status (ACP-REV-1.0) ──────────────────
	if token.Rev != nil && req.RevocationChecker != nil {
		revoked, err := req.RevocationChecker.IsRevoked(token.Nonce, token.Rev)
		if err != nil {
			return nil, err
		}
		if revoked {
			return nil, ErrCT010TokenRevoked
		}
	}

	// ── Step 6: Verify requested capability ∈ cap ───────────────────────
	if len(token.Cap) == 0 {
		return nil, ErrCT012EmptyCapArray
	}
	if req.RequestedCapability != "" {
		if !containsCapability(token.Cap, req.RequestedCapability) {
			return nil, ErrCT005CapabilityNotPresent
		}
	}

	// ── Step 7: Verify requested resource is covered by res ─────────────
	if req.RequestedResource != "" {
		if !resourceCovered(token.Resource, req.RequestedResource) {
			return nil, ErrCT006ResourceNotCovered
		}
	}

	// ── Step 8: If delegated token, verify parent_hash ───────────────────
	// (Full chain validation is done by the delegation package.)
	// Here we only validate internal consistency.
	if token.Deleg.MaxDepth > MaxDelegationDepth {
		return nil, ErrCT008MaxDepthExceeded
	}
	if !token.Deleg.Allowed && token.Deleg.MaxDepth != 0 {
		return nil, ErrCT007DelegationNotAllowed
	}

	// ── Step 9: Verify constraints ──────────────────────────────────────
	// Constraint validation is capability-specific (ACP-CAP-REG-1.0).
	// For this reference implementation, constraints are stored and returned
	// for upstream validation by the caller.
	// Implementors MUST validate capability-specific constraints before execution.

	// ── Nonce replay prevention ─────────────────────────────────────────
	// Checked after structural validation to avoid oracle attacks.
	if req.NonceStore != nil {
		if req.NonceStore.HasSeen(token.Nonce) {
			return nil, ErrCT011ConstraintViolated // Replay detected
		}
		req.NonceStore.MarkSeen(token.Nonce)
	}

	return &token, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// containsCapability returns true if cap is present in the token's cap array.
func containsCapability(caps []string, cap string) bool {
	for _, c := range caps {
		if c == cap {
			return true
		}
	}
	return false
}

// resourceCovered returns true if requestedRes is covered by tokenRes.
// ACP-CT-1.0 §5.7: res format is "<institution_domain>/<resource_path>".
// A token with res="org.example/accounts" covers "org.example/accounts/ACC-001".
func resourceCovered(tokenRes, requestedRes string) bool {
	if tokenRes == requestedRes {
		return true
	}
	// Token resource is a prefix of the requested resource
	if len(requestedRes) > len(tokenRes) && requestedRes[:len(tokenRes)] == tokenRes {
		return requestedRes[len(tokenRes)] == '/'
	}
	return false
}

// ComputeTokenHash computes SHA-256(JCS(token without sig)) for use in parent_hash.
// Used when creating a delegated token (ACP-CT-1.0 §7).
func ComputeTokenHash(token *CapabilityToken) (string, error) {
	// Marshal to map, remove sig, canonicalize, hash.
	data, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		return "", err
	}
	delete(rawMap, "sig")

	rawMapJSON, err := json.Marshal(rawMap)
	if err != nil {
		return "", err
	}
	canonical, err := jcs.Transform(rawMapJSON)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}
