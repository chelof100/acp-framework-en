// Package iut implements ACP-TS-1.1 test vector evaluation.
// It is the core of the acp-evaluate IUT binary used by the ACR-1.0 compliance runner.
package iut

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gowebpki/jcs"
	"github.com/mr-tron/base58"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// TestVector is the ACP-TS-1.1 test vector format.
type TestVector struct {
	Meta     VectorMeta     `json:"meta"`
	Input    VectorInput    `json:"input"`
	Context  VectorContext  `json:"context"`
	Expected VectorExpected `json:"expected"`
}

// VectorMeta holds test vector metadata.
type VectorMeta struct {
	ID               string `json:"id"`
	ACPVersion       string `json:"acp_version"`
	Layer            string `json:"layer"`
	ConformanceLevel string `json:"conformance_level"`
	Description      string `json:"description"`
	Severity         string `json:"severity"`
}

// VectorInput wraps the capability under evaluation.
type VectorInput struct {
	Capability map[string]interface{} `json:"capability"`
}

// VectorContext is the evaluation environment provided by the test vector.
type VectorContext struct {
	CurrentTime        int64                      `json:"current_time"`
	TrustedIssuers     []string                   `json:"trusted_issuers"`
	RevocationList     []string                   `json:"revocation_list"`
	DelegationRegistry map[string]DelegationEntry `json:"delegation_registry"`
}

// DelegationEntry is one agent's delegation record in the registry.
type DelegationEntry struct {
	ActionSet             []string `json:"action_set"`
	Resource              string   `json:"resource"`
	Revoked               bool     `json:"revoked"`
	RevokedAt             *int64   `json:"revoked_at,omitempty"`
	DelegatedBy           string   `json:"delegated_by,omitempty"`
	Depth                 *int     `json:"depth,omitempty"`
	InstitutionalMaxDepth *int     `json:"institutional_max_depth,omitempty"`
}

// VectorExpected is the expected evaluation outcome.
type VectorExpected struct {
	Decision  string  `json:"decision"`
	ErrorCode *string `json:"error_code"`
}

// Response is the IUT output written to STDOUT.
type Response struct {
	Decision  string  `json:"decision"`
	ErrorCode *string `json:"error_code,omitempty"`
}

// ─── Public API ───────────────────────────────────────────────────────────────

// Evaluate runs the ACP L1/L2 evaluation against a test vector.
//
// Evaluation order (per ACP-CT-1.0 §5):
//  1. Version field present
//  2. Required fields present
//  3. Issuer trust
//  4. Signature validity
//  5. Expiry
//  6. JTI revocation
//  7. Delegation (L2)
func Evaluate(vec TestVector) Response {
	cap := vec.Input.Capability
	ctx := vec.Context

	reject := func(code string) Response {
		c := code
		return Response{Decision: "REJECT", ErrorCode: &c}
	}

	// 1. Version
	ver, _ := cap["ver"].(string)
	if ver == "" {
		return reject("MALFORMED_INPUT")
	}

	// 2. Required fields
	for _, f := range []string{"issuer", "sub", "action_set", "resource", "exp", "jti", "nonce", "signature"} {
		if _, ok := cap[f]; !ok {
			return reject("MALFORMED_INPUT")
		}
	}

	issuer, _ := cap["issuer"].(string)
	jti, _ := cap["jti"].(string)

	// 3. Issuer trust
	if !sliceContains(ctx.TrustedIssuers, issuer) {
		return reject("UNTRUSTED_ISSUER")
	}

	// 4. Signature
	pubKey, err := resolveDIDKey(issuer)
	if err != nil {
		return reject("INVALID_SIGNATURE")
	}
	if err := verifyCapSig(cap, pubKey); err != nil {
		return reject("INVALID_SIGNATURE")
	}

	// 5. Expiry
	var expTime int64
	switch v := cap["exp"].(type) {
	case float64:
		expTime = int64(v)
	case int64:
		expTime = v
	}
	if ctx.CurrentTime >= expTime {
		return reject("EXPIRED")
	}

	// 6. JTI revocation
	if sliceContains(ctx.RevocationList, jti) {
		return reject("REVOKED")
	}

	// 7. Delegation (L2) — only if delegation field present
	if del := cap["delegation"]; del != nil {
		if code := checkDelegation(cap, ctx); code != "" {
			return reject(code)
		}
	}

	return Response{Decision: "VALID"}
}

// SignCapability signs a capability using the given Ed25519 private key.
// The signature field is removed before signing (if present).
// Returns base64url-encoded Ed25519 signature over sha256(jcs(capability)).
func SignCapability(cap map[string]interface{}, sk ed25519.PrivateKey) (string, error) {
	c := shallowCopyMap(cap)
	delete(c, "signature")

	raw, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("jcs: %w", err)
	}
	digest := sha256.Sum256(canonical)
	sig := ed25519.Sign(sk, digest[:])
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

// resolveDIDKey resolves a did:key: DID to an Ed25519 public key.
// Format: did:key:z<base58btc(multicodec[0xed,0x01] + 32-byte-pubkey)>
func resolveDIDKey(did string) (ed25519.PublicKey, error) {
	const prefix = "did:key:z"
	if !strings.HasPrefix(did, prefix) {
		return nil, fmt.Errorf("unsupported DID: %s", did)
	}
	encoded := did[len(prefix):]
	decoded, err := base58.Decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("base58: %w", err)
	}
	// Ed25519 multicodec prefix: [0xed, 0x01]
	if len(decoded) < 2 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, fmt.Errorf("not an Ed25519 did:key")
	}
	keyBytes := decoded[2:]
	if len(keyBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("wrong key length: %d", len(keyBytes))
	}
	return ed25519.PublicKey(keyBytes), nil
}

// verifyCapSig verifies the capability's "signature" field.
// Computes: ed25519.Verify(pubKey, sha256(jcs(cap_without_signature)), sig)
func verifyCapSig(cap map[string]interface{}, pubKey ed25519.PublicKey) error {
	sigStr, _ := cap["signature"].(string)
	if sigStr == "" {
		return fmt.Errorf("missing signature")
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigStr)
	if err != nil {
		// Try standard encoding as fallback (some test data uses padding)
		sigBytes, err = base64.StdEncoding.DecodeString(sigStr)
		if err != nil {
			return fmt.Errorf("base64 decode: %w", err)
		}
	}

	c := shallowCopyMap(cap)
	delete(c, "signature")
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)

	if !ed25519.Verify(pubKey, digest[:], sigBytes) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// checkDelegation validates L2 delegation rules.
// Returns the rejection error code, or "" if delegation is valid.
func checkDelegation(cap map[string]interface{}, ctx VectorContext) string {
	delMap, _ := cap["delegation"].(map[string]interface{})
	if delMap == nil {
		return ""
	}

	depthF, _ := delMap["depth"].(float64)
	maxDepthF, _ := delMap["max_depth"].(float64)
	depth := int(depthF)
	maxDepth := int(maxDepthF)

	// Rule 1: depth must not exceed max_depth
	if depth > maxDepth {
		return "DELEGATION_DEPTH"
	}

	delegator, _ := delMap["delegator"].(string)
	if delegator == "" || ctx.DelegationRegistry == nil {
		return ""
	}

	entry, ok := ctx.DelegationRegistry[delegator]
	if !ok {
		return ""
	}

	// Rule 2: delegator must not be revoked
	if entry.Revoked {
		return "REVOKED"
	}

	// Rule 3: check institutional max_depth from root
	if entry.InstitutionalMaxDepth != nil && depth > *entry.InstitutionalMaxDepth {
		return "DELEGATION_DEPTH"
	}

	// Rule 4: capability action_set must be a subset of delegator's authorized actions
	capActions := interfaceToStringSlice(cap["action_set"])
	for _, a := range capActions {
		if !sliceContains(entry.ActionSet, a) {
			return "ACCESS_DENIED"
		}
	}

	// Rule 5: delegation constraints action_set must also be within delegator's authority
	if constraints, ok := delMap["constraints"].(map[string]interface{}); ok {
		cActions := interfaceToStringSlice(constraints["action_set"])
		for _, a := range cActions {
			if !sliceContains(entry.ActionSet, a) {
				return "ACCESS_DENIED"
			}
		}
	}

	return ""
}

// ─── Utility ──────────────────────────────────────────────────────────────────

func shallowCopyMap(m map[string]interface{}) map[string]interface{} {
	c := make(map[string]interface{}, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

func interfaceToStringSlice(v interface{}) []string {
	arr, _ := v.([]interface{})
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func sliceContains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
