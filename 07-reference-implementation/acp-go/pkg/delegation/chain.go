// Package delegation implements ACP-CT-1.0 §7 delegation chain validation.
// Enforces mandatory constraints: cap subset, res subset, exp monotone,
// max_depth decrement, absolute depth limit, and parent_hash integrity.
package delegation

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/chelof100/acp-framework/acp-go/pkg/tokens"
)

// Errors
var (
	ErrDelegationNotAllowed    = errors.New("acp/delegation: delegation not permitted on parent token")
	ErrCapabilityEscalation    = errors.New("acp/delegation: delegated cap is not a subset of parent cap")
	ErrResourceEscalation      = errors.New("acp/delegation: delegated res is not a subset of parent res")
	ErrExpirationExtension     = errors.New("acp/delegation: delegated exp exceeds parent exp")
	ErrDepthViolation          = errors.New("acp/delegation: max_depth not decremented by 1")
	ErrAbsoluteDepthExceeded   = errors.New("acp/delegation: max_depth exceeds absolute limit of 8")
	ErrParentHashMismatch      = errors.New("acp/delegation: parent_hash does not match parent token")
	ErrMissingParentHash       = errors.New("acp/delegation: delegated token missing parent_hash")
	ErrChainTooLong            = errors.New("acp/delegation: delegation chain exceeds absolute depth limit")
)

// Chain represents an ordered sequence of capability tokens forming a
// delegation chain. chain[0] is the root token, chain[n] is the leaf.
type Chain []*tokens.CapabilityToken

// Validate verifies the full delegation chain from root to leaf.
// issuerKeys maps AgentID → Ed25519PublicKey for each issuer in the chain.
// All constraints from ACP-CT-1.0 §7 are enforced.
func Validate(chain Chain, issuerKeys map[string]ed25519.PublicKey) error {
	if len(chain) == 0 {
		return errors.New("acp/delegation: empty chain")
	}
	if len(chain) > tokens.MaxDelegationDepth+1 {
		return ErrChainTooLong
	}

	// Validate root token has no parent_hash.
	if chain[0].ParentHash != nil {
		return errors.New("acp/delegation: root token must not have parent_hash")
	}

	// Validate each delegation link.
	for i := 1; i < len(chain); i++ {
		parent := chain[i-1]
		child := chain[i]
		if err := validateLink(parent, child); err != nil {
			return fmt.Errorf("acp/delegation: link %d→%d: %w", i-1, i, err)
		}
	}
	return nil
}

// validateLink enforces ACP-CT-1.0 §7 constraints between parent token T1
// and delegated token T2.
func validateLink(parent, child *tokens.CapabilityToken) error {
	// The parent must allow delegation.
	if !parent.Deleg.Allowed {
		return ErrDelegationNotAllowed
	}

	// cap(T2) ⊆ cap(T1)
	for _, c := range child.Cap {
		if !capInSlice(parent.Cap, c) {
			return fmt.Errorf("%w: %q not in parent cap", ErrCapabilityEscalation, c)
		}
	}

	// res(T2) ⊆ res(T1) — child resource must be covered by parent resource.
	if !resourceSubset(parent.Resource, child.Resource) {
		return fmt.Errorf("%w: %q not covered by %q", ErrResourceEscalation, child.Resource, parent.Resource)
	}

	// exp(T2) ≤ exp(T1)
	if child.Expiration > parent.Expiration {
		return ErrExpirationExtension
	}

	// max_depth(T2) < max_depth(T1) — must decrement by exactly 1.
	if child.Deleg.MaxDepth != parent.Deleg.MaxDepth-1 {
		return ErrDepthViolation
	}

	// Absolute depth limit.
	if child.Deleg.MaxDepth > tokens.MaxDelegationDepth {
		return ErrAbsoluteDepthExceeded
	}

	// parent_hash(T2) = SHA-256(JCS(T1 without sig))
	if child.ParentHash == nil {
		return ErrMissingParentHash
	}
	expectedHash, err := tokens.ComputeTokenHash(parent)
	if err != nil {
		return fmt.Errorf("acp/delegation: computing parent hash: %w", err)
	}
	if *child.ParentHash != expectedHash {
		return ErrParentHashMismatch
	}

	return nil
}

// ValidateChainJSON parses and validates a chain from raw JSON token bytes.
// rawTokens[0] is the root, rawTokens[n] is the leaf.
// issuerKeys maps AgentID → public key for each issuer.
func ValidateChainJSON(rawTokens [][]byte, issuerKeys map[string]ed25519.PublicKey) (Chain, error) {
	chain := make(Chain, len(rawTokens))
	for i, raw := range rawTokens {
		var t tokens.CapabilityToken
		if err := json.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("acp/delegation: parsing token %d: %w", i, err)
		}
		chain[i] = &t
	}
	if err := Validate(chain, issuerKeys); err != nil {
		return nil, err
	}
	return chain, nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func capInSlice(slice []string, cap string) bool {
	for _, c := range slice {
		if c == cap {
			return true
		}
	}
	return false
}

// resourceSubset returns true if childRes is covered by parentRes.
// Same logic as tokens.resourceCovered.
func resourceSubset(parentRes, childRes string) bool {
	if parentRes == childRes {
		return true
	}
	if len(childRes) > len(parentRes) && childRes[:len(parentRes)] == parentRes {
		return childRes[len(parentRes)] == '/'
	}
	return false
}
