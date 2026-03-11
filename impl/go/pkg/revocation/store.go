// Package revocation — RevocationStore: server-side revocation registry (ACP-REV-1.0).
//
// The RevocationStore is the authoritative source of truth for revoked tokens.
// It is used by:
//   - GET  /acp/v1/rev/check  → query revocation status
//   - POST /acp/v1/rev/revoke → emit a revocation
//   - StoreRevocationChecker  → wires the store into token verification
package revocation

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/tokens"
)

// ─── Reason Codes (ACP-REV-1.0 §8) ───────────────────────────────────────────

const (
	ReasonEarlyExpiration     = "REV-001" // Early expiration by issuer request
	ReasonKeyCompromise       = "REV-002" // Subject private key compromise
	ReasonPolicyViolation     = "REV-003" // Policy violation detected
	ReasonAgentDecommissioned = "REV-004" // Agent decommissioned
	ReasonAdministrative      = "REV-005" // Administrative order
	ReasonParentRevoked       = "REV-006" // Transitive: parent token revoked
	ReasonInactivityExpiry    = "REV-007" // Inactivity expiry
	ReasonEmergency           = "REV-008" // Emergency revocation (key/institutional compromise)
)

// ValidReasonCodes is the complete set of valid reason codes.
var ValidReasonCodes = map[string]bool{
	ReasonEarlyExpiration:     true,
	ReasonKeyCompromise:       true,
	ReasonPolicyViolation:     true,
	ReasonAgentDecommissioned: true,
	ReasonAdministrative:      true,
	ReasonParentRevoked:       true,
	ReasonInactivityExpiry:    true,
	ReasonEmergency:           true,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

var (
	ErrAlreadyRevoked = errors.New("acp/revocation: token already revoked (REV-E001 variant)")
	ErrTokenNotFound  = errors.New("acp/revocation: token_id not found — treat as revoked (REV-E001)")
	ErrInvalidReason  = errors.New("acp/revocation: invalid reason_code (REV-E007)")
	ErrNoPermission   = errors.New("acp/revocation: insufficient permission to emit revocation (REV-E006)")
)

// ─── RevocationRecord ─────────────────────────────────────────────────────────

// RevocationRecord is a single entry in the revocation registry.
type RevocationRecord struct {
	TokenID    string `json:"token_id"`
	RevokedAt  int64  `json:"revoked_at"`
	RevokedBy  string `json:"revoked_by"`
	ReasonCode string `json:"reason_code"`
}

// ─── RevocationStore interface ────────────────────────────────────────────────

// RevocationStore is the server-side authoritative registry of revoked tokens.
// Implementations MUST be safe for concurrent use.
//
// A conformant implementation MUST persist records across restarts.
// InMemoryRevocationStore is NOT conformant (development use only).
type RevocationStore interface {
	// Revoke adds a revocation record for a token.
	// Returns ErrAlreadyRevoked if token_id is already in the store.
	// Returns ErrInvalidReason if the reason_code is not in ValidReasonCodes.
	Revoke(record RevocationRecord) error

	// IsRevoked reports whether a token_id has been revoked.
	// Returns (true, record, nil) if revoked.
	// Returns (false, nil, nil) if active (not in store).
	// Returns (false, nil, err) on store error.
	IsRevoked(tokenID string) (bool, *RevocationRecord, error)

	// GetRecord returns the full revocation record for a token_id.
	// Returns ErrTokenNotFound if not revoked.
	GetRecord(tokenID string) (*RevocationRecord, error)

	// Size returns the number of revoked tokens currently in the store.
	Size() int
}

// ─── InMemoryRevocationStore ──────────────────────────────────────────────────

// InMemoryRevocationStore is a thread-safe, non-persistent revocation store.
//
// CONFORMANCE WARNING: This implementation is NOT ACP-REV-1.0 conformant for
// production use — records are lost on process restart. Use only for development
// and testing. A conformant implementation must persist records to durable storage.
type InMemoryRevocationStore struct {
	mu      sync.RWMutex
	records map[string]RevocationRecord
}

// NewInMemoryRevocationStore creates an empty in-memory revocation store.
func NewInMemoryRevocationStore() *InMemoryRevocationStore {
	return &InMemoryRevocationStore{
		records: make(map[string]RevocationRecord),
	}
}

// Revoke adds a revocation record. Returns ErrAlreadyRevoked if already present.
func (s *InMemoryRevocationStore) Revoke(record RevocationRecord) error {
	if record.TokenID == "" {
		return fmt.Errorf("acp/revocation: token_id must not be empty")
	}
	if !ValidReasonCodes[record.ReasonCode] {
		return fmt.Errorf("%w: %q", ErrInvalidReason, record.ReasonCode)
	}
	if record.RevokedAt == 0 {
		record.RevokedAt = time.Now().Unix()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.records[record.TokenID]; exists {
		return ErrAlreadyRevoked
	}
	s.records[record.TokenID] = record
	return nil
}

// IsRevoked checks if a token_id is in the revocation store.
func (s *InMemoryRevocationStore) IsRevoked(tokenID string) (bool, *RevocationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, exists := s.records[tokenID]
	if !exists {
		return false, nil, nil
	}
	r := record
	return true, &r, nil
}

// GetRecord returns the revocation record for a token_id.
func (s *InMemoryRevocationStore) GetRecord(tokenID string) (*RevocationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	record, exists := s.records[tokenID]
	if !exists {
		return nil, ErrTokenNotFound
	}
	r := record
	return &r, nil
}

// Size returns the number of revoked tokens.
func (s *InMemoryRevocationStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

// ─── StoreRevocationChecker ───────────────────────────────────────────────────

// StoreRevocationChecker implements tokens.RevocationChecker by consulting
// a RevocationStore. This wires the server-side store into the token
// verification pipeline.
//
// When rev == nil or rev.Type == "crl" (CRL not implemented in v1), the checker
// consults the local store regardless — the store is always the authority.
type StoreRevocationChecker struct {
	store RevocationStore
}

// NewStoreRevocationChecker creates a checker backed by the given store.
func NewStoreRevocationChecker(store RevocationStore) *StoreRevocationChecker {
	return &StoreRevocationChecker{store: store}
}

// IsRevoked satisfies tokens.RevocationChecker.
func (c *StoreRevocationChecker) IsRevoked(tokenNonce string, _ *tokens.Revocation) (bool, error) {
	revoked, _, err := c.store.IsRevoked(tokenNonce)
	return revoked, err
}
