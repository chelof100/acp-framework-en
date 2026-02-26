// Package tokens — InMemoryNonceStore implements the NonceStore interface
// defined in capability.go for replay prevention of capability tokens.
package tokens

import (
	"fmt"
	"sync"
	"time"
)

// nonceEntry stores metadata about a seen nonce for TTL-based expiry.
type nonceEntry struct {
	seenAt    time.Time
	expiresAt time.Time // mirrors the token's exp field
}

// InMemoryNonceStore is a thread-safe in-memory NonceStore.
// It prevents replay attacks by rejecting tokens whose nonces have
// already been consumed. Entries are pruned once the token's exp passes.
//
// For production deployments with multiple server instances, replace
// this with a distributed store (Redis, Memcached, PostgreSQL).
type InMemoryNonceStore struct {
	mu      sync.Mutex
	entries map[string]nonceEntry
}

// NewInMemoryNonceStore creates an empty nonce store.
func NewInMemoryNonceStore() *InMemoryNonceStore {
	return &InMemoryNonceStore{
		entries: make(map[string]nonceEntry),
	}
}

// MarkUsed records that a nonce has been used.
// Returns an error if the nonce was already seen (replay detected).
// tokenExp is the token's expiration Unix timestamp — used to determine
// when the nonce entry can be safely pruned.
func (s *InMemoryNonceStore) MarkUsed(nonce string, tokenExp int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.entries[nonce]; exists {
		return fmt.Errorf("acp/nonce: nonce %q already used (replay attack)", nonce)
	}

	s.entries[nonce] = nonceEntry{
		seenAt:    time.Now(),
		expiresAt: time.Unix(tokenExp, 0),
	}
	return nil
}

// WasSeen returns true if the nonce has already been used.
func (s *InMemoryNonceStore) WasSeen(nonce string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, exists := s.entries[nonce]
	return exists
}

// Prune removes entries for tokens that have already expired.
// Call periodically (e.g., every 5 minutes) to prevent unbounded growth.
func (s *InMemoryNonceStore) Prune() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	removed := 0
	for nonce, entry := range s.entries {
		if now.After(entry.expiresAt) {
			delete(s.entries, nonce)
			removed++
		}
	}
	return removed
}

// Size returns the number of stored nonce entries.
func (s *InMemoryNonceStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
