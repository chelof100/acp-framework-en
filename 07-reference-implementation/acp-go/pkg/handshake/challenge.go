// Package handshake implements ACP-HP-1.0: the ACP Handshake Protocol.
// Provides challenge generation (128-bit CSPRNG nonces) and Proof-of-Possession
// (PoP) verification with HTTP channel binding.
package handshake

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const (
	// ChallengeTTL is the lifetime of a challenge nonce (ACP-HP-1.0).
	ChallengeTTL = 30 * time.Second
	// ChallengeSize is the CSPRNG byte count (128 bits = 16 bytes).
	ChallengeSize = 16
)

// Errors
var (
	ErrChallengeExpired  = errors.New("acp/handshake: challenge expired or not found")
	ErrChallengeGenerate = errors.New("acp/handshake: CSPRNG failure generating challenge")
)

// challengeEntry holds a nonce and its expiration time.
type challengeEntry struct {
	expiresAt time.Time
}

// ChallengeStore manages ephemeral one-time-use challenge nonces.
// All operations are safe for concurrent use.
type ChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]challengeEntry
}

// NewChallengeStore creates an initialized ChallengeStore.
// Callers should periodically call Prune() to evict expired entries.
func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{
		challenges: make(map[string]challengeEntry),
	}
}

// GenerateChallenge creates a cryptographically secure 128-bit nonce,
// stores it with a 30-second TTL, and returns it as base64url (no padding).
// Per ACP-HP-1.0: nonces are single-use and ephemeral.
func (s *ChallengeStore) GenerateChallenge() (string, error) {
	b := make([]byte, ChallengeSize)
	if _, err := rand.Read(b); err != nil {
		return "", ErrChallengeGenerate
	}
	challenge := base64.RawURLEncoding.EncodeToString(b)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[challenge] = challengeEntry{
		expiresAt: time.Now().Add(ChallengeTTL),
	}
	return challenge, nil
}

// ConsumeChallenge verifies the challenge exists and has not expired,
// then removes it atomically (single-use guarantee).
//
// Security note: the challenge is deleted BEFORE the expiry check.
// This means an expired challenge is consumed and cannot be replayed,
// even if the error is ignored by the caller.
func (s *ChallengeStore) ConsumeChallenge(challenge string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, exists := s.challenges[challenge]
	if !exists {
		return ErrChallengeExpired
	}

	// Delete immediately — prevents replay regardless of expiry outcome.
	delete(s.challenges, challenge)

	if time.Now().After(entry.expiresAt) {
		return ErrChallengeExpired
	}
	return nil
}

// Prune removes all expired challenges from the store.
// Should be called periodically (e.g., every minute) to prevent memory growth.
func (s *ChallengeStore) Prune() {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.challenges {
		if now.After(v.expiresAt) {
			delete(s.challenges, k)
		}
	}
}

// Size returns the current number of pending challenges (for monitoring).
func (s *ChallengeStore) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.challenges)
}
