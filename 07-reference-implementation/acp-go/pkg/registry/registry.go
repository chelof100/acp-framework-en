// Package registry provides AgentID → Ed25519PublicKey resolution.
// The ACP server uses the registry to look up an agent's public key
// when verifying Proof-of-Possession (ACP-HP-1.0) and token subjects.
package registry

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
)

// ─── Interface ────────────────────────────────────────────────────────────────

// ErrAgentNotFound is returned when an AgentID has no registered public key.
var ErrAgentNotFound = errors.New("acp/registry: agent not found")

// AgentRegistry resolves an AgentID to its Ed25519 public key.
// Implementations may back this by an in-memory map, PostgreSQL, Redis, etc.
type AgentRegistry interface {
	// GetPublicKey returns the Ed25519 public key for the given AgentID.
	// Returns ErrAgentNotFound if the agent is not registered.
	GetPublicKey(agentID string) (ed25519.PublicKey, error)

	// Register adds or updates an agent's public key.
	Register(agentID string, pubKey ed25519.PublicKey) error
}

// ─── In-Memory Implementation ─────────────────────────────────────────────────

// InMemoryRegistry is a thread-safe in-memory AgentRegistry.
// Suitable for testing, development, and small single-node deployments.
// Production deployments SHOULD use a persistent backing store.
type InMemoryRegistry struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

// NewInMemoryRegistry creates an empty in-memory registry.
func NewInMemoryRegistry() *InMemoryRegistry {
	return &InMemoryRegistry{
		keys: make(map[string]ed25519.PublicKey),
	}
}

// GetPublicKey returns the public key for the given AgentID.
func (r *InMemoryRegistry) GetPublicKey(agentID string) (ed25519.PublicKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pk, ok := r.keys[agentID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrAgentNotFound, agentID)
	}
	return pk, nil
}

// Register adds or updates an agent's public key.
// An empty agentID or nil pubKey returns an error.
func (r *InMemoryRegistry) Register(agentID string, pubKey ed25519.PublicKey) error {
	if agentID == "" {
		return errors.New("acp/registry: agentID must not be empty")
	}
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("acp/registry: invalid public key length: %d (expected %d)", len(pubKey), ed25519.PublicKeySize)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[agentID] = pubKey
	return nil
}

// Deregister removes an agent from the registry.
func (r *InMemoryRegistry) Deregister(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.keys, agentID)
}

// Size returns the number of registered agents.
func (r *InMemoryRegistry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.keys)
}
