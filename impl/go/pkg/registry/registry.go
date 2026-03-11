// Package registry provides AgentID → Ed25519PublicKey resolution and full
// agent metadata management (ACP-API-1.0 §4).
//
// The ACP server uses the registry to:
//   - Look up agent public keys for PoP and CT subject verification
//   - Store and retrieve full AgentRecord data (autonomy_level, status, etc.)
package registry

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ─── Errors ───────────────────────────────────────────────────────────────────

var (
	// ErrAgentNotFound is returned when an AgentID has no registered entry.
	ErrAgentNotFound = errors.New("acp/registry: agent not found")

	// ErrAgentAlreadyRegistered is returned on duplicate registration (AGENT-004).
	ErrAgentAlreadyRegistered = errors.New("acp/registry: agent already registered")

	// ErrInvalidTransition is returned for disallowed state transitions (STATE-001).
	ErrInvalidTransition = errors.New("acp/registry: invalid state transition")

	// ErrAgentRevoked is returned when attempting to transition from revoked (STATE-002).
	ErrAgentRevoked = errors.New("acp/registry: agent is revoked — irreversible state")
)

// ─── Agent Status ─────────────────────────────────────────────────────────────

// AgentStatus represents the lifecycle state of an agent (ACP-API-1.0 §4).
type AgentStatus string

const (
	StatusActive     AgentStatus = "active"
	StatusRestricted AgentStatus = "restricted"
	StatusSuspended  AgentStatus = "suspended"
	StatusRevoked    AgentStatus = "revoked"
)

// validTransitions defines allowed state transitions per ACP-API-1.0 §4.
var validTransitions = map[AgentStatus]map[AgentStatus]bool{
	StatusActive: {
		StatusRestricted: true,
		StatusSuspended:  true,
		StatusRevoked:    true,
	},
	StatusRestricted: {
		StatusActive:    true,
		StatusSuspended: true,
		StatusRevoked:   true,
	},
	StatusSuspended: {
		StatusActive:  true,
		StatusRevoked: true,
	},
	// StatusRevoked has no outgoing transitions (terminal).
}

// ─── Agent Record ─────────────────────────────────────────────────────────────

// AgentRecord holds the full metadata for a registered agent (ACP-API-1.0 §4).
type AgentRecord struct {
	AgentID         string            `json:"agent_id"`
	PublicKey       ed25519.PublicKey `json:"-"` // not serialised directly
	PublicKeyB64    string            `json:"public_key"` // base64url
	InstitutionID   string            `json:"institution_id"`
	AutonomyLevel   int               `json:"autonomy_level"` // 0–4
	AuthorityDomain string            `json:"authority_domain"`
	Status          AgentStatus       `json:"status"`
	Metadata        map[string]string `json:"metadata,omitempty"`
	RegisteredAt    int64             `json:"registered_at"`
	LastActiveAt    int64             `json:"last_active_at"`
}

// ─── Interface ────────────────────────────────────────────────────────────────

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
// It supports both lightweight pubkey-only registration (via Register) and
// full agent records (via RegisterFull). Suitable for testing, development,
// and small single-node deployments. Production SHOULD use a persistent store.
type InMemoryRegistry struct {
	mu      sync.RWMutex
	keys    map[string]ed25519.PublicKey // legacy path: agentID → pubkey
	records map[string]*AgentRecord      // full records: agentID → record
}

// NewInMemoryRegistry creates an empty in-memory registry.
func NewInMemoryRegistry() *InMemoryRegistry {
	return &InMemoryRegistry{
		keys:    make(map[string]ed25519.PublicKey),
		records: make(map[string]*AgentRecord),
	}
}

// GetPublicKey returns the public key for the given AgentID.
// Checks the full records store first, falls back to the legacy keys map.
func (r *InMemoryRegistry) GetPublicKey(agentID string) (ed25519.PublicKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if rec, ok := r.records[agentID]; ok {
		return rec.PublicKey, nil
	}
	pk, ok := r.keys[agentID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrAgentNotFound, agentID)
	}
	return pk, nil
}

// Register adds or updates an agent's public key (lightweight, no metadata).
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

// RegisterFull registers a new agent with full metadata (ACP-API-1.0 §4).
// Returns ErrAgentAlreadyRegistered if the agent_id already exists (AGENT-004).
func (r *InMemoryRegistry) RegisterFull(rec AgentRecord) error {
	if rec.AgentID == "" {
		return errors.New("acp/registry: agent_id must not be empty")
	}
	if len(rec.PublicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("acp/registry: invalid public key length: %d", len(rec.PublicKey))
	}
	if rec.AutonomyLevel < 0 || rec.AutonomyLevel > 4 {
		return fmt.Errorf("acp/registry: autonomy_level %d out of range [0,4]", rec.AutonomyLevel)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.records[rec.AgentID]; exists {
		return fmt.Errorf("%w: %q", ErrAgentAlreadyRegistered, rec.AgentID)
	}
	// Also check legacy keys map.
	if _, exists := r.keys[rec.AgentID]; exists {
		return fmt.Errorf("%w: %q", ErrAgentAlreadyRegistered, rec.AgentID)
	}
	if rec.Status == "" {
		rec.Status = StatusActive
	}
	now := time.Now().Unix()
	if rec.RegisteredAt == 0 {
		rec.RegisteredAt = now
	}
	if rec.LastActiveAt == 0 {
		rec.LastActiveAt = now
	}
	cp := rec // copy
	r.records[rec.AgentID] = &cp
	return nil
}

// GetRecord returns the full AgentRecord for an agent.
// Returns ErrAgentNotFound if the agent is not registered via RegisterFull.
func (r *InMemoryRegistry) GetRecord(agentID string) (AgentRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rec, ok := r.records[agentID]
	if !ok {
		return AgentRecord{}, fmt.Errorf("%w: %q", ErrAgentNotFound, agentID)
	}
	return *rec, nil
}

// UpdateStatus transitions the agent to a new status.
// Validates the transition per ACP-API-1.0 §4 transition table.
// Returns ErrAgentRevoked if current status is revoked (terminal).
// Returns ErrInvalidTransition for disallowed transitions.
func (r *InMemoryRegistry) UpdateStatus(agentID string, newStatus AgentStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.records[agentID]
	if !ok {
		return fmt.Errorf("%w: %q", ErrAgentNotFound, agentID)
	}
	if rec.Status == StatusRevoked {
		return fmt.Errorf("%w: %q", ErrAgentRevoked, agentID)
	}
	allowed := validTransitions[rec.Status]
	if !allowed[newStatus] {
		return fmt.Errorf("%w: %s → %s", ErrInvalidTransition, rec.Status, newStatus)
	}
	rec.Status = newStatus
	return nil
}

// TouchLastActive updates the LastActiveAt timestamp for an agent.
// Silently ignores agents not in the full records store.
func (r *InMemoryRegistry) TouchLastActive(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rec, ok := r.records[agentID]; ok {
		rec.LastActiveAt = time.Now().Unix()
	}
}

// Deregister removes an agent from the registry (both stores).
func (r *InMemoryRegistry) Deregister(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.keys, agentID)
	delete(r.records, agentID)
}

// Size returns the total number of registered agents (both stores, deduplicated).
func (r *InMemoryRegistry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	seen := make(map[string]struct{}, len(r.records)+len(r.keys))
	for id := range r.records {
		seen[id] = struct{}{}
	}
	for id := range r.keys {
		seen[id] = struct{}{}
	}
	return len(seen)
}
