// Package disc implements ACP-DISC-1.0 (agent discovery registry).
//
// Provides agent registration, expiry-aware queries with capability and
// institution filters, and pagination support.
package disc

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// ─── Error Sentinels (ACP-DISC-1.0) ──────────────────────────────────────────

var (
	ErrEmptyAgentID          = errors.New("DISC-001: agent_id is required")
	ErrEmptyInstitutionID    = errors.New("DISC-002: institution_id is required")
	ErrAgentNotFound         = errors.New("DISC-003: agent not found in discovery registry")
	ErrAgentAlreadyRegistered = errors.New("DISC-004: agent_id already registered")
)

// ─── Types ────────────────────────────────────────────────────────────────────

// DiscoveryEntry is a registered agent record in the discovery registry.
type DiscoveryEntry struct {
	AgentID              string   `json:"agent_id"`
	InstitutionID        string   `json:"institution_id"`
	PublicCapabilities   []string `json:"public_capabilities"`
	ContactEndpoint      string   `json:"contact_endpoint"`
	RegisteredAt         int64    `json:"registered_at"`
	ExpiresAt            int64    `json:"expires_at"`
}

// RegisterRequest holds the input for registering an agent.
// TTLSeconds defaults to 86400 (24h) if zero or negative.
type RegisterRequest struct {
	AgentID            string   `json:"agent_id"`
	InstitutionID      string   `json:"institution_id"`
	PublicCapabilities []string `json:"public_capabilities"`
	ContactEndpoint    string   `json:"contact_endpoint"`
	TTLSeconds         int      `json:"ttl_seconds"`
}

// QueryFilter defines filter and pagination options for agent discovery queries.
type QueryFilter struct {
	Capability    string `json:"capability"`     // filter: entry must expose this capability
	InstitutionID string `json:"institution_id"` // filter: entry must belong to this institution
	Page          int    `json:"page"`           // 1-based; defaults to 1 if <= 0
	PerPage       int    `json:"per_page"`       // defaults to 20 if <= 0
}

// QueryResponse is the paginated result of a discovery query.
type QueryResponse struct {
	Total   int              `json:"total"`
	Page    int              `json:"page"`
	PerPage int              `json:"per_page"`
	Results []DiscoveryEntry `json:"results"`
}

// ─── Core Functions ───────────────────────────────────────────────────────────

// Register validates the request and builds a DiscoveryEntry with timestamps set.
// TTLSeconds defaults to 86400 if zero or negative.
func Register(req RegisterRequest) (DiscoveryEntry, error) {
	if req.AgentID == "" {
		return DiscoveryEntry{}, ErrEmptyAgentID
	}
	if req.InstitutionID == "" {
		return DiscoveryEntry{}, ErrEmptyInstitutionID
	}

	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 86400
	}

	now := time.Now().Unix()
	return DiscoveryEntry{
		AgentID:            req.AgentID,
		InstitutionID:      req.InstitutionID,
		PublicCapabilities: req.PublicCapabilities,
		ContactEndpoint:    req.ContactEndpoint,
		RegisteredAt:       now,
		ExpiresAt:          now + int64(ttl),
	}, nil
}

// IsExpired returns true if the entry's ExpiresAt is before now.
func IsExpired(e DiscoveryEntry, now int64) bool {
	return e.ExpiresAt < now
}

// ─── InMemoryDiscoveryRegistry ────────────────────────────────────────────────

// InMemoryDiscoveryRegistry is a thread-safe in-memory discovery registry.
type InMemoryDiscoveryRegistry struct {
	mu    sync.RWMutex
	store map[string]DiscoveryEntry // agent_id → DiscoveryEntry
}

// NewInMemoryDiscoveryRegistry creates an empty discovery registry.
func NewInMemoryDiscoveryRegistry() *InMemoryDiscoveryRegistry {
	return &InMemoryDiscoveryRegistry{
		store: make(map[string]DiscoveryEntry),
	}
}

// Register validates, builds, and stores a DiscoveryEntry.
// Returns ErrAgentAlreadyRegistered if the agent_id is already present.
func (r *InMemoryDiscoveryRegistry) Register(req RegisterRequest) (DiscoveryEntry, error) {
	entry, err := Register(req)
	if err != nil {
		return DiscoveryEntry{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.store[entry.AgentID]; exists {
		return DiscoveryEntry{}, fmt.Errorf("%w: %s", ErrAgentAlreadyRegistered, entry.AgentID)
	}
	r.store[entry.AgentID] = entry
	return entry, nil
}

// Get retrieves a DiscoveryEntry by agent_id (does not check expiry).
func (r *InMemoryDiscoveryRegistry) Get(agentID string) (DiscoveryEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.store[agentID]
	return entry, ok
}

// Deregister removes an agent from the registry.
func (r *InMemoryDiscoveryRegistry) Deregister(agentID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.store[agentID]; !ok {
		return fmt.Errorf("%w: %s", ErrAgentNotFound, agentID)
	}
	delete(r.store, agentID)
	return nil
}

// Query filters by Capability and InstitutionID (if set), skips expired entries,
// and applies pagination. now is the current Unix timestamp.
func (r *InMemoryDiscoveryRegistry) Query(f QueryFilter, now int64) QueryResponse {
	r.mu.RLock()
	defer r.mu.RUnlock()

	page := f.Page
	if page <= 0 {
		page = 1
	}
	perPage := f.PerPage
	if perPage <= 0 {
		perPage = 20
	}

	// Collect and filter.
	var filtered []DiscoveryEntry
	for _, entry := range r.store {
		// Skip expired.
		if IsExpired(entry, now) {
			continue
		}
		// Filter by InstitutionID.
		if f.InstitutionID != "" && entry.InstitutionID != f.InstitutionID {
			continue
		}
		// Filter by Capability.
		if f.Capability != "" && !hasCapability(entry.PublicCapabilities, f.Capability) {
			continue
		}
		filtered = append(filtered, entry)
	}

	// Sort for deterministic pagination.
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].AgentID < filtered[j].AgentID
	})

	total := len(filtered)
	start := (page - 1) * perPage
	if start >= total {
		return QueryResponse{Total: total, Page: page, PerPage: perPage, Results: []DiscoveryEntry{}}
	}
	end := start + perPage
	if end > total {
		end = total
	}

	return QueryResponse{
		Total:   total,
		Page:    page,
		PerPage: perPage,
		Results: filtered[start:end],
	}
}

// Size returns the total number of entries (including expired).
func (r *InMemoryDiscoveryRegistry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.store)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func hasCapability(caps []string, cap string) bool {
	for _, c := range caps {
		if strings.EqualFold(c, cap) {
			return true
		}
	}
	return false
}

// ─── UUID Helper ──────────────────────────────────────────────────────────────

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// newUUID is referenced in case future functions need it; suppress unused warning.
var _ = newUUID
