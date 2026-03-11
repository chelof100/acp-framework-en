// store.go — InMemoryReputationStore: non-persistent store for dev/testing.
//
// CONFORMANCE WARNING: This store is NOT ACP-REP-1.1 conformant for production
// deployments. Records and events are lost on process restart. A conformant
// implementation must persist records to durable storage (e.g. PostgreSQL,
// SQLite, or a FileReputationStore with fsync).
package reputation

import (
	"fmt"
	"sync"
	"time"
)

// ─── InMemoryReputationStore ──────────────────────────────────────────────────

// InMemoryReputationStore is a thread-safe, non-persistent reputation store.
// Suitable for development and integration testing.
type InMemoryReputationStore struct {
	mu      sync.RWMutex
	entries map[string]*repEntry
}

type repEntry struct {
	record ReputationRecord
	events []ReputationEvent
}

// NewInMemoryReputationStore creates an empty in-memory reputation store.
func NewInMemoryReputationStore() *InMemoryReputationStore {
	return &InMemoryReputationStore{
		entries: make(map[string]*repEntry),
	}
}

// getOrCreate returns the entry for agentID, creating a cold-start entry if absent.
// Caller MUST hold the write lock.
func (s *InMemoryReputationStore) getOrCreate(agentID string) *repEntry {
	e, ok := s.entries[agentID]
	if !ok {
		e = &repEntry{
			record: ReputationRecord{
				AgentID:    agentID,
				Score:      nil,
				State:      StateActive,
				EventCount: 0,
				UpdatedAt:  time.Now().Unix(),
			},
		}
		s.entries[agentID] = e
	}
	return e
}

// GetRecord returns the current reputation record for an agent.
// Returns a cold-start record (Score=nil, State=ACTIVE) for unknown agents.
func (s *InMemoryReputationStore) GetRecord(agentID string) (*ReputationRecord, error) {
	s.mu.RLock()
	e, ok := s.entries[agentID]
	s.mu.RUnlock()

	if !ok {
		r := ReputationRecord{
			AgentID:    agentID,
			Score:      nil,
			State:      StateActive,
			EventCount: 0,
			UpdatedAt:  time.Now().Unix(),
		}
		return &r, nil
	}
	r := e.record
	return &r, nil
}

// RecordEvent persists a reputation event and updates the agent's score.
func (s *InMemoryReputationStore) RecordEvent(agentID string, event ReputationEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.getOrCreate(agentID)
	e.events = append(e.events, event)
	e.record.Score = event.NewScore
	e.record.EventCount++
	e.record.UpdatedAt = event.Timestamp
	return nil
}

// GetState returns the current administrative state of an agent.
func (s *InMemoryReputationStore) GetState(agentID string) (AgentState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, ok := s.entries[agentID]
	if !ok {
		return StateActive, nil
	}
	return e.record.State, nil
}

// SetState sets the administrative state of an agent.
// Returns ErrAgentBanned if the current state is BANNED.
func (s *InMemoryReputationStore) SetState(agentID string, state AgentState, reason, authorizedBy string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.getOrCreate(agentID)
	if e.record.State == StateBanned {
		return ErrAgentBanned
	}

	_ = fmt.Sprintf("state change %s→%s by %s: %s", e.record.State, state, authorizedBy, reason) // logged in production impl
	e.record.State = state
	e.record.UpdatedAt = time.Now().Unix()
	return nil
}

// GetEvents returns paginated events for an agent, most-recent-first.
func (s *InMemoryReputationStore) GetEvents(agentID string, limit, offset int) ([]ReputationEvent, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	e, ok := s.entries[agentID]
	if !ok {
		return []ReputationEvent{}, 0, nil
	}

	all := e.events
	total := len(all)

	if offset >= total {
		return []ReputationEvent{}, total, nil
	}

	// Build result most-recent-first.
	result := make([]ReputationEvent, 0, limit)
	for i := total - 1 - offset; i >= 0 && len(result) < limit; i-- {
		result = append(result, all[i])
	}

	return result, total, nil
}

// AgentCount returns the number of agents with at least one event.
func (s *InMemoryReputationStore) AgentCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}
