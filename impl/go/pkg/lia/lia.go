// Package lia implements ACP-LIA-1.0 Liability Traceability.
//
// A LIABILITY_RECORD materializes, for each consumed Execution Token (ET),
// an auditable record that allows regulators, auditors, and financial
// counterparties to deterministically identify who bears legal responsibility
// for each action executed by an autonomous agent.
//
// Key properties:
//   - One record per execution (per consumed ET with a final result)
//   - Immutable: append-only, never modified or deleted
//   - Deterministic: same ET + same ledger tokens → identical record
//   - Audited degradation: chain_incomplete=true when chain can't be reconstructed
//   - PSN dependency: every record references the active policy snapshot
//
// Required for L4-EXTENDED conformance (ACP-CONF-1.2).
package lia

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
)

// ─── Error Sentinels (ACP-LIA-1.0 §12) ───────────────────────────────────────

var (
	ErrNotFound             = errors.New("LIA-001: liability record not found")
	ErrChainNotReconstructible = errors.New("LIA-002: delegation chain not reconstructible")
	ErrPolicySnapshotMissing = errors.New("LIA-003: policy snapshot unavailable for executed_at")
	ErrETNotFound           = errors.New("LIA-004: ET not found in ledger")
	ErrAuthorizationNotFound = errors.New("LIA-005: authorization event not found for ET")
	ErrLedgerWriteFailure   = errors.New("LIA-006: ledger write failure during emission")
	ErrPending              = errors.New("LIA-007: ET consumed, LIABILITY_RECORD emission in progress")
	ErrDuplicate            = errors.New("LIA-008: LIABILITY_RECORD already exists for this et_id")
)

// ─── Types (ACP-LIA-1.0 §4 + §5) ─────────────────────────────────────────────

// ChainEntry is one step in the delegation chain (§5.7).
type ChainEntry struct {
	Depth     int    `json:"depth"`
	TokenNonce string `json:"token_nonce"`
	AgentID   string `json:"agent_id"`
	IssuedAt  int64  `json:"issued_at"`
}

// LiabilityRecord is the payload of the LIABILITY_RECORD ledger event (§4).
// It is stored as the payload of a LEDGER LIABILITY_RECORD event.
type LiabilityRecord struct {
	LiabilityID        string       `json:"liability_id"`
	ETID               string       `json:"et_id"`
	AuthorizationID    string       `json:"authorization_id"`
	AgentID            string       `json:"agent_id"`
	Capability         string       `json:"capability"`
	Resource           string       `json:"resource"`
	DelegationChain    []ChainEntry `json:"delegation_chain"`
	DelegationDepth    int          `json:"delegation_depth"`
	LiabilityAssignee  string       `json:"liability_assignee"`
	PolicySnapshotRef  string       `json:"policy_snapshot_ref"`
	ExecutionResult    string       `json:"execution_result"` // "success" | "failure" | "unknown"
	ExecutedAt         int64        `json:"executed_at"`
	ConsumedBySystem   string       `json:"consumed_by_system"`
	ChainIncomplete    bool         `json:"chain_incomplete"`
}

// LedgerRecord wraps a LiabilityRecord with the ledger event metadata.
// Used by the in-memory store for query purposes (§9).
type LedgerRecord struct {
	LiabilityRecord
	LedgerEventID  string `json:"ledger_event_id"`
	LedgerSequence int64  `json:"ledger_sequence"`
}

// EmitRequest carries the inputs for liability record creation (§8).
type EmitRequest struct {
	ETID              string
	AuthorizationID   string
	AgentID           string
	Capability        string
	Resource          string
	DelegationChain   []ChainEntry // ordered by depth ASC; may be partial
	PolicySnapshotRef string       // UUID of active PSN at executed_at
	ExecutionResult   string       // "success" | "failure" | "unknown"
	ExecutedAt        int64
	ConsumedBySystem  string
	ChainIncomplete   bool
	// EscalationResolverAgentID is set if a human-resolved ESCALATION_RESOLVED
	// event exists for this et_id (§6 Rule 1).
	EscalationResolverAgentID string
	// SupervisorAgentID is the immediate supervisor in the chain (§6 Rule 2).
	// Set when executing agent autonomy_level < 2.
	SupervisorAgentID  string
	SupervisorAutonomy int // autonomy_level of executing agent
}

// ─── Emission ─────────────────────────────────────────────────────────────────

// Emit constructs a LiabilityRecord from the given request.
//
// Applies the §6 liability_assignee rules in order:
//
//	Rule 1: human-resolved escalation → EscalationResolverAgentID
//	Rule 2: autonomy_level < 2 → SupervisorAgentID
//	Rule 3: default → AgentID (the executor)
//
// The record is NOT written to the ledger here — callers MUST write it as a
// LIABILITY_RECORD event via the ledger package (§8 steps 7-9).
func Emit(req EmitRequest) (LiabilityRecord, error) {
	liabilityID, err := newUUID()
	if err != nil {
		return LiabilityRecord{}, fmt.Errorf("lia: generate id: %w", err)
	}

	assignee := resolveAssignee(req)

	depth := 0
	if len(req.DelegationChain) > 0 {
		depth = req.DelegationChain[len(req.DelegationChain)-1].Depth
	}

	return LiabilityRecord{
		LiabilityID:       liabilityID,
		ETID:              req.ETID,
		AuthorizationID:   req.AuthorizationID,
		AgentID:           req.AgentID,
		Capability:        req.Capability,
		Resource:          req.Resource,
		DelegationChain:   req.DelegationChain,
		DelegationDepth:   depth,
		LiabilityAssignee: assignee,
		PolicySnapshotRef: req.PolicySnapshotRef,
		ExecutionResult:   req.ExecutionResult,
		ExecutedAt:        req.ExecutedAt,
		ConsumedBySystem:  req.ConsumedBySystem,
		ChainIncomplete:   req.ChainIncomplete,
	}, nil
}

// resolveAssignee applies the §6 liability assignment rules in order.
func resolveAssignee(req EmitRequest) string {
	// Rule 1: human-resolved escalation
	if req.EscalationResolverAgentID != "" {
		return req.EscalationResolverAgentID
	}
	// Rule 2: autonomy_level < 2 and supervisor identifiable
	if req.SupervisorAutonomy < 2 && req.SupervisorAgentID != "" {
		return req.SupervisorAgentID
	}
	// Rule 3: default — executor bears responsibility
	return req.AgentID
}

// ─── In-memory Store ──────────────────────────────────────────────────────────

// InMemoryLiabilityStore is a thread-safe store for LedgerRecords.
// Supports lookup by liability_id, et_id, and agent_id (§9.1, §9.2, §9.3).
type InMemoryLiabilityStore struct {
	mu      sync.RWMutex
	records map[string]*LedgerRecord // keyed by liability_id
	byET    map[string]string        // et_id → liability_id
	byAgent map[string][]string      // agent_id → []liability_id (executor or assignee)
}

// NewInMemoryLiabilityStore creates an empty liability store.
func NewInMemoryLiabilityStore() *InMemoryLiabilityStore {
	return &InMemoryLiabilityStore{
		records: make(map[string]*LedgerRecord),
		byET:    make(map[string]string),
		byAgent: make(map[string][]string),
	}
}

// Store persists a LedgerRecord. Returns ErrDuplicate if et_id already has a record.
func (s *InMemoryLiabilityStore) Store(r LedgerRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.byET[r.ETID]; exists {
		return fmt.Errorf("%w: et_id=%s", ErrDuplicate, r.ETID)
	}
	s.records[r.LiabilityID] = &r
	s.byET[r.ETID] = r.LiabilityID

	// Index by executor agent_id
	s.byAgent[r.AgentID] = append(s.byAgent[r.AgentID], r.LiabilityID)
	// Index by assignee (if different from executor)
	if r.LiabilityAssignee != r.AgentID {
		s.byAgent[r.LiabilityAssignee] = append(s.byAgent[r.LiabilityAssignee], r.LiabilityID)
	}
	return nil
}

// GetByLiabilityID retrieves a record by liability_id (§9.1).
func (s *InMemoryLiabilityStore) GetByLiabilityID(liabilityID string) (LedgerRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[liabilityID]
	if !ok {
		return LedgerRecord{}, false
	}
	return *r, true
}

// GetByETID retrieves the record for a specific ET (§9.2).
func (s *InMemoryLiabilityStore) GetByETID(etID string) (LedgerRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byET[etID]
	if !ok {
		return LedgerRecord{}, false
	}
	r, ok := s.records[id]
	if !ok {
		return LedgerRecord{}, false
	}
	return *r, true
}

// AgentQueryFilter specifies filters for the by-agent query (§9.3).
type AgentQueryFilter struct {
	Role   string // "executor" | "assignee" | "any"
	FromTS int64  // 0 = no lower bound
	ToTS   int64  // 0 = no upper bound
	Limit  int    // 0 = use default (100)
}

// AgentQueryResult holds the paginated result for by-agent queries.
type AgentQueryResult struct {
	Items      []LedgerRecord
	TotalCount int
}

// GetByAgentID lists records where agent_id or liability_assignee match (§9.3).
func (s *InMemoryLiabilityStore) GetByAgentID(agentID string, f AgentQueryFilter) AgentQueryResult {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := s.byAgent[agentID]
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	var result []LedgerRecord
	for _, id := range ids {
		r, ok := s.records[id]
		if !ok {
			continue
		}
		// Role filter
		switch f.Role {
		case "executor":
			if r.AgentID != agentID {
				continue
			}
		case "assignee":
			if r.LiabilityAssignee != agentID {
				continue
			}
		}
		// Time filter
		if f.FromTS > 0 && r.ExecutedAt < f.FromTS {
			continue
		}
		if f.ToTS > 0 && r.ExecutedAt > f.ToTS {
			continue
		}
		result = append(result, *r)
		if len(result) >= limit {
			break
		}
	}

	return AgentQueryResult{
		Items:      result,
		TotalCount: len(result),
	}
}

// Size returns the number of stored records.
func (s *InMemoryLiabilityStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}

// ─── UUID helper ──────────────────────────────────────────────────────────────

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
