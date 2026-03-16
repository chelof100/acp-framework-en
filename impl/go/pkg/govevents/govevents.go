// Package govevents implements ACP-GOV-EVENTS-1.0.
//
// The Governance Event Stream is a formally typed, signed, ordered record of
// every institutional change to the authority state of the ACP ecosystem.
// Events are produced by the ACP server and consumed by external systems
// (MIR, ARAF, auditors).
//
// 10 normative event types defined in §5:
//   delegation_revoked, agent_suspended, agent_reinstated, policy_updated,
//   authority_transferred, sanction_applied, capability_suspended,
//   capability_reinstated, trust_anchor_rotated, compliance_finding
//
// Required for L4-EXTENDED conformance (ACP-CONF-1.2).
package govevents

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gowebpki/jcs"
)

// ─── Error Sentinels (ACP-GOV-EVENTS-1.0 §10) ────────────────────────────────

var (
	ErrUnknownEventType       = errors.New("GEVE-001: unknown event type")
	ErrInstitutionalSig       = errors.New("GEVE-002: institutional signature invalid")
	ErrRequiredPayloadField   = errors.New("GEVE-003: required payload field missing for event type")
	ErrEffectiveAtBeforeStamp = errors.New("GEVE-004: effective_at before timestamp")
	ErrEvidenceRefNotFound    = errors.New("GEVE-005: evidence_ref references nonexistent ledger entry")
	ErrDuplicateEventID       = errors.New("GEVE-006: duplicate event_id received")
	ErrMissingOriginatorSig   = errors.New("GEVE-007: cross-institutional event missing originating signature")
	ErrInvalidVersion         = errors.New("GEVE-010: unsupported version, expected 1.0")
)

// ─── Event Type Constants (§5) ────────────────────────────────────────────────

const (
	TypeDelegationRevoked   = "delegation_revoked"
	TypeAgentSuspended      = "agent_suspended"
	TypeAgentReinstated     = "agent_reinstated"
	TypePolicyUpdated       = "policy_updated"
	TypeAuthorityTransferred = "authority_transferred"
	TypeSanctionApplied     = "sanction_applied"
	TypeCapabilitySuspended = "capability_suspended"
	TypeCapabilityReinstated = "capability_reinstated"
	TypeTrustAnchorRotated  = "trust_anchor_rotated"
	TypeComplianceFinding   = "compliance_finding"
)

// validEventTypes is the canonical set of normative event types.
var validEventTypes = map[string]struct{}{
	TypeDelegationRevoked:    {},
	TypeAgentSuspended:       {},
	TypeAgentReinstated:      {},
	TypePolicyUpdated:        {},
	TypeAuthorityTransferred: {},
	TypeSanctionApplied:      {},
	TypeCapabilitySuspended:  {},
	TypeCapabilityReinstated: {},
	TypeTrustAnchorRotated:   {},
	TypeComplianceFinding:    {},
}

// ─── Governance Event Object (§4) ─────────────────────────────────────────────

// GovernanceEvent is the top-level governance event structure (§4.1).
// The Sig field covers all other fields via Ed25519(SHA-256(JCS(signable))).
type GovernanceEvent struct {
	Ver           string      `json:"ver"`
	EventID       string      `json:"event_id"`
	EventType     string      `json:"event_type"`
	InstitutionID string      `json:"institution_id"`
	AgentID       *string     `json:"agent_id"` // null if event targets no specific agent
	TriggeredBy   string      `json:"triggered_by"`
	Timestamp     int64       `json:"timestamp"`
	EffectiveAt   int64       `json:"effective_at"`
	Reason        string      `json:"reason"`
	EvidenceRef   *string     `json:"evidence_ref"` // ledger entry ID or null
	Payload       interface{} `json:"payload"`
	Sig           string      `json:"sig"`
}

// signableEvent excludes sig from the signing input.
type signableEvent struct {
	Ver           string      `json:"ver"`
	EventID       string      `json:"event_id"`
	EventType     string      `json:"event_type"`
	InstitutionID string      `json:"institution_id"`
	AgentID       *string     `json:"agent_id"`
	TriggeredBy   string      `json:"triggered_by"`
	Timestamp     int64       `json:"timestamp"`
	EffectiveAt   int64       `json:"effective_at"`
	Reason        string      `json:"reason"`
	EvidenceRef   *string     `json:"evidence_ref"`
	Payload       interface{} `json:"payload"`
	Sig           string      `json:"sig"` // always "" when signing
}

// EmitRequest holds the inputs for governance event emission.
type EmitRequest struct {
	EventType     string
	InstitutionID string
	AgentID       *string     // nil if event is institution-level
	TriggeredBy   string
	Reason        string
	EvidenceRef   *string     // nil if no ledger evidence
	EffectiveAt   *int64      // nil means effective immediately (= timestamp)
	Payload       interface{}
}

// ─── Payload Types (§5) ──────────────────────────────────────────────────────

// DelegationRevokedPayload is the payload for delegation_revoked (§5.1).
type DelegationRevokedPayload struct {
	DelegationID        string `json:"delegation_id"`
	Delegator           string `json:"delegator"`
	Delegatee           string `json:"delegatee"`
	CapabilityAffected  string `json:"capability_affected"`
	RevocationID        string `json:"revocation_id"`
}

// AgentSuspendedPayload is the payload for agent_suspended (§5.2).
type AgentSuspendedPayload struct {
	SuspensionID             string   `json:"suspension_id"`
	SuspendedUntil           *int64   `json:"suspended_until"` // null = indefinite
	CapabilitiesFrozen       []string `json:"capabilities_frozen"`
	ActiveDelegationsFrozen  []string `json:"active_delegations_frozen"`
}

// AgentReinstatedPayload is the payload for agent_reinstated (§5.3).
type AgentReinstatedPayload struct {
	SuspensionID          string   `json:"suspension_id"`
	ReinstatedBy          string   `json:"reinstated_by"`
	CapabilitiesRestored  []string `json:"capabilities_restored"`
}

// PolicyUpdatedPayload is the payload for policy_updated (§5.4).
type PolicyUpdatedPayload struct {
	PolicyID              string   `json:"policy_id"`
	PreviousVersion       string   `json:"previous_version"`
	NewVersion            string   `json:"new_version"`
	NewPolicyHash         string   `json:"new_policy_hash"`
	BreakingChange        bool     `json:"breaking_change"`
	AffectedCapabilities  []string `json:"affected_capabilities"`
}

// AuthorityTransferredPayload is the payload for authority_transferred (§5.5).
type AuthorityTransferredPayload struct {
	TransferID               string   `json:"transfer_id"`
	FromInstitution          string   `json:"from_institution"`
	ToInstitution            string   `json:"to_institution"`
	TransferredCapabilities  []string `json:"transferred_capabilities"`
	AcceptanceRef            string   `json:"acceptance_ref"`
}

// SanctionAppliedPayload is the payload for sanction_applied (§5.6).
type SanctionAppliedPayload struct {
	SanctionID        string  `json:"sanction_id"`
	SanctionType      string  `json:"sanction_type"` // capability_restriction | delegation_limit | audit_escalation | full_suspension
	Scope             string  `json:"scope"`
	ViolationRef      string  `json:"violation_ref"`
	Duration          *int64  `json:"duration"`           // null = indefinite
	ExternalOrderRef  *string `json:"external_order_ref"` // null if no external order
}

// CapabilitySuspendedPayload is the payload for capability_suspended (§5.7).
type CapabilitySuspendedPayload struct {
	Capability     string `json:"capability"`
	SuspendedUntil *int64 `json:"suspended_until"` // null = indefinite
	ReasonCode     string `json:"reason_code"`
}

// CapabilityReinstatedPayload is the payload for capability_reinstated (§5.8).
type CapabilityReinstatedPayload struct {
	Capability    string `json:"capability"`
	ReinstatedBy  string `json:"reinstated_by"`
}

// TrustAnchorRotatedPayload is the payload for trust_anchor_rotated (§5.9).
type TrustAnchorRotatedPayload struct {
	OldKeyID      string `json:"old_key_id"`
	NewKeyID      string `json:"new_key_id"`
	RotationType  string `json:"rotation_type"` // "scheduled" | "emergency"
	OverlapPeriod int64  `json:"overlap_period"` // seconds
	NewPublicKey  string `json:"new_public_key"` // base64url Ed25519
}

// ComplianceFindingPayload is the payload for compliance_finding (§5.10).
type ComplianceFindingPayload struct {
	FindingID              string   `json:"finding_id"`
	Severity               string   `json:"severity"` // "critical" | "major" | "minor"
	FindingType            string   `json:"finding_type"`
	AffectedSpec           string   `json:"affected_spec"`
	RemediationRequired    bool     `json:"remediation_required"`
	RemediationDeadline    *int64   `json:"remediation_deadline"` // null if not required
	EvidenceRefs           []string `json:"evidence_refs"`
}

// ─── Emission ─────────────────────────────────────────────────────────────────

// Emit creates and signs a GovernanceEvent.
//
// privKey may be nil (dev/test mode — sig field will be empty).
//
// Returns ErrUnknownEventType if event_type is not in the normative taxonomy.
// Returns ErrEffectiveAtBeforeStamp if effective_at < timestamp.
func Emit(req EmitRequest, privKey ed25519.PrivateKey) (GovernanceEvent, error) {
	if _, ok := validEventTypes[req.EventType]; !ok {
		return GovernanceEvent{}, fmt.Errorf("%w: %q", ErrUnknownEventType, req.EventType)
	}

	eventID, err := newUUID()
	if err != nil {
		return GovernanceEvent{}, fmt.Errorf("govevents: generate id: %w", err)
	}

	now := time.Now().Unix()
	effectiveAt := now
	if req.EffectiveAt != nil {
		effectiveAt = *req.EffectiveAt
	}

	if effectiveAt < now {
		// Allow timestamps in the very recent past (clock skew), but reject obviously wrong values.
		// Per §4.2: effective_at MAY equal timestamp. Reject only strict before.
		if now-effectiveAt > 60 {
			return GovernanceEvent{}, fmt.Errorf("%w: effective_at %d < timestamp %d",
				ErrEffectiveAtBeforeStamp, effectiveAt, now)
		}
	}

	ev := GovernanceEvent{
		Ver:           "1.0",
		EventID:       eventID,
		EventType:     req.EventType,
		InstitutionID: req.InstitutionID,
		AgentID:       req.AgentID,
		TriggeredBy:   req.TriggeredBy,
		Timestamp:     now,
		EffectiveAt:   effectiveAt,
		Reason:        req.Reason,
		EvidenceRef:   req.EvidenceRef,
		Payload:       req.Payload,
	}

	if privKey != nil {
		sig, err := signEvent(ev, privKey)
		if err != nil {
			return GovernanceEvent{}, fmt.Errorf("govevents: sign: %w", err)
		}
		ev.Sig = sig
	}

	return ev, nil
}

// ─── Validation ───────────────────────────────────────────────────────────────

// VerifySig verifies the institutional signature on a GovernanceEvent (§4.2).
func VerifySig(ev GovernanceEvent, pubKey ed25519.PublicKey) error {
	if ev.Ver != "1.0" {
		return ErrInvalidVersion
	}
	if ev.Sig == "" {
		return fmt.Errorf("%w: sig is empty", ErrInstitutionalSig)
	}

	s := signableEvent{
		Ver:           ev.Ver,
		EventID:       ev.EventID,
		EventType:     ev.EventType,
		InstitutionID: ev.InstitutionID,
		AgentID:       ev.AgentID,
		TriggeredBy:   ev.TriggeredBy,
		Timestamp:     ev.Timestamp,
		EffectiveAt:   ev.EffectiveAt,
		Reason:        ev.Reason,
		EvidenceRef:   ev.EvidenceRef,
		Payload:       ev.Payload,
		Sig:           "",
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("govevents: marshal signable: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return fmt.Errorf("govevents: jcs: %w", err)
	}
	digest := sha256.Sum256(canonical)
	sigBytes, err := base64.RawURLEncoding.DecodeString(ev.Sig)
	if err != nil {
		return fmt.Errorf("%w: decode sig: %v", ErrInstitutionalSig, err)
	}
	if !ed25519.Verify(pubKey, digest[:], sigBytes) {
		return ErrInstitutionalSig
	}
	return nil
}

// IsValidEventType returns true if the given string is a normative event type.
func IsValidEventType(t string) bool {
	_, ok := validEventTypes[t]
	return ok
}

// ─── In-memory Event Stream ───────────────────────────────────────────────────

// InMemoryEventStream is a thread-safe, ordered governance event stream.
// Implements §6 stream semantics: ordered by timestamp, deduplicated by event_id.
type InMemoryEventStream struct {
	mu       sync.RWMutex
	events   []GovernanceEvent
	byID     map[string]int // event_id → index
	sequence int64          // monotonically increasing
}

// NewInMemoryEventStream creates an empty governance event stream.
func NewInMemoryEventStream() *InMemoryEventStream {
	return &InMemoryEventStream{
		byID: make(map[string]int),
	}
}

// Append adds a GovernanceEvent to the stream.
// Returns ErrDuplicateEventID if the event_id already exists (§6.2).
func (s *InMemoryEventStream) Append(ev GovernanceEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byID[ev.EventID]; exists {
		return fmt.Errorf("%w: %s", ErrDuplicateEventID, ev.EventID)
	}
	s.sequence++
	idx := len(s.events)
	s.events = append(s.events, ev)
	s.byID[ev.EventID] = idx
	return nil
}

// Get retrieves a GovernanceEvent by event_id.
func (s *InMemoryEventStream) Get(eventID string) (GovernanceEvent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.byID[eventID]
	if !ok {
		return GovernanceEvent{}, false
	}
	return s.events[idx], true
}

// QueryFilter defines filters for the List query (§7).
type QueryFilter struct {
	Since   int64    // return events with timestamp >= Since (0 = all)
	Types   []string // filter by event_type (nil = all types)
	AgentID string   // filter by agent_id (empty = all agents)
}

// List returns governance events matching the given filter (§7).
// Results are ordered by timestamp (ascending).
func (s *InMemoryEventStream) List(f QueryFilter) []GovernanceEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	typeSet := make(map[string]struct{}, len(f.Types))
	for _, t := range f.Types {
		typeSet[t] = struct{}{}
	}

	var result []GovernanceEvent
	for _, ev := range s.events {
		if f.Since > 0 && ev.Timestamp < f.Since {
			continue
		}
		if len(typeSet) > 0 {
			if _, ok := typeSet[ev.EventType]; !ok {
				continue
			}
		}
		if f.AgentID != "" {
			if ev.AgentID == nil || *ev.AgentID != f.AgentID {
				continue
			}
		}
		result = append(result, ev)
	}
	return result
}

// Size returns the number of events in the stream.
func (s *InMemoryEventStream) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.events)
}

// ─── Signing helper ───────────────────────────────────────────────────────────

func signEvent(ev GovernanceEvent, privKey ed25519.PrivateKey) (string, error) {
	s := signableEvent{
		Ver:           ev.Ver,
		EventID:       ev.EventID,
		EventType:     ev.EventType,
		InstitutionID: ev.InstitutionID,
		AgentID:       ev.AgentID,
		TriggeredBy:   ev.TriggeredBy,
		Timestamp:     ev.Timestamp,
		EffectiveAt:   ev.EffectiveAt,
		Reason:        ev.Reason,
		EvidenceRef:   ev.EvidenceRef,
		Payload:       ev.Payload,
		Sig:           "",
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("jcs: %w", err)
	}
	digest := sha256.Sum256(canonical)
	sig := ed25519.Sign(privKey, digest[:])
	return base64.RawURLEncoding.EncodeToString(sig), nil
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
