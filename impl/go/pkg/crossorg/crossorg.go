// Package crossorg implements ACP-CROSS-ORG-1.1 (cross-organizational interaction registry).
//
// Provides signed bundle and acknowledgement handling for cross-institutional
// ACP interactions, including an in-memory store for bundles and ACKs.
//
// Key additions over 1.0:
//   - interaction_id (UUIDv7): mandatory correlation identifier, reused across retries.
//   - Retry state tracking: attempt count, last_attempt_at, ack_latency_ms.
//   - Derived interaction status: computed from ledger events (no mutable state field).
//   - New error sentinels: CROSS-012 through CROSS-015.
package crossorg

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gowebpki/jcs"
)

// ─── Error Sentinels (ACP-CROSS-ORG-1.1) ─────────────────────────────────────

var (
	ErrMalformedEvent          = errors.New("CROSS-001: malformed event")
	ErrInvalidPayloadHash      = errors.New("CROSS-002: invalid payload_hash format")
	ErrEmptyDelegationChain    = errors.New("CROSS-003: empty or invalid delegation_chain")
	ErrNoActiveFederation      = errors.New("CROSS-004: no active federation")
	ErrAuthorizationNotFound   = errors.New("CROSS-005: authorization_id not found")
	ErrLiabilityRecordNotFound = errors.New("CROSS-006: liability_record_id not found")
	ErrEventAlreadyRecorded    = errors.New("CROSS-007: interaction already recorded")
	ErrBundleSigInvalid        = errors.New("CROSS-008: bundle signature verification failed")
	ErrEventSigInvalid         = errors.New("CROSS-009: event signature verification failed")
	ErrFederationUnreachable   = errors.New("CROSS-010: ITA federation registry unreachable")
	ErrAckTimeout              = errors.New("CROSS-011: ack_required but no CrossOrgAck received within timeout")
	ErrRetryLimitExceeded      = errors.New("CROSS-012: retry limit exceeded (3 attempts); escalation triggered")
	ErrPendingReviewExpired    = errors.New("CROSS-013: pending_review SLA expired without resolution")
	ErrDuplicateInteraction    = errors.New("CROSS-014: duplicate interaction_id with different payload_hash or action_type")
	ErrInvalidACKTransition    = errors.New("CROSS-015: invalid ACK transition: pending_review → pending_review is prohibited")
)

// ─── Interaction Status (Derived — ACP-CROSS-ORG-1.1 §9) ─────────────────────

// InteractionStatus is the derived state of a cross-org interaction.
// It is always computed from ledger events — never stored directly.
type InteractionStatus string

const (
	StatusPendingAck     InteractionStatus = "pending_ack"
	StatusAcked          InteractionStatus = "acked"
	StatusRejected       InteractionStatus = "rejected"
	StatusPendingReview  InteractionStatus = "pending_review"
	StatusExpired        InteractionStatus = "expired"
)

// AckStatusAccepted, AckStatusRejected, AckStatusPendingReview are the valid
// values for CrossOrgAck.Status.
const (
	AckStatusAccepted      = "accepted"
	AckStatusRejected      = "rejected"
	AckStatusPendingReview = "pending_review"
)

// DeriveStatus computes the derived interaction status from a set of ACKs
// for a given interaction_id, applying the precedence rules from §9.
//
// acks must be all CrossOrgAck records for the interaction_id, ordered
// oldest-first. now is the current time used for expiry evaluation.
func DeriveStatus(acks []CrossOrgAck, now time.Time) InteractionStatus {
	if len(acks) == 0 {
		return StatusPendingAck
	}
	// Precedence: accepted > rejected > pending_review (+ expiry) > pending_ack
	for _, a := range acks {
		if a.Status == AckStatusAccepted {
			return StatusAcked
		}
	}
	for _, a := range acks {
		if a.Status == AckStatusRejected {
			return StatusRejected
		}
	}
	for _, a := range acks {
		if a.Status == AckStatusPendingReview {
			if a.ReviewDeadline > 0 && now.Unix() > a.ReviewDeadline {
				return StatusExpired
			}
			return StatusPendingReview
		}
	}
	return StatusPendingAck
}

// ─── Action Type Constants ────────────────────────────────────────────────────

const (
	ActionDataShare           = "data_share"
	ActionServiceInvocation   = "service_invocation"
	ActionDelegationTransfer  = "delegation_transfer"
	ActionComplianceQuery     = "compliance_query"
	ActionFinancialSettlement = "financial_settlement"
	ActionAuditRequest        = "audit_request"
	ActionReputationQuery     = "reputation_query"
)

var validActionTypes = map[string]struct{}{
	ActionDataShare:           {},
	ActionServiceInvocation:   {},
	ActionDelegationTransfer:  {},
	ActionComplianceQuery:     {},
	ActionFinancialSettlement: {},
	ActionAuditRequest:        {},
	ActionReputationQuery:     {},
}

// ─── Types ────────────────────────────────────────────────────────────────────

// CrossOrgInteraction is a single cross-organizational event within a bundle.
type CrossOrgInteraction struct {
	InteractionID       string                 `json:"interaction_id"`        // UUIDv7 — reused across retries
	EventID             string                 `json:"event_id"`              // UUIDv4 — unique per emission
	Timestamp           int64                  `json:"timestamp"`
	SourceInstitutionID string                 `json:"source_institution_id"`
	TargetInstitutionID string                 `json:"target_institution_id"`
	ActionType          string                 `json:"action_type"`
	PayloadHash         string                 `json:"payload_hash"`
	DelegationChain     []string               `json:"delegation_chain"`
	AuthorizationID     string                 `json:"authorization_id"`
	LiabilityRecordID   string                 `json:"liability_record_id"`
	AttemptNumber       int                    `json:"attempt_number"`        // 1-based; increments on retry
	AckRequired         bool                   `json:"ack_required"`
	Metadata            map[string]interface{} `json:"metadata"`
	Sig                 string                 `json:"sig"`
}

// signableInteraction excludes Sig for signing.
type signableInteraction struct {
	InteractionID       string                 `json:"interaction_id"`
	EventID             string                 `json:"event_id"`
	Timestamp           int64                  `json:"timestamp"`
	SourceInstitutionID string                 `json:"source_institution_id"`
	TargetInstitutionID string                 `json:"target_institution_id"`
	ActionType          string                 `json:"action_type"`
	PayloadHash         string                 `json:"payload_hash"`
	DelegationChain     []string               `json:"delegation_chain"`
	AuthorizationID     string                 `json:"authorization_id"`
	LiabilityRecordID   string                 `json:"liability_record_id"`
	AttemptNumber       int                    `json:"attempt_number"`
	AckRequired         bool                   `json:"ack_required"`
	Metadata            map[string]interface{} `json:"metadata"`
	Sig                 string                 `json:"sig"` // always "" when signing
}

// CrossOrgBundle is a signed container of cross-organizational interactions.
type CrossOrgBundle struct {
	BundleID            string                 `json:"bundle_id"`
	BundleVersion       string                 `json:"bundle_version"`
	InteractionID       string                 `json:"interaction_id"` // matches all contained events
	SourceInstitutionID string                 `json:"source_institution_id"`
	TargetInstitutionID string                 `json:"target_institution_id"`
	CreatedAt           int64                  `json:"created_at"`
	AttemptNumber       int                    `json:"attempt_number"`
	Events              []CrossOrgInteraction  `json:"events"`
	Evidence            map[string]interface{} `json:"evidence"`
	Sig                 string                 `json:"sig"`
}

// signableBundle excludes Sig for signing.
type signableBundle struct {
	BundleID            string                 `json:"bundle_id"`
	BundleVersion       string                 `json:"bundle_version"`
	InteractionID       string                 `json:"interaction_id"`
	SourceInstitutionID string                 `json:"source_institution_id"`
	TargetInstitutionID string                 `json:"target_institution_id"`
	CreatedAt           int64                  `json:"created_at"`
	AttemptNumber       int                    `json:"attempt_number"`
	Events              []CrossOrgInteraction  `json:"events"`
	Evidence            map[string]interface{} `json:"evidence"`
	Sig                 string                 `json:"sig"` // always "" when signing
}

// CrossOrgAck is a signed acknowledgement for a cross-organizational interaction.
// It is also a first-class CROSS_ORG_ACK ledger event (ACP-LEDGER-1.3 §5.15).
type CrossOrgAck struct {
	AckID               string `json:"ack_id"`
	InteractionID       string `json:"interaction_id"`
	OriginalEventID     string `json:"original_event_id"`
	TargetInstitutionID string `json:"target_institution_id"`
	SourceInstitutionID string `json:"source_institution_id"`
	ValidatedAt         int64  `json:"validated_at"`
	Status              string `json:"status"`          // "accepted" | "rejected" | "pending_review"
	ReviewDeadline      int64  `json:"review_deadline"` // unix seconds; 0 when not applicable
	RejectionReason     string `json:"rejection_reason,omitempty"`
	LedgerSequence      int64  `json:"ledger_sequence"`
	Sig                 string `json:"sig"`
}

// signableAck excludes Sig for signing.
type signableAck struct {
	AckID               string `json:"ack_id"`
	InteractionID       string `json:"interaction_id"`
	OriginalEventID     string `json:"original_event_id"`
	TargetInstitutionID string `json:"target_institution_id"`
	SourceInstitutionID string `json:"source_institution_id"`
	ValidatedAt         int64  `json:"validated_at"`
	Status              string `json:"status"`
	ReviewDeadline      int64  `json:"review_deadline"`
	RejectionReason     string `json:"rejection_reason,omitempty"`
	LedgerSequence      int64  `json:"ledger_sequence"`
	Sig                 string `json:"sig"` // always "" when signing
}

// RetryState is the observability record per interaction_id (§8.5).
// Never stored in the ledger — operational metadata only.
type RetryState struct {
	InteractionID       string    `json:"interaction_id"`
	AttemptCount        int       `json:"attempt_count"`
	LastAttemptAt       time.Time `json:"last_attempt_at"`
	LastAttemptEventID  string    `json:"last_attempt_event_id"`
	AckReceived         bool      `json:"ack_received"`
	RetryExhausted      bool      `json:"retry_exhausted"`
	AckLatencyMs        int64     `json:"ack_latency_ms"` // 0 until ACK received
}

// ReceiveBundleRequest wraps an incoming CrossOrgBundle for processing.
type ReceiveBundleRequest struct {
	Bundle CrossOrgBundle `json:"bundle"`
}

// ─── Core Functions ───────────────────────────────────────────────────────────

// IsValidActionType returns true if t is a recognised cross-org action type.
func IsValidActionType(t string) bool {
	_, ok := validActionTypes[t]
	return ok
}

// SignBundle signs the bundle and sets bundle.Sig.
func SignBundle(bundle *CrossOrgBundle, privKey ed25519.PrivateKey) error {
	sig, err := signBundle(*bundle, privKey)
	if err != nil {
		return err
	}
	bundle.Sig = sig
	return nil
}

// VerifyBundle verifies the Ed25519 signature on a CrossOrgBundle.
func VerifyBundle(bundle CrossOrgBundle, pubKey ed25519.PublicKey) error {
	sigBytes, err := base64.RawURLEncoding.DecodeString(bundle.Sig)
	if err != nil {
		return fmt.Errorf("%w: decode sig: %v", ErrBundleSigInvalid, err)
	}

	s := signableBundle{
		BundleID:            bundle.BundleID,
		BundleVersion:       bundle.BundleVersion,
		InteractionID:       bundle.InteractionID,
		SourceInstitutionID: bundle.SourceInstitutionID,
		TargetInstitutionID: bundle.TargetInstitutionID,
		CreatedAt:           bundle.CreatedAt,
		AttemptNumber:       bundle.AttemptNumber,
		Events:              bundle.Events,
		Evidence:            bundle.Evidence,
		Sig:                 "",
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("crossorg: marshal bundle: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return fmt.Errorf("crossorg: jcs bundle: %w", err)
	}
	digest := sha256.Sum256(canonical)
	if !ed25519.Verify(pubKey, digest[:], sigBytes) {
		return ErrBundleSigInvalid
	}
	return nil
}

// BuildAck creates a signed CrossOrgAck.
// status must be one of AckStatusAccepted, AckStatusRejected, AckStatusPendingReview.
// reviewDeadlineUnix is required (non-zero) when status == AckStatusPendingReview.
func BuildAck(
	interactionID, eventID, targetInstitutionID, sourceInstitutionID, status string,
	reviewDeadlineUnix int64,
	ledgerSeq int64,
	privKey ed25519.PrivateKey,
) (CrossOrgAck, error) {
	ackID, err := newUUID()
	if err != nil {
		return CrossOrgAck{}, fmt.Errorf("crossorg: generate ack_id: %w", err)
	}

	ack := CrossOrgAck{
		AckID:               ackID,
		InteractionID:       interactionID,
		OriginalEventID:     eventID,
		TargetInstitutionID: targetInstitutionID,
		SourceInstitutionID: sourceInstitutionID,
		ValidatedAt:         time.Now().Unix(),
		Status:              status,
		ReviewDeadline:      reviewDeadlineUnix,
		LedgerSequence:      ledgerSeq,
	}

	sig, err := signAck(ack, privKey)
	if err != nil {
		return CrossOrgAck{}, fmt.Errorf("crossorg: sign ack: %w", err)
	}
	ack.Sig = sig
	return ack, nil
}

// VerifyAck verifies the Ed25519 signature on a CrossOrgAck.
func VerifyAck(ack CrossOrgAck, pubKey ed25519.PublicKey) error {
	sigBytes, err := base64.RawURLEncoding.DecodeString(ack.Sig)
	if err != nil {
		return fmt.Errorf("%w: decode sig: %v", ErrEventSigInvalid, err)
	}

	s := signableAck{
		AckID:               ack.AckID,
		InteractionID:       ack.InteractionID,
		OriginalEventID:     ack.OriginalEventID,
		TargetInstitutionID: ack.TargetInstitutionID,
		SourceInstitutionID: ack.SourceInstitutionID,
		ValidatedAt:         ack.ValidatedAt,
		Status:              ack.Status,
		ReviewDeadline:      ack.ReviewDeadline,
		RejectionReason:     ack.RejectionReason,
		LedgerSequence:      ack.LedgerSequence,
		Sig:                 "",
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("crossorg: marshal ack: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return fmt.Errorf("crossorg: jcs ack: %w", err)
	}
	digest := sha256.Sum256(canonical)
	if !ed25519.Verify(pubKey, digest[:], sigBytes) {
		return ErrEventSigInvalid
	}
	return nil
}

// ─── Signing Helpers ─────────────────────────────────────────────────────────

func signBundle(bundle CrossOrgBundle, privKey ed25519.PrivateKey) (string, error) {
	s := signableBundle{
		BundleID:            bundle.BundleID,
		BundleVersion:       bundle.BundleVersion,
		InteractionID:       bundle.InteractionID,
		SourceInstitutionID: bundle.SourceInstitutionID,
		TargetInstitutionID: bundle.TargetInstitutionID,
		CreatedAt:           bundle.CreatedAt,
		AttemptNumber:       bundle.AttemptNumber,
		Events:              bundle.Events,
		Evidence:            bundle.Evidence,
		Sig:                 "",
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

func signAck(ack CrossOrgAck, privKey ed25519.PrivateKey) (string, error) {
	s := signableAck{
		AckID:               ack.AckID,
		InteractionID:       ack.InteractionID,
		OriginalEventID:     ack.OriginalEventID,
		TargetInstitutionID: ack.TargetInstitutionID,
		SourceInstitutionID: ack.SourceInstitutionID,
		ValidatedAt:         ack.ValidatedAt,
		Status:              ack.Status,
		ReviewDeadline:      ack.ReviewDeadline,
		RejectionReason:     ack.RejectionReason,
		LedgerSequence:      ack.LedgerSequence,
		Sig:                 "",
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

// ─── InMemoryCrossOrgStore ────────────────────────────────────────────────────

// InMemoryCrossOrgStore is a thread-safe in-memory store for bundles and ACKs.
type InMemoryCrossOrgStore struct {
	mu      sync.RWMutex
	bundles map[string]CrossOrgBundle   // bundle_id → bundle
	acks    map[string]CrossOrgAck      // ack_id → ack
	byIxID  map[string][]CrossOrgAck   // interaction_id → []ack (for DeriveStatus)
	retries map[string]*RetryState     // interaction_id → retry state
}

// NewInMemoryCrossOrgStore creates an empty cross-org store.
func NewInMemoryCrossOrgStore() *InMemoryCrossOrgStore {
	return &InMemoryCrossOrgStore{
		bundles: make(map[string]CrossOrgBundle),
		acks:    make(map[string]CrossOrgAck),
		byIxID:  make(map[string][]CrossOrgAck),
		retries: make(map[string]*RetryState),
	}
}

// Append stores a bundle. Returns ErrEventAlreadyRecorded if BundleID exists.
func (s *InMemoryCrossOrgStore) Append(bundle CrossOrgBundle) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.bundles[bundle.BundleID]; exists {
		return fmt.Errorf("%w: %s", ErrEventAlreadyRecorded, bundle.BundleID)
	}
	s.bundles[bundle.BundleID] = bundle
	return nil
}

// GetBundle retrieves a bundle by BundleID.
func (s *InMemoryCrossOrgStore) GetBundle(bundleID string) (CrossOrgBundle, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.bundles[bundleID]
	return b, ok
}

// ListBySource returns all bundles whose SourceInstitutionID matches.
func (s *InMemoryCrossOrgStore) ListBySource(sourceInstitutionID string) []CrossOrgBundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []CrossOrgBundle
	for _, b := range s.bundles {
		if b.SourceInstitutionID == sourceInstitutionID {
			result = append(result, b)
		}
	}
	return result
}

// ListByTarget returns all bundles whose TargetInstitutionID matches.
func (s *InMemoryCrossOrgStore) ListByTarget(targetInstitutionID string) []CrossOrgBundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []CrossOrgBundle
	for _, b := range s.bundles {
		if b.TargetInstitutionID == targetInstitutionID {
			result = append(result, b)
		}
	}
	return result
}

// StoreAck persists an ACK and indexes it by interaction_id.
func (s *InMemoryCrossOrgStore) StoreAck(ack CrossOrgAck) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acks[ack.AckID] = ack
	s.byIxID[ack.InteractionID] = append(s.byIxID[ack.InteractionID], ack)
	return nil
}

// GetAck retrieves an ACK by AckID.
func (s *InMemoryCrossOrgStore) GetAck(ackID string) (CrossOrgAck, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.acks[ackID]
	return a, ok
}

// GetStatus computes the derived interaction status for an interaction_id.
// Implements ACP-CROSS-ORG-1.1 §9 precedence rules.
func (s *InMemoryCrossOrgStore) GetStatus(interactionID string, now time.Time) InteractionStatus {
	s.mu.RLock()
	acks := s.byIxID[interactionID]
	s.mu.RUnlock()
	return DeriveStatus(acks, now)
}

// GetRetryState returns the retry state for an interaction_id, or nil if unknown.
func (s *InMemoryCrossOrgStore) GetRetryState(interactionID string) *RetryState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.retries[interactionID]
}

// UpdateRetryState sets or updates the retry state for an interaction_id.
func (s *InMemoryCrossOrgStore) UpdateRetryState(state *RetryState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retries[state.InteractionID] = state
}

// Size returns the total number of stored bundles.
func (s *InMemoryCrossOrgStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.bundles)
}

// ─── UUID Helpers ─────────────────────────────────────────────────────────────

// newUUID generates a random UUIDv4.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// NewInteractionID generates a UUIDv7 for use as an interaction_id.
// UUIDv7 encodes the current Unix time in milliseconds in the most-significant
// bits, making IDs time-ordered and suitable for deduplication correlation.
func NewInteractionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// Embed current time (ms) in bits 0–47.
	ms := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint32(b[0:4], uint32(ms>>16))
	binary.BigEndian.PutUint16(b[4:6], uint16(ms&0xffff))
	// Set version 7.
	b[6] = (b[6] & 0x0f) | 0x70
	// Set variant RFC 4122.
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
