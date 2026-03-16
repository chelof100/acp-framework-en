// Package crossorg implements ACP-CROSS-ORG-1.0 (cross-organizational interaction registry).
//
// Provides signed bundle and acknowledgement handling for cross-institutional
// ACP interactions, including an in-memory store for bundles and ACKs.
package crossorg

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

// ─── Error Sentinels (ACP-CROSS-ORG-1.0) ─────────────────────────────────────

var (
	ErrMalformedEvent         = errors.New("CROSS-001: malformed event")
	ErrInvalidPayloadHash     = errors.New("CROSS-002: invalid payload_hash format")
	ErrEmptyDelegationChain   = errors.New("CROSS-003: empty or invalid delegation_chain")
	ErrNoActiveFederation     = errors.New("CROSS-004: no active federation")
	ErrAuthorizationNotFound  = errors.New("CROSS-005: authorization_id not found")
	ErrLiabilityRecordNotFound = errors.New("CROSS-006: liability_record_id not found")
	ErrEventAlreadyRecorded   = errors.New("CROSS-007: event already recorded")
	ErrBundleSigInvalid       = errors.New("CROSS-008: bundle signature verification failed")
	ErrEventSigInvalid        = errors.New("CROSS-009: event signature verification failed")
	ErrInvalidVersion         = errors.New("CROSS-010: unsupported version, expected 1.0")
)

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
	EventID             string                 `json:"event_id"`
	Timestamp           int64                  `json:"timestamp"`
	SourceInstitutionID string                 `json:"source_institution_id"`
	TargetInstitutionID string                 `json:"target_institution_id"`
	ActionType          string                 `json:"action_type"`
	PayloadHash         string                 `json:"payload_hash"`
	DelegationChain     []string               `json:"delegation_chain"`
	AuthorizationID     string                 `json:"authorization_id"`
	LiabilityRecordID   string                 `json:"liability_record_id"`
	AckRequired         bool                   `json:"ack_required"`
	Metadata            map[string]interface{} `json:"metadata"`
	Sig                 string                 `json:"sig"`
}

// signableInteraction excludes Sig for signing.
type signableInteraction struct {
	EventID             string                 `json:"event_id"`
	Timestamp           int64                  `json:"timestamp"`
	SourceInstitutionID string                 `json:"source_institution_id"`
	TargetInstitutionID string                 `json:"target_institution_id"`
	ActionType          string                 `json:"action_type"`
	PayloadHash         string                 `json:"payload_hash"`
	DelegationChain     []string               `json:"delegation_chain"`
	AuthorizationID     string                 `json:"authorization_id"`
	LiabilityRecordID   string                 `json:"liability_record_id"`
	AckRequired         bool                   `json:"ack_required"`
	Metadata            map[string]interface{} `json:"metadata"`
	Sig                 string                 `json:"sig"` // always "" when signing
}

// CrossOrgBundle is a signed container of cross-organizational interactions.
type CrossOrgBundle struct {
	BundleID            string                 `json:"bundle_id"`
	BundleVersion       string                 `json:"bundle_version"`
	SourceInstitutionID string                 `json:"source_institution_id"`
	TargetInstitutionID string                 `json:"target_institution_id"`
	CreatedAt           int64                  `json:"created_at"`
	Events              []CrossOrgInteraction  `json:"events"`
	Evidence            map[string]interface{} `json:"evidence"`
	Sig                 string                 `json:"sig"`
}

// signableBundle excludes Sig for signing.
type signableBundle struct {
	BundleID            string                 `json:"bundle_id"`
	BundleVersion       string                 `json:"bundle_version"`
	SourceInstitutionID string                 `json:"source_institution_id"`
	TargetInstitutionID string                 `json:"target_institution_id"`
	CreatedAt           int64                  `json:"created_at"`
	Events              []CrossOrgInteraction  `json:"events"`
	Evidence            map[string]interface{} `json:"evidence"`
	Sig                 string                 `json:"sig"` // always "" when signing
}

// CrossOrgAck is a signed acknowledgement for a cross-organizational interaction.
type CrossOrgAck struct {
	AckID               string `json:"ack_id"`
	OriginalEventID     string `json:"original_event_id"`
	TargetInstitutionID string `json:"target_institution_id"`
	SourceInstitutionID string `json:"source_institution_id"`
	ValidatedAt         int64  `json:"validated_at"`
	Status              string `json:"status"` // "accepted" | "rejected"
	LedgerSequence      int64  `json:"ledger_sequence"`
	Sig                 string `json:"sig"`
}

// signableAck excludes Sig for signing.
type signableAck struct {
	AckID               string `json:"ack_id"`
	OriginalEventID     string `json:"original_event_id"`
	TargetInstitutionID string `json:"target_institution_id"`
	SourceInstitutionID string `json:"source_institution_id"`
	ValidatedAt         int64  `json:"validated_at"`
	Status              string `json:"status"`
	LedgerSequence      int64  `json:"ledger_sequence"`
	Sig                 string `json:"sig"` // always "" when signing
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
		SourceInstitutionID: bundle.SourceInstitutionID,
		TargetInstitutionID: bundle.TargetInstitutionID,
		CreatedAt:           bundle.CreatedAt,
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
func BuildAck(
	eventID, targetInstitutionID, sourceInstitutionID, status string,
	ledgerSeq int64,
	privKey ed25519.PrivateKey,
) (CrossOrgAck, error) {
	ackID, err := newUUID()
	if err != nil {
		return CrossOrgAck{}, fmt.Errorf("crossorg: generate ack_id: %w", err)
	}

	ack := CrossOrgAck{
		AckID:               ackID,
		OriginalEventID:     eventID,
		TargetInstitutionID: targetInstitutionID,
		SourceInstitutionID: sourceInstitutionID,
		ValidatedAt:         time.Now().Unix(),
		Status:              status,
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
		OriginalEventID:     ack.OriginalEventID,
		TargetInstitutionID: ack.TargetInstitutionID,
		SourceInstitutionID: ack.SourceInstitutionID,
		ValidatedAt:         ack.ValidatedAt,
		Status:              ack.Status,
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
		SourceInstitutionID: bundle.SourceInstitutionID,
		TargetInstitutionID: bundle.TargetInstitutionID,
		CreatedAt:           bundle.CreatedAt,
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
		OriginalEventID:     ack.OriginalEventID,
		TargetInstitutionID: ack.TargetInstitutionID,
		SourceInstitutionID: ack.SourceInstitutionID,
		ValidatedAt:         ack.ValidatedAt,
		Status:              ack.Status,
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
	bundles map[string]CrossOrgBundle // bundle_id → bundle
	acks    map[string]CrossOrgAck    // ack_id → ack
}

// NewInMemoryCrossOrgStore creates an empty cross-org store.
func NewInMemoryCrossOrgStore() *InMemoryCrossOrgStore {
	return &InMemoryCrossOrgStore{
		bundles: make(map[string]CrossOrgBundle),
		acks:    make(map[string]CrossOrgAck),
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

// StoreAck persists an ACK.
func (s *InMemoryCrossOrgStore) StoreAck(ack CrossOrgAck) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.acks[ack.AckID] = ack
	return nil
}

// GetAck retrieves an ACK by AckID.
func (s *InMemoryCrossOrgStore) GetAck(ackID string) (CrossOrgAck, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.acks[ackID]
	return a, ok
}

// Size returns the total number of stored bundles.
func (s *InMemoryCrossOrgStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.bundles)
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
