// Package pay implements ACP-PAY-1.0 (payment extension).
//
// Provides payment token verification, signed payment-verified event emission,
// and an in-memory store for payment events with double-spend detection.
package pay

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

// ─── Error Sentinels (ACP-PAY-1.0) ───────────────────────────────────────────

var (
	ErrMalformedPaymentCondition  = errors.New("PAY-001: malformed payment_condition")
	ErrInvalidSettlementProof     = errors.New("PAY-002: invalid or unverifiable settlement proof")
	ErrInsufficientAmount         = errors.New("PAY-003: insufficient amount")
	ErrPaymentConditionExpired    = errors.New("PAY-004: payment condition expired")
	ErrDoubleSpend                = errors.New("PAY-005: double-spend detected — proof_id already recorded")
	ErrPaymentSystemUnavailable   = errors.New("PAY-006: payment verification system unavailable")
	ErrInvalidVersion             = errors.New("PAY-010: unsupported version, expected 1.0")
)

// ─── Types ────────────────────────────────────────────────────────────────────

// PaymentCondition describes the required payment terms for a capability.
type PaymentCondition struct {
	Amount    float64 `json:"amount"`
	Currency  string  `json:"currency"`
	ExpiresAt int64   `json:"expires_at"`
}

// SettlementProof is evidence that a payment has been settled.
type SettlementProof struct {
	ProofID          string                 `json:"proof_id"`
	Type             string                 `json:"type"` // "on-chain" | "off-chain-channel" | "corporate-ledger"
	Amount           float64                `json:"amount"`
	Currency         string                 `json:"currency"`
	Recipient        string                 `json:"recipient"`
	Timestamp        int64                  `json:"timestamp"`
	ConfirmationData map[string]interface{} `json:"confirmation_data"`
	Sig              string                 `json:"sig"`
}

// ACPPayToken wraps the capability claim with its payment condition and proof.
type ACPPayToken struct {
	CapabilityClaim  string           `json:"capability_claim"`
	PaymentCondition PaymentCondition `json:"payment_condition"`
	Proof            SettlementProof  `json:"proof"`
}

// PaymentVerifiedEvent is the signed event emitted after successful token verification.
type PaymentVerifiedEvent struct {
	Ver          string  `json:"ver"`
	EventID      string  `json:"event_id"`
	EventType    string  `json:"event_type"`
	Timestamp    int64   `json:"timestamp"`
	AgentID      string  `json:"agent_id"`
	InstitutionID string  `json:"institution_id"`
	ProofID      string  `json:"proof_id"`
	Resource     string  `json:"resource"`
	CapabilityID string  `json:"capability_id"`
	Amount       float64 `json:"amount"`
	Currency     string  `json:"currency"`
	PrevHash     string  `json:"prev_hash"`
	Sig          string  `json:"sig"`
}

// signableEvent excludes Sig for signing.
type signableEvent struct {
	Ver          string  `json:"ver"`
	EventID      string  `json:"event_id"`
	EventType    string  `json:"event_type"`
	Timestamp    int64   `json:"timestamp"`
	AgentID      string  `json:"agent_id"`
	InstitutionID string  `json:"institution_id"`
	ProofID      string  `json:"proof_id"`
	Resource     string  `json:"resource"`
	CapabilityID string  `json:"capability_id"`
	Amount       float64 `json:"amount"`
	Currency     string  `json:"currency"`
	PrevHash     string  `json:"prev_hash"`
	Sig          string  `json:"sig"` // always "" when signing
}

// VerifyRequest is the input to VerifyToken.
type VerifyRequest struct {
	Token         ACPPayToken `json:"token"`
	AgentID       string      `json:"agent_id"`
	InstitutionID string      `json:"institution_id"`
	Resource      string      `json:"resource"`
	CapabilityID  string      `json:"capability_id"`
}

// ─── Core Functions ───────────────────────────────────────────────────────────

// VerifyToken validates an ACPPayToken and, on success, creates and signs a
// PaymentVerifiedEvent (ver="1.0", EventType="PAYMENT_VERIFIED").
//
// Validation order:
//  1. req.Token.Proof.ProofID not empty → ErrMalformedPaymentCondition
//  2. PaymentCondition.ExpiresAt >= now → ErrPaymentConditionExpired
//  3. PaymentCondition.Amount > 0       → ErrInsufficientAmount
func VerifyToken(req VerifyRequest, now int64, privKey ed25519.PrivateKey) (PaymentVerifiedEvent, error) {
	if req.Token.Proof.ProofID == "" {
		return PaymentVerifiedEvent{}, ErrMalformedPaymentCondition
	}
	if req.Token.PaymentCondition.ExpiresAt < now {
		return PaymentVerifiedEvent{}, ErrPaymentConditionExpired
	}
	if req.Token.PaymentCondition.Amount <= 0 {
		return PaymentVerifiedEvent{}, ErrInsufficientAmount
	}

	eventID, err := newUUID()
	if err != nil {
		return PaymentVerifiedEvent{}, fmt.Errorf("pay: generate event_id: %w", err)
	}

	ev := PaymentVerifiedEvent{
		Ver:          "1.0",
		EventID:      eventID,
		EventType:    "PAYMENT_VERIFIED",
		Timestamp:    time.Now().Unix(),
		AgentID:      req.AgentID,
		InstitutionID: req.InstitutionID,
		ProofID:      req.Token.Proof.ProofID,
		Resource:     req.Resource,
		CapabilityID: req.CapabilityID,
		Amount:       req.Token.PaymentCondition.Amount,
		Currency:     req.Token.PaymentCondition.Currency,
		PrevHash:     "",
	}

	sig, err := signEvent(ev, privKey)
	if err != nil {
		return PaymentVerifiedEvent{}, fmt.Errorf("pay: sign event: %w", err)
	}
	ev.Sig = sig
	return ev, nil
}

// GetProof retrieves the SettlementProof from a stored PaymentVerifiedEvent by ProofID.
func GetProof(store *InMemoryPayStore, proofID string) (SettlementProof, bool) {
	ev, ok := store.GetEvent(proofID)
	if !ok {
		return SettlementProof{}, false
	}
	return SettlementProof{
		ProofID: ev.ProofID,
		Amount:  ev.Amount,
		Currency: ev.Currency,
	}, true
}

// ─── Signing Helper ───────────────────────────────────────────────────────────

func signEvent(ev PaymentVerifiedEvent, privKey ed25519.PrivateKey) (string, error) {
	s := signableEvent{
		Ver:          ev.Ver,
		EventID:      ev.EventID,
		EventType:    ev.EventType,
		Timestamp:    ev.Timestamp,
		AgentID:      ev.AgentID,
		InstitutionID: ev.InstitutionID,
		ProofID:      ev.ProofID,
		Resource:     ev.Resource,
		CapabilityID: ev.CapabilityID,
		Amount:       ev.Amount,
		Currency:     ev.Currency,
		PrevHash:     ev.PrevHash,
		Sig:          "",
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

// ─── InMemoryPayStore ─────────────────────────────────────────────────────────

// InMemoryPayStore is a thread-safe in-memory store for PaymentVerifiedEvents.
// Keyed by ProofID to enable double-spend detection.
type InMemoryPayStore struct {
	mu     sync.RWMutex
	byProof map[string]PaymentVerifiedEvent // proof_id → event
	byAgent map[string][]string             // agent_id → []proof_id
}

// NewInMemoryPayStore creates an empty payment store.
func NewInMemoryPayStore() *InMemoryPayStore {
	return &InMemoryPayStore{
		byProof: make(map[string]PaymentVerifiedEvent),
		byAgent: make(map[string][]string),
	}
}

// StoreEvent stores a PaymentVerifiedEvent.
// Returns ErrDoubleSpend if the ProofID is already present.
func (s *InMemoryPayStore) StoreEvent(ev PaymentVerifiedEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byProof[ev.ProofID]; exists {
		return fmt.Errorf("%w: %s", ErrDoubleSpend, ev.ProofID)
	}
	s.byProof[ev.ProofID] = ev
	s.byAgent[ev.AgentID] = append(s.byAgent[ev.AgentID], ev.ProofID)
	return nil
}

// GetEvent retrieves a PaymentVerifiedEvent by ProofID.
func (s *InMemoryPayStore) GetEvent(proofID string) (PaymentVerifiedEvent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ev, ok := s.byProof[proofID]
	return ev, ok
}

// ListByAgent returns all events associated with a given AgentID.
func (s *InMemoryPayStore) ListByAgent(agentID string) []PaymentVerifiedEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	proofIDs, ok := s.byAgent[agentID]
	if !ok {
		return nil
	}
	result := make([]PaymentVerifiedEvent, 0, len(proofIDs))
	for _, pid := range proofIDs {
		if ev, ok := s.byProof[pid]; ok {
			result = append(result, ev)
		}
	}
	return result
}

// Size returns the total number of stored events.
func (s *InMemoryPayStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byProof)
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
