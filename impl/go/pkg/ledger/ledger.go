// Package ledger implements ACP-LEDGER-1.3.
//
// An ACP Audit Ledger is an append-only, hash-chained sequence of events that
// provides tamper-evident, cryptographically verifiable audit records of all
// significant ACP protocol operations.
//
// Key properties:
//   - Append-only: no delete, modify, or reorder
//   - Hash chain: each event commits to its predecessor via SHA-256
//   - JCS (RFC 8785): deterministic canonicalization for cross-platform reproducibility
//   - Ed25519: institutional signature over hash (transitively covering all fields)
//   - chain_valid: every query response MUST include this field
package ledger

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

// ─── Constants ─────────────────────────────────────────────────────────────────

const (
	// Version is the ACP-LEDGER-1.3 protocol version string.
	Version = "1.3"

	// GenesisHash is the fixed prev_hash for the first ledger event (§4.2).
	// Represents 32 zero bytes encoded as base64url with padding.
	GenesisHash = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

// ─── Error Sentinels (ACP-LEDGER-1.0 §12) ─────────────────────────────────────

var (
	// ErrModificationRejected is returned when a write operation violates immutability.
	ErrModificationRejected = errors.New("LEDGER-001: modification rejected")

	// ErrInvalidSignature is returned when event signature verification fails.
	ErrInvalidSignature = errors.New("LEDGER-002: invalid signature")

	// ErrHashMismatch is returned when the computed hash does not match stored hash.
	ErrHashMismatch = errors.New("LEDGER-003: hash mismatch")

	// ErrPrevHashBroken is returned when prev_hash does not match predecessor hash.
	ErrPrevHashBroken = errors.New("LEDGER-004: prev_hash broken")

	// ErrSequenceGap is returned when sequence is not predecessor+1.
	ErrSequenceGap = errors.New("LEDGER-005: sequence gap")

	// ErrTimestampRegression is returned when timestamp < predecessor timestamp.
	ErrTimestampRegression = errors.New("LEDGER-006: timestamp regression")

	// ErrGenesisMissing is returned when the genesis event is absent or invalid.
	ErrGenesisMissing = errors.New("LEDGER-007: genesis event missing or invalid")

	// ErrUnknownEventType is returned when event_type is not in the known set.
	ErrUnknownEventType = errors.New("LEDGER-008: unknown event type")

	// ErrIncompletePayload is returned when payload is missing required fields.
	ErrIncompletePayload = errors.New("LEDGER-009: incomplete payload")

	// ErrMissingPolicySnapshotRef is returned when an AUTHORIZATION or RISK_EVALUATION
	// event is missing the required policy_snapshot_ref field (ACP-LEDGER-1.3 §5.2, §5.3).
	ErrMissingPolicySnapshotRef = errors.New("LEDGER-010: missing policy_snapshot_ref")

	// ErrSigMissing is returned when sig is absent or empty on a production event.
	// Per ACP-LEDGER-1.3 §4.4, sig MUST be present and non-empty.
	ErrSigMissing = errors.New("LEDGER-012: sig missing or empty")
)

// ─── Event Types (ACP-LEDGER-1.3 §5) ─────────────────────────────────────────

const (
	// Core event types (v1.0)
	EventLedgerGenesis          = "LEDGER_GENESIS"
	EventAuthorization          = "AUTHORIZATION"
	EventRiskEvaluation         = "RISK_EVALUATION"
	EventRevocation             = "REVOCATION"
	EventTokenIssued            = "TOKEN_ISSUED"
	EventExecutionTokenIssued   = "EXECUTION_TOKEN_ISSUED"
	EventExecutionTokenConsumed = "EXECUTION_TOKEN_CONSUMED"
	EventAgentRegistered        = "AGENT_REGISTERED"
	EventAgentStateChange       = "AGENT_STATE_CHANGE"
	EventEscalationCreated      = "ESCALATION_CREATED"
	EventEscalationResolved     = "ESCALATION_RESOLVED"

	// Extended event types (v1.1 — ACP-LIA-1.0, ACP-PSN-1.0, ACP-REP-1.2)
	EventLiabilityRecord       = "LIABILITY_RECORD"
	EventPolicySnapshotCreated = "POLICY_SNAPSHOT_CREATED"
	EventReputationUpdated     = "REPUTATION_UPDATED"

	// Evidence layer event types (v1.3 — ACP-PROVENANCE-1.0, ACP-POLICY-CTX-1.0, ACP-GOV-EVENTS-1.0)
	EventProvenance      = "PROVENANCE"
	EventPolicySnapshot  = "POLICY_SNAPSHOT"
	EventGovernance      = "GOVERNANCE"
)

// validEventTypes is the canonical set of recognized event types.
var validEventTypes = map[string]struct{}{
	EventLedgerGenesis:          {},
	EventAuthorization:          {},
	EventRiskEvaluation:         {},
	EventRevocation:             {},
	EventTokenIssued:            {},
	EventExecutionTokenIssued:   {},
	EventExecutionTokenConsumed: {},
	EventAgentRegistered:        {},
	EventAgentStateChange:       {},
	EventEscalationCreated:      {},
	EventEscalationResolved:     {},
	EventLiabilityRecord:        {},
	EventPolicySnapshotCreated:  {},
	EventReputationUpdated:      {},
	EventProvenance:             {},
	EventPolicySnapshot:         {},
	EventGovernance:             {},
}

// ─── Structures ───────────────────────────────────────────────────────────────

// Event is a single ACP audit ledger event (ACP-LEDGER-1.0 §3).
//
// Immutability contract: once appended, fields MUST NOT be modified.
type Event struct {
	Ver           string      `json:"ver"`
	EventID       string      `json:"event_id"`
	EventType     string      `json:"event_type"`
	Sequence      int64       `json:"sequence"`
	Timestamp     int64       `json:"timestamp"`
	InstitutionID string      `json:"institution_id"`
	PrevHash      string      `json:"prev_hash"`
	Payload       interface{} `json:"payload"`
	Hash          string      `json:"hash"`
	Sig           string      `json:"sig,omitempty"`
}

// hashableEvent is the subset of Event fields covered by the hash (§4.3, §6).
// Excludes: hash, sig.
type hashableEvent struct {
	Ver           string      `json:"ver"`
	EventID       string      `json:"event_id"`
	EventType     string      `json:"event_type"`
	Sequence      int64       `json:"sequence"`
	Timestamp     int64       `json:"timestamp"`
	InstitutionID string      `json:"institution_id"`
	PrevHash      string      `json:"prev_hash"`
	Payload       interface{} `json:"payload"`
}

// signableEvent is the subset of Event fields covered by the institutional sig (§4.4).
// Includes hash (so sig transitively covers all fields); excludes sig itself.
type signableEvent struct {
	Ver           string      `json:"ver"`
	EventID       string      `json:"event_id"`
	EventType     string      `json:"event_type"`
	Sequence      int64       `json:"sequence"`
	Timestamp     int64       `json:"timestamp"`
	InstitutionID string      `json:"institution_id"`
	PrevHash      string      `json:"prev_hash"`
	Payload       interface{} `json:"payload"`
	Hash          string      `json:"hash"`
}

// VerificationError reports a specific problem found during chain verification (§7, §8).
type VerificationError struct {
	Code     string `json:"code"`
	EventID  string `json:"event_id,omitempty"`
	Sequence int64  `json:"sequence,omitempty"`
	Message  string `json:"message"`
}

// Error implements the error interface for VerificationError.
func (e VerificationError) Error() string {
	return fmt.Sprintf("%s [event_id=%s seq=%d]: %s", e.Code, e.EventID, e.Sequence, e.Message)
}

// ─── InMemoryLedger ────────────────────────────────────────────────────────────

// InMemoryLedger is an ACP-LEDGER-1.0 conformant, thread-safe, append-only ledger.
//
// Events are stored in a slice ordered by sequence number (1-indexed).
// An additional map provides O(1) lookup by event_id.
type InMemoryLedger struct {
	mu            sync.RWMutex
	events        []Event        // ordered by sequence (index 0 = sequence 1)
	byID          map[string]int // event_id → index in events slice
	institutionID string
	privKey       ed25519.PrivateKey // nil → dev mode (events stored unsigned)
}

// NewInMemoryLedger creates a new ledger and emits the mandatory LEDGER_GENESIS event.
//
// If privKey is non-nil, all events (including genesis) will be signed.
// If privKey is nil, events are stored unsigned (dev/test mode).
func NewInMemoryLedger(institutionID string, privKey ed25519.PrivateKey) (*InMemoryLedger, error) {
	l := &InMemoryLedger{
		institutionID: institutionID,
		privKey:       privKey,
		byID:          make(map[string]int),
	}
	genesisPayload := map[string]interface{}{
		"institution_id": institutionID,
		"acp_version":    Version,
		"created_at":     time.Now().Unix(),
		"created_by":     "system",
	}
	if _, err := l.appendInternal(EventLedgerGenesis, genesisPayload); err != nil {
		return nil, fmt.Errorf("ledger genesis: %w", err)
	}
	return l, nil
}

// Append adds a new event to the ledger. Thread-safe.
//
// Returns ErrUnknownEventType for unrecognized event types.
// Returns ErrModificationRejected if caller attempts to append LEDGER_GENESIS
// (genesis is emitted automatically by NewInMemoryLedger).
func (l *InMemoryLedger) Append(eventType string, payload interface{}) (Event, error) {
	if _, ok := validEventTypes[eventType]; !ok {
		return Event{}, fmt.Errorf("%w: %q", ErrUnknownEventType, eventType)
	}
	if eventType == EventLedgerGenesis {
		return Event{}, fmt.Errorf("%w: LEDGER_GENESIS may only be emitted at ledger creation", ErrModificationRejected)
	}
	return l.appendInternal(eventType, payload)
}

// appendInternal is the unsynchronised append used internally (genesis + public Append).
func (l *InMemoryLedger) appendInternal(eventType string, payload interface{}) (Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Determine prev_hash and sequence.
	var prevHash string
	var sequence int64
	if len(l.events) == 0 {
		// Genesis: use the spec-defined constant.
		prevHash = GenesisHash
		sequence = 1
	} else {
		last := l.events[len(l.events)-1]
		prevHash = last.Hash
		sequence = last.Sequence + 1
	}

	// Generate a UUID v4 for event_id.
	eventID, err := newUUID()
	if err != nil {
		return Event{}, fmt.Errorf("event_id generation: %w", err)
	}

	// Compute hash from hashable fields (§6).
	h := hashableEvent{
		Ver:           Version,
		EventID:       eventID,
		EventType:     eventType,
		Sequence:      sequence,
		Timestamp:     time.Now().Unix(),
		InstitutionID: l.institutionID,
		PrevHash:      prevHash,
		Payload:       payload,
	}
	hash, err := computeHashFromHashable(h)
	if err != nil {
		return Event{}, fmt.Errorf("hash computation: %w", err)
	}

	// Assemble full event.
	ev := Event{
		Ver:           h.Ver,
		EventID:       h.EventID,
		EventType:     h.EventType,
		Sequence:      h.Sequence,
		Timestamp:     h.Timestamp,
		InstitutionID: h.InstitutionID,
		PrevHash:      h.PrevHash,
		Payload:       h.Payload,
		Hash:          hash,
	}

	// Sign if private key is available (§4.4).
	if l.privKey != nil {
		sig, err := signEventFields(ev, l.privKey)
		if err != nil {
			return Event{}, fmt.Errorf("event signing: %w", err)
		}
		ev.Sig = sig
	}

	// Store immutably.
	idx := len(l.events)
	l.events = append(l.events, ev)
	l.byID[eventID] = idx

	return ev, nil
}

// ─── Query Methods ────────────────────────────────────────────────────────────

// Get returns the event with the given event_id.
// Returns false if not found.
func (l *InMemoryLedger) Get(eventID string) (Event, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	idx, ok := l.byID[eventID]
	if !ok {
		return Event{}, false
	}
	return l.events[idx], true
}

// GetBySequence returns the event at the given sequence number (1-based).
// Returns false if out of range.
func (l *InMemoryLedger) GetBySequence(seq int64) (Event, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if seq < 1 || int(seq) > len(l.events) {
		return Event{}, false
	}
	return l.events[seq-1], true
}

// List returns events with sequence in [fromSeq, toSeq] (inclusive, 1-based).
//
// fromSeq ≤ 0 is treated as 1 (beginning of ledger).
// toSeq ≤ 0 is treated as the last sequence in the ledger.
// Returns nil if the ledger is empty or fromSeq > toSeq.
func (l *InMemoryLedger) List(fromSeq, toSeq int64) []Event {
	l.mu.RLock()
	defer l.mu.RUnlock()
	n := int64(len(l.events))
	if n == 0 {
		return nil
	}
	if fromSeq <= 0 {
		fromSeq = 1
	}
	if toSeq <= 0 || toSeq > n {
		toSeq = n
	}
	if fromSeq > toSeq {
		return nil
	}
	// Sequences are 1-based; slice is 0-based.
	start := int(fromSeq - 1)
	end := int(toSeq)
	result := make([]Event, end-start)
	copy(result, l.events[start:end])
	return result
}

// Size returns the total number of events currently in the ledger.
func (l *InMemoryLedger) Size() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.events)
}

// ─── Verification ─────────────────────────────────────────────────────────────

// Verify performs a full chain verification (ACP-LEDGER-1.0 §7).
//
// Returns a slice of VerificationErrors; an empty slice means the chain is valid.
// Per §8, verification continues past the first error to identify full corruption scope.
func (l *InMemoryLedger) Verify() []VerificationError {
	l.mu.RLock()
	events := make([]Event, len(l.events))
	copy(events, l.events)
	pubKey := l.derivePubKey()
	l.mu.RUnlock()

	return verifyChain(events, pubKey)
}

// VerifyEvent verifies a single event by event_id and returns any errors found.
//
// The predecessor event is loaded automatically to check prev_hash and sequence.
// Returns LEDGER-007 if the event_id is not found.
func (l *InMemoryLedger) VerifyEvent(eventID string) (Event, []VerificationError) {
	l.mu.RLock()
	idx, ok := l.byID[eventID]
	if !ok {
		l.mu.RUnlock()
		return Event{}, []VerificationError{{
			Code:    "LEDGER-007",
			EventID: eventID,
			Message: "event not found",
		}}
	}
	ev := l.events[idx]
	var prev *Event
	if idx > 0 {
		p := l.events[idx-1]
		prev = &p
	}
	pubKey := l.derivePubKey()
	l.mu.RUnlock()

	return ev, verifySingleEvent(ev, prev, pubKey)
}

// derivePubKey extracts the Ed25519 public key from the stored private key, or returns nil.
func (l *InMemoryLedger) derivePubKey() ed25519.PublicKey {
	if l.privKey == nil {
		return nil
	}
	return l.privKey.Public().(ed25519.PublicKey)
}

// ─── Chain Verification Helpers ───────────────────────────────────────────────

// verifyChain verifies the full ordered event chain (§7 "Verificación completa").
func verifyChain(events []Event, pubKey ed25519.PublicKey) []VerificationError {
	var errs []VerificationError

	// Empty ledger → missing genesis.
	if len(events) == 0 {
		return []VerificationError{{
			Code:    "LEDGER-007",
			Message: "ledger is empty, genesis event missing",
		}}
	}

	// Genesis checks.
	genesis := events[0]
	if genesis.EventType != EventLedgerGenesis {
		errs = append(errs, VerificationError{
			Code:     "LEDGER-007",
			EventID:  genesis.EventID,
			Sequence: genesis.Sequence,
			Message:  fmt.Sprintf("first event type is %q, expected %q", genesis.EventType, EventLedgerGenesis),
		})
	}
	if genesis.PrevHash != GenesisHash {
		errs = append(errs, VerificationError{
			Code:     "LEDGER-004",
			EventID:  genesis.EventID,
			Sequence: genesis.Sequence,
			Message:  fmt.Sprintf("genesis prev_hash %q != constant %q", genesis.PrevHash, GenesisHash),
		})
	}

	// Per-event checks (§7 steps 1–6).
	for i, ev := range events {
		prev := prevEventOrNil(events, i)
		evErrs := verifySingleEvent(ev, prev, pubKey)
		errs = append(errs, evErrs...)
	}

	return errs
}

func prevEventOrNil(events []Event, i int) *Event {
	if i == 0 {
		return nil
	}
	p := events[i-1]
	return &p
}

// verifySingleEvent verifies one event according to §7 steps 1–6.
//
// Steps 3–6 (chain linkage) are only checked when prev is non-nil.
func verifySingleEvent(ev Event, prev *Event, pubKey ed25519.PublicKey) []VerificationError {
	var errs []VerificationError

	// Step 0a: Verify event_type is in the registered set (LEDGER-008).
	if _, known := validEventTypes[ev.EventType]; !known {
		errs = append(errs, VerificationError{
			Code: "LEDGER-008", EventID: ev.EventID, Sequence: ev.Sequence,
			Message: fmt.Sprintf("unrecognized event_type %q", ev.EventType),
		})
	}

	// Step 0b: Verify payload completeness for typed events (LEDGER-010, LEDGER-011).
	if ev.EventType == EventAuthorization || ev.EventType == EventRiskEvaluation {
		raw, _ := json.Marshal(ev.Payload)
		var m map[string]interface{}
		if json.Unmarshal(raw, &m) == nil {
			if _, ok := m["policy_snapshot_ref"]; !ok {
				code := "LEDGER-010"
				if ev.EventType == EventRiskEvaluation {
					code = "LEDGER-011"
				}
				errs = append(errs, VerificationError{
					Code: code, EventID: ev.EventID, Sequence: ev.Sequence,
					Message: fmt.Sprintf("%s payload missing required field policy_snapshot_ref", ev.EventType),
				})
			}
		}
	}

	// Step 1a: Check sig presence (LEDGER-012). Per §4.4, sig MUST be non-empty in production.
	if pubKey != nil && ev.Sig == "" {
		errs = append(errs, VerificationError{
			Code: "LEDGER-012", EventID: ev.EventID, Sequence: ev.Sequence,
			Message: "sig field missing or empty (MUST per ACP-LEDGER-1.3 §4.4)",
		})
	}

	// Step 1b: Verify institutional signature value (LEDGER-002).
	if pubKey != nil && ev.Sig != "" {
		if err := verifyEventSig(ev, pubKey); err != nil {
			errs = append(errs, VerificationError{
				Code: "LEDGER-002", EventID: ev.EventID, Sequence: ev.Sequence,
				Message: "institutional signature verification failed",
			})
		}
	}

	// Step 2: Recompute hash and compare to stored hash.
	computed, err := computeHashFromEvent(ev)
	if err != nil {
		errs = append(errs, VerificationError{
			Code: "LEDGER-003", EventID: ev.EventID, Sequence: ev.Sequence,
			Message: fmt.Sprintf("hash computation error: %v", err),
		})
	} else if computed != ev.Hash {
		errs = append(errs, VerificationError{
			Code: "LEDGER-003", EventID: ev.EventID, Sequence: ev.Sequence,
			Message: fmt.Sprintf("computed %q != stored %q", computed, ev.Hash),
		})
	}

	// Steps 3–6: chain linkage (requires predecessor).
	if prev != nil {
		// Step 3: prev_hash must equal predecessor's hash.
		if ev.PrevHash != prev.Hash {
			errs = append(errs, VerificationError{
				Code: "LEDGER-004", EventID: ev.EventID, Sequence: ev.Sequence,
				Message: fmt.Sprintf("prev_hash %q != predecessor hash %q", ev.PrevHash, prev.Hash),
			})
		}
		// Step 4: sequence must be predecessor + 1.
		if ev.Sequence != prev.Sequence+1 {
			errs = append(errs, VerificationError{
				Code: "LEDGER-005", EventID: ev.EventID, Sequence: ev.Sequence,
				Message: fmt.Sprintf("sequence %d != prev_sequence %d +1", ev.Sequence, prev.Sequence),
			})
		}
		// Step 5: timestamp must be non-regressing.
		if ev.Timestamp < prev.Timestamp {
			errs = append(errs, VerificationError{
				Code: "LEDGER-006", EventID: ev.EventID, Sequence: ev.Sequence,
				Message: fmt.Sprintf("timestamp %d < prev_timestamp %d", ev.Timestamp, prev.Timestamp),
			})
		}
	}

	return errs
}

// ─── Crypto Helpers ───────────────────────────────────────────────────────────

// computeHashFromHashable computes hash = base64url(SHA-256(JCS(h))) for a hashableEvent.
// Uses URLEncoding (with padding) to produce results compatible with GenesisHash (§4.2).
func computeHashFromHashable(h hashableEvent) (string, error) {
	raw, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("jcs: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return base64.URLEncoding.EncodeToString(sum[:]), nil
}

// computeHashFromEvent recomputes the hash for an existing Event (for verification).
func computeHashFromEvent(ev Event) (string, error) {
	return computeHashFromHashable(hashableEvent{
		Ver:           ev.Ver,
		EventID:       ev.EventID,
		EventType:     ev.EventType,
		Sequence:      ev.Sequence,
		Timestamp:     ev.Timestamp,
		InstitutionID: ev.InstitutionID,
		PrevHash:      ev.PrevHash,
		Payload:       ev.Payload,
	})
}

// signEventFields signs all event fields except sig: Ed25519(SHA-256(JCS(signableEvent))).
// Signature is returned as RawURLEncoding (no padding), consistent with ACP signing conventions.
func signEventFields(ev Event, privKey ed25519.PrivateKey) (string, error) {
	se := signableEvent{
		Ver:           ev.Ver,
		EventID:       ev.EventID,
		EventType:     ev.EventType,
		Sequence:      ev.Sequence,
		Timestamp:     ev.Timestamp,
		InstitutionID: ev.InstitutionID,
		PrevHash:      ev.PrevHash,
		Payload:       ev.Payload,
		Hash:          ev.Hash,
	}
	raw, err := json.Marshal(se)
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

// verifyEventSig verifies an event's institutional signature.
func verifyEventSig(ev Event, pubKey ed25519.PublicKey) error {
	sigBytes, err := base64.RawURLEncoding.DecodeString(ev.Sig)
	if err != nil {
		return fmt.Errorf("decode sig: %w", err)
	}
	se := signableEvent{
		Ver:           ev.Ver,
		EventID:       ev.EventID,
		EventType:     ev.EventType,
		Sequence:      ev.Sequence,
		Timestamp:     ev.Timestamp,
		InstitutionID: ev.InstitutionID,
		PrevHash:      ev.PrevHash,
		Payload:       ev.Payload,
		Hash:          ev.Hash,
	}
	raw, err := json.Marshal(se)
	if err != nil {
		return err
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	if !ed25519.Verify(pubKey, digest[:], sigBytes) {
		return ErrInvalidSignature
	}
	return nil
}

// ─── UUID helper ──────────────────────────────────────────────────────────────

// newUUID generates a random UUID v4.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
