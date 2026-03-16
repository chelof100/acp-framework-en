// Package psn implements ACP-PSN-1.0 (Policy Snapshot).
//
// A PolicySnapshot is an immutable, signed record of the complete state of the
// risk policy at a specific instant. It solves the "policy drift" problem:
// given a policy_snapshot_ref from any AUTHORIZATION or LIABILITY_RECORD event,
// any actor can exactly replicate the risk calculation that was performed at
// execution time — regardless of policy changes made afterwards.
//
// Key invariants:
//   - Exactly one ACTIVE snapshot at all times (effective_until: null).
//   - Atomic transition: a new snapshot is activated and the previous is
//     superseded in a single operation (§7).
//   - Immutable: once created and signed, a snapshot cannot be modified.
//
// Required for L3-FULL conformance (ACP-CONF-1.2).
package psn

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

// ─── Error Sentinels (ACP-PSN-1.0 §12) ───────────────────────────────────────

var (
	ErrSnapshotNotFound      = errors.New("PSN-001: snapshot not found for the given ID")
	ErrInvalidSig            = errors.New("PSN-002: invalid signature — snapshot has been altered or key mismatch")
	ErrUnsupportedVersion    = errors.New("PSN-003: schema version (ver) not supported by this implementation")
	ErrTransitionInProgress  = errors.New("PSN-004: snapshot transition in progress — concurrent create rejected")
	ErrNoActiveSnapshot      = errors.New("PSN-005: no active snapshot exists — invalid system state")
	ErrInvalidThresholds     = errors.New("PSN-006: invalid thresholds — values out of range or incorrect structure")
	ErrRequiredField         = errors.New("PSN-007: required field missing")
)

// ─── Types (ACP-PSN-1.0 §4) ───────────────────────────────────────────────────

// ThresholdBand defines approved_max and escalated_max risk scores for one level.
// -1 means the level cannot execute any action.
type ThresholdBand struct {
	ApprovedMax  int `json:"approved_max"`
	EscalatedMax int `json:"escalated_max"`
}

// Thresholds holds global and per-autonomy-level risk score thresholds (§5.7).
type Thresholds struct {
	Default        ThresholdBand        `json:"default"`
	ByAutonomyLevel map[string]ThresholdBand `json:"by_autonomy_level,omitempty"`
}

// PolicySnapshot is the top-level immutable policy record (§4).
// The Sig field covers all other fields via Ed25519(SHA-256(JCS(signable))).
type PolicySnapshot struct {
	Ver                string                 `json:"ver"`
	SnapshotID         string                 `json:"snapshot_id"`
	InstitutionID      string                 `json:"institution_id"`
	PolicyVersion      string                 `json:"policy_version"`
	EffectiveFrom      int64                  `json:"effective_from"`
	EffectiveUntil     *int64                 `json:"effective_until"` // null = ACTIVE
	Thresholds         Thresholds             `json:"thresholds"`
	CapabilityBaselines map[string]int        `json:"capability_baselines,omitempty"`
	ContextFactors     map[string]int         `json:"context_factors,omitempty"`
	ResourceFactors    map[string]int         `json:"resource_factors,omitempty"`
	CustomFactors      map[string]int         `json:"custom_factors,omitempty"`
	CreatedAt          int64                  `json:"created_at"`
	CreatedBy          string                 `json:"created_by"`
	Sig                string                 `json:"sig"`
}

// Status returns "ACTIVE" or "SUPERSEDED" depending on EffectiveUntil.
func (s PolicySnapshot) Status() string {
	if s.EffectiveUntil == nil {
		return "ACTIVE"
	}
	return "SUPERSEDED"
}

// IsActiveAt returns true if the snapshot covers the given Unix timestamp.
func (s PolicySnapshot) IsActiveAt(ts int64) bool {
	if ts < s.EffectiveFrom {
		return false
	}
	if s.EffectiveUntil != nil && ts >= *s.EffectiveUntil {
		return false
	}
	return true
}

// CreateRequest is the input for creating the first (bootstrap) snapshot.
type CreateRequest struct {
	InstitutionID       string
	PolicyVersion       string
	Thresholds          Thresholds
	CapabilityBaselines map[string]int
	ContextFactors      map[string]int
	ResourceFactors     map[string]int
	CustomFactors       map[string]int
	CreatedBy           string
}

// TransitionRequest is the input for activating a new snapshot (§7).
type TransitionRequest struct {
	PolicyVersion       string
	Thresholds          Thresholds
	CapabilityBaselines map[string]int
	ContextFactors      map[string]int
	ResourceFactors     map[string]int
	CustomFactors       map[string]int
	CreatedBy           string
}

// TransitionResult is returned by Transition.
type TransitionResult struct {
	NewSnapshot        PolicySnapshot
	SupersededSnapshot PolicySnapshot // previous ACTIVE, now with EffectiveUntil set
}

// signableSnapshot excludes Sig from the signing input (sig set to "").
type signableSnapshot struct {
	Ver                 string                 `json:"ver"`
	SnapshotID          string                 `json:"snapshot_id"`
	InstitutionID       string                 `json:"institution_id"`
	PolicyVersion       string                 `json:"policy_version"`
	EffectiveFrom       int64                  `json:"effective_from"`
	EffectiveUntil      *int64                 `json:"effective_until"`
	Thresholds          Thresholds             `json:"thresholds"`
	CapabilityBaselines map[string]int         `json:"capability_baselines,omitempty"`
	ContextFactors      map[string]int         `json:"context_factors,omitempty"`
	ResourceFactors     map[string]int         `json:"resource_factors,omitempty"`
	CustomFactors       map[string]int         `json:"custom_factors,omitempty"`
	CreatedAt           int64                  `json:"created_at"`
	CreatedBy           string                 `json:"created_by"`
	Sig                 string                 `json:"sig"` // always "" when signing
}

// ─── Create (bootstrap) ───────────────────────────────────────────────────────

// Create creates the first PolicySnapshot for an institution (bootstrap).
//
// Use Transition to replace an existing active snapshot (§7).
// privKey may be nil (dev mode — sig field will be empty).
func Create(req CreateRequest, privKey ed25519.PrivateKey) (PolicySnapshot, error) {
	if req.InstitutionID == "" {
		return PolicySnapshot{}, fmt.Errorf("%w: institution_id", ErrRequiredField)
	}
	if req.PolicyVersion == "" {
		return PolicySnapshot{}, fmt.Errorf("%w: policy_version", ErrRequiredField)
	}
	if err := validateThresholds(req.Thresholds); err != nil {
		return PolicySnapshot{}, err
	}

	now := time.Now().Unix()
	id, err := newUUID()
	if err != nil {
		return PolicySnapshot{}, fmt.Errorf("psn: generate id: %w", err)
	}

	snap := PolicySnapshot{
		Ver:                 "1.0",
		SnapshotID:          id,
		InstitutionID:       req.InstitutionID,
		PolicyVersion:       req.PolicyVersion,
		EffectiveFrom:       now,
		EffectiveUntil:      nil,
		Thresholds:          req.Thresholds,
		CapabilityBaselines: req.CapabilityBaselines,
		ContextFactors:      req.ContextFactors,
		ResourceFactors:     req.ResourceFactors,
		CustomFactors:       req.CustomFactors,
		CreatedAt:           now,
		CreatedBy:           req.CreatedBy,
	}

	if privKey != nil {
		sig, err := signSnapshot(snap, privKey)
		if err != nil {
			return PolicySnapshot{}, fmt.Errorf("psn: sign: %w", err)
		}
		snap.Sig = sig
	}
	return snap, nil
}

// ─── Transition ───────────────────────────────────────────────────────────────

// Transition atomically supersedes the current active snapshot and activates a
// new one (ACP-PSN-1.0 §7). Thread-safe when called on an InMemorySnapshotStore.
//
// Returns ErrNoActiveSnapshot if no active snapshot exists.
// privKey may be nil (dev mode).
func Transition(store *InMemorySnapshotStore, req TransitionRequest, privKey ed25519.PrivateKey) (TransitionResult, error) {
	if err := validateThresholds(req.Thresholds); err != nil {
		return TransitionResult{}, err
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if store.activeID == "" {
		return TransitionResult{}, ErrNoActiveSnapshot
	}

	prev := store.objects[store.activeID]
	now := time.Now().Unix()

	// New snapshot.
	newID, err := newUUID()
	if err != nil {
		return TransitionResult{}, fmt.Errorf("psn: generate id: %w", err)
	}
	newSnap := PolicySnapshot{
		Ver:                 "1.0",
		SnapshotID:          newID,
		InstitutionID:       prev.InstitutionID,
		PolicyVersion:       req.PolicyVersion,
		EffectiveFrom:       now,
		EffectiveUntil:      nil,
		Thresholds:          req.Thresholds,
		CapabilityBaselines: req.CapabilityBaselines,
		ContextFactors:      req.ContextFactors,
		ResourceFactors:     req.ResourceFactors,
		CustomFactors:       req.CustomFactors,
		CreatedAt:           now,
		CreatedBy:           req.CreatedBy,
	}
	if privKey != nil {
		sig, err := signSnapshot(newSnap, privKey)
		if err != nil {
			return TransitionResult{}, fmt.Errorf("psn: sign new: %w", err)
		}
		newSnap.Sig = sig
	}

	// Supersede previous: set effective_until = new effective_from (§7.4).
	superseded := prev
	superseded.EffectiveUntil = &now
	// Re-sign superseded snapshot with updated effective_until.
	if privKey != nil {
		sig, err := signSnapshot(superseded, privKey)
		if err != nil {
			return TransitionResult{}, fmt.Errorf("psn: sign superseded: %w", err)
		}
		superseded.Sig = sig
	}

	// Atomic commit: update prev, store new, update activeID.
	store.objects[superseded.SnapshotID] = superseded
	store.objects[newSnap.SnapshotID] = newSnap
	store.activeID = newSnap.SnapshotID

	return TransitionResult{NewSnapshot: newSnap, SupersededSnapshot: superseded}, nil
}

// ─── Verification ─────────────────────────────────────────────────────────────

// VerifySig verifies the institutional signature on a PolicySnapshot (§3.5, §10.2).
func VerifySig(snap PolicySnapshot, pubKey ed25519.PublicKey) error {
	if snap.Ver != "1.0" {
		return ErrUnsupportedVersion
	}
	if snap.Sig == "" {
		return fmt.Errorf("%w: sig is empty", ErrInvalidSig)
	}
	s := signableSnapshot{
		Ver:                 snap.Ver,
		SnapshotID:          snap.SnapshotID,
		InstitutionID:       snap.InstitutionID,
		PolicyVersion:       snap.PolicyVersion,
		EffectiveFrom:       snap.EffectiveFrom,
		EffectiveUntil:      snap.EffectiveUntil,
		Thresholds:          snap.Thresholds,
		CapabilityBaselines: snap.CapabilityBaselines,
		ContextFactors:      snap.ContextFactors,
		ResourceFactors:     snap.ResourceFactors,
		CustomFactors:       snap.CustomFactors,
		CreatedAt:           snap.CreatedAt,
		CreatedBy:           snap.CreatedBy,
		Sig:                 "",
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("psn: marshal signable: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return fmt.Errorf("psn: jcs: %w", err)
	}
	digest := sha256.Sum256(canonical)
	sigBytes, err := base64.RawURLEncoding.DecodeString(snap.Sig)
	if err != nil {
		return fmt.Errorf("%w: decode sig: %v", ErrInvalidSig, err)
	}
	if !ed25519.Verify(pubKey, digest[:], sigBytes) {
		return ErrInvalidSig
	}
	return nil
}

// ─── In-memory Store ──────────────────────────────────────────────────────────

// InMemorySnapshotStore is a thread-safe store for PolicySnapshot objects.
//
// Invariant: exactly one snapshot with Status()=="ACTIVE" at all times
// (after the first snapshot is activated).
type InMemorySnapshotStore struct {
	mu       sync.RWMutex
	objects  map[string]PolicySnapshot // keyed by snapshot_id
	activeID string                    // ID of the current ACTIVE snapshot (or "")
}

// NewInMemorySnapshotStore returns an empty store.
func NewInMemorySnapshotStore() *InMemorySnapshotStore {
	return &InMemorySnapshotStore{objects: make(map[string]PolicySnapshot)}
}

// Activate stores a snapshot and marks it as the active one.
// Use this to bootstrap the store with the first snapshot (created via Create).
// Returns ErrSnapshotNotFound if the snapshot_id is already known (idempotent guard).
func (s *InMemorySnapshotStore) Activate(snap PolicySnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.objects[snap.SnapshotID]; exists {
		return fmt.Errorf("psn: %s already stored", snap.SnapshotID)
	}
	s.objects[snap.SnapshotID] = snap
	s.activeID = snap.SnapshotID
	return nil
}

// GetActive returns the current ACTIVE snapshot.
// Returns ErrNoActiveSnapshot if the store has not been bootstrapped.
func (s *InMemorySnapshotStore) GetActive() (PolicySnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.activeID == "" {
		return PolicySnapshot{}, ErrNoActiveSnapshot
	}
	return s.objects[s.activeID], nil
}

// Get retrieves a snapshot by ID (includes SUPERSEDED).
func (s *InMemorySnapshotStore) Get(snapshotID string) (PolicySnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snap, ok := s.objects[snapshotID]
	return snap, ok
}

// GetAtTime returns the snapshot that was ACTIVE at the given Unix timestamp.
// Returns ErrNoActiveSnapshot if no snapshot covers that time.
func (s *InMemorySnapshotStore) GetAtTime(ts int64) (PolicySnapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, snap := range s.objects {
		if snap.IsActiveAt(ts) {
			return snap, nil
		}
	}
	return PolicySnapshot{}, ErrNoActiveSnapshot
}

// ListRange returns snapshots whose effective range overlaps [from, to].
// If includeSuperseded is false, only ACTIVE snapshots are returned.
func (s *InMemorySnapshotStore) ListRange(from, to int64, includeSuperseded bool) []PolicySnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []PolicySnapshot
	for _, snap := range s.objects {
		if !includeSuperseded && snap.Status() == "SUPERSEDED" {
			continue
		}
		// Overlap: snap starts before to AND (snap has no end OR snap ends after from).
		if snap.EffectiveFrom < to && (snap.EffectiveUntil == nil || *snap.EffectiveUntil > from) {
			result = append(result, snap)
		}
	}
	return result
}

// Size returns the total number of stored snapshots (ACTIVE + SUPERSEDED).
func (s *InMemorySnapshotStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.objects)
}

// ─── Signing helper ───────────────────────────────────────────────────────────

func signSnapshot(snap PolicySnapshot, privKey ed25519.PrivateKey) (string, error) {
	s := signableSnapshot{
		Ver:                 snap.Ver,
		SnapshotID:          snap.SnapshotID,
		InstitutionID:       snap.InstitutionID,
		PolicyVersion:       snap.PolicyVersion,
		EffectiveFrom:       snap.EffectiveFrom,
		EffectiveUntil:      snap.EffectiveUntil,
		Thresholds:          snap.Thresholds,
		CapabilityBaselines: snap.CapabilityBaselines,
		ContextFactors:      snap.ContextFactors,
		ResourceFactors:     snap.ResourceFactors,
		CustomFactors:       snap.CustomFactors,
		CreatedAt:           snap.CreatedAt,
		CreatedBy:           snap.CreatedBy,
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

// ─── Threshold validation ─────────────────────────────────────────────────────

// validateThresholds checks that threshold values are non-negative or -1 (blocked).
func validateThresholds(t Thresholds) error {
	if err := validateBand("default", t.Default); err != nil {
		return err
	}
	for level, band := range t.ByAutonomyLevel {
		if err := validateBand("by_autonomy_level."+level, band); err != nil {
			return err
		}
	}
	return nil
}

func validateBand(name string, b ThresholdBand) error {
	// -1 = blocked level (valid); 0-100 = normal range.
	if b.ApprovedMax < -1 || b.ApprovedMax > 100 {
		return fmt.Errorf("%w: %s.approved_max=%d out of range [-1,100]", ErrInvalidThresholds, name, b.ApprovedMax)
	}
	if b.EscalatedMax < -1 || b.EscalatedMax > 100 {
		return fmt.Errorf("%w: %s.escalated_max=%d out of range [-1,100]", ErrInvalidThresholds, name, b.EscalatedMax)
	}
	return nil
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
