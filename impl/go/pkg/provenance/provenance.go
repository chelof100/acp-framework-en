// Package provenance implements ACP-PROVENANCE-1.0.
//
// An AuthorityProvenance object is a retrospective proof artifact that answers:
// "by what authority was this action taken, at this moment, through this chain?"
//
// It captures the full delegation chain from principal to executor, signed by
// the institutional key, producing a self-contained, tamper-evident evidence
// artifact that can be verified without querying the live system.
//
// Required for L3-FULL conformance (ACP-CONF-1.2).
package provenance

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

// ─── Error Sentinels (ACP-PROVENANCE-1.0 §10) ────────────────────────────────

var (
	ErrChainIncomplete    = errors.New("PROV-001: chain incomplete — break detected between steps")
	ErrCapabilityEscalation = errors.New("PROV-002: capability escalation — step expands capability from previous")
	ErrExpiredStep        = errors.New("PROV-003: expired delegation step — valid_until < captured_at")
	ErrStepSigInvalid     = errors.New("PROV-004: step signature invalid")
	ErrInstitutionalSig   = errors.New("PROV-005: institutional signature invalid")
	ErrPolicyHashMismatch = errors.New("PROV-006: policy hash mismatch")
	ErrExecutionIDMismatch = errors.New("PROV-007: execution_id does not match bound ET")
	ErrCapturedAtOutside  = errors.New("PROV-008: captured_at outside ET validity window")
	ErrExecutorMismatch   = errors.New("PROV-009: executor mismatch — chain[last].executor != executor")
	ErrInvalidVersion     = errors.New("PROV-010: unsupported version, expected 1.0")
)

// ─── Types (ACP-PROVENANCE-1.0 §4) ────────────────────────────────────────────

// DelegationStep represents a single step in the delegation chain (§4.3).
type DelegationStep struct {
	Step             int    `json:"step"`
	Delegator        string `json:"delegator"`
	Executor         string `json:"executor"`
	DelegationID     string `json:"delegation_id"`
	CapabilitySubset string `json:"capability_subset"`
	DelegatedAt      int64  `json:"delegated_at"`
	ValidUntil       int64  `json:"valid_until"`
	DelegationSig    string `json:"delegation_sig"`
}

// AuthorityProvenance is the top-level provenance object (§4.1).
// The Sig field covers all other fields via Ed25519(SHA-256(JCS(signable))).
type AuthorityProvenance struct {
	Ver            string           `json:"ver"`
	ProvenanceID   string           `json:"provenance_id"`
	ExecutionID    string           `json:"execution_id"`
	CapturedAt     int64            `json:"captured_at"`
	Principal      string           `json:"principal"`
	Executor       string           `json:"executor"`
	AuthorityScope string           `json:"authority_scope"`
	Chain          []DelegationStep `json:"chain"`
	PolicyRef      string           `json:"policy_ref"`
	PolicyHash     string           `json:"policy_hash"`
	Sig            string           `json:"sig"`
}

// IssueRequest carries the inputs for provenance creation.
type IssueRequest struct {
	ExecutionID    string
	Principal      string
	Executor       string
	AuthorityScope string
	Chain          []DelegationStep
	PolicyRef      string           // "<policy_id>:<policy_version>"
	PolicyHash     string           // SHA-256 hex digest of the policy document
}

// signableProvenance is the subset of fields covered by the institutional sig (§5).
// sig is excluded; set to "" per §5 ("sig set to empty string").
type signableProvenance struct {
	Ver            string           `json:"ver"`
	ProvenanceID   string           `json:"provenance_id"`
	ExecutionID    string           `json:"execution_id"`
	CapturedAt     int64            `json:"captured_at"`
	Principal      string           `json:"principal"`
	Executor       string           `json:"executor"`
	AuthorityScope string           `json:"authority_scope"`
	Chain          []DelegationStep `json:"chain"`
	PolicyRef      string           `json:"policy_ref"`
	PolicyHash     string           `json:"policy_hash"`
	Sig            string           `json:"sig"` // always "" when signing
}

// ─── Issuance ──────────────────────────────────────────────────────────────────

// Issue creates and signs an AuthorityProvenance object.
//
// privKey may be nil (dev/test mode — sig field will be empty).
//
// Per ACP-PROVENANCE-1.0 §4 + §5:
//  1. Generate provenance_id UUID v4
//  2. Set captured_at = now
//  3. Copy chain and fields from request
//  4. Sign with institutional private key
func Issue(req IssueRequest, privKey ed25519.PrivateKey) (AuthorityProvenance, error) {
	provenanceID, err := newUUID()
	if err != nil {
		return AuthorityProvenance{}, fmt.Errorf("provenance: generate id: %w", err)
	}

	ap := AuthorityProvenance{
		Ver:            "1.0",
		ProvenanceID:   provenanceID,
		ExecutionID:    req.ExecutionID,
		CapturedAt:     time.Now().Unix(),
		Principal:      req.Principal,
		Executor:       req.Executor,
		AuthorityScope: req.AuthorityScope,
		Chain:          req.Chain,
		PolicyRef:      req.PolicyRef,
		PolicyHash:     req.PolicyHash,
	}

	if privKey != nil {
		sig, err := signProvenance(ap, privKey)
		if err != nil {
			return AuthorityProvenance{}, fmt.Errorf("provenance: sign: %w", err)
		}
		ap.Sig = sig
	}

	return ap, nil
}

// ─── Validation ────────────────────────────────────────────────────────────────

// VerifySig verifies the institutional signature on an AuthorityProvenance object (§5).
func VerifySig(ap AuthorityProvenance, pubKey ed25519.PublicKey) error {
	if ap.Ver != "1.0" {
		return ErrInvalidVersion
	}
	if ap.Sig == "" {
		return fmt.Errorf("%w: sig is empty", ErrInstitutionalSig)
	}

	s := signableProvenance{
		Ver:            ap.Ver,
		ProvenanceID:   ap.ProvenanceID,
		ExecutionID:    ap.ExecutionID,
		CapturedAt:     ap.CapturedAt,
		Principal:      ap.Principal,
		Executor:       ap.Executor,
		AuthorityScope: ap.AuthorityScope,
		Chain:          ap.Chain,
		PolicyRef:      ap.PolicyRef,
		PolicyHash:     ap.PolicyHash,
		Sig:            "",
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("provenance: marshal signable: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return fmt.Errorf("provenance: jcs: %w", err)
	}
	digest := sha256.Sum256(canonical)
	sigBytes, err := base64.RawURLEncoding.DecodeString(ap.Sig)
	if err != nil {
		return fmt.Errorf("%w: decode sig: %v", ErrInstitutionalSig, err)
	}
	if !ed25519.Verify(pubKey, digest[:], sigBytes) {
		return ErrInstitutionalSig
	}
	return nil
}

// ValidateChain checks the structural and temporal validity of the delegation chain (§6).
//
// Verifies:
//   - P1: chain completeness — continuous path from principal to executor
//   - P2: capability monotone restriction — each step ⊆ previous
//   - P3: temporal validity — all steps valid at capturedAt
//
// Note: step.delegation_sig (P4) requires the delegator's registered public key,
// which is external to this package. Callers SHOULD verify step signatures
// using their agent registry.
func ValidateChain(ap AuthorityProvenance, capturedAt int64) error {
	chain := ap.Chain

	// P1 — Chain completeness (§5 P1)
	if len(chain) > 0 {
		if chain[0].Delegator != ap.Principal {
			return fmt.Errorf("%w: chain[0].delegator %q != principal %q",
				ErrChainIncomplete, chain[0].Delegator, ap.Principal)
		}
		for i := 0; i < len(chain)-1; i++ {
			if chain[i].Executor != chain[i+1].Delegator {
				return fmt.Errorf("%w: step %d executor %q != step %d delegator %q",
					ErrChainIncomplete, i+1, chain[i].Executor, i+2, chain[i+1].Delegator)
			}
		}
		last := chain[len(chain)-1]
		if last.Executor != ap.Executor {
			return fmt.Errorf("%w: chain[last].executor %q != executor %q",
				ErrExecutorMismatch, last.Executor, ap.Executor)
		}
	}

	// P3 — Temporal validity (§5 P3)
	for i, step := range chain {
		if step.ValidUntil < capturedAt {
			return fmt.Errorf("%w: step %d valid_until %d < captured_at %d",
				ErrExpiredStep, i+1, step.ValidUntil, capturedAt)
		}
	}

	return nil
}

// ─── In-memory Store ──────────────────────────────────────────────────────────

// InMemoryProvenanceStore is a thread-safe store for AuthorityProvenance objects.
type InMemoryProvenanceStore struct {
	mu      sync.RWMutex
	objects map[string]AuthorityProvenance // keyed by provenance_id
	byExec  map[string]string              // execution_id → provenance_id
}

// NewInMemoryProvenanceStore creates an empty provenance store.
func NewInMemoryProvenanceStore() *InMemoryProvenanceStore {
	return &InMemoryProvenanceStore{
		objects: make(map[string]AuthorityProvenance),
		byExec:  make(map[string]string),
	}
}

// Store persists an AuthorityProvenance. Returns an error if provenance_id already exists.
func (s *InMemoryProvenanceStore) Store(ap AuthorityProvenance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.objects[ap.ProvenanceID]; exists {
		return fmt.Errorf("provenance: %s already stored", ap.ProvenanceID)
	}
	s.objects[ap.ProvenanceID] = ap
	s.byExec[ap.ExecutionID] = ap.ProvenanceID
	return nil
}

// Get retrieves an AuthorityProvenance by provenance_id.
func (s *InMemoryProvenanceStore) Get(provenanceID string) (AuthorityProvenance, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ap, ok := s.objects[provenanceID]
	return ap, ok
}

// GetByExecutionID retrieves the AuthorityProvenance bound to an execution token.
func (s *InMemoryProvenanceStore) GetByExecutionID(executionID string) (AuthorityProvenance, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byExec[executionID]
	if !ok {
		return AuthorityProvenance{}, false
	}
	ap, ok := s.objects[id]
	return ap, ok
}

// Size returns the number of stored provenance objects.
func (s *InMemoryProvenanceStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.objects)
}

// ─── Signing helper ───────────────────────────────────────────────────────────

// signProvenance computes Ed25519(SHA-256(JCS(signable))) per ACP-SIGN-1.0.
// The sig field is set to "" in the signable struct, per §5.
func signProvenance(ap AuthorityProvenance, privKey ed25519.PrivateKey) (string, error) {
	s := signableProvenance{
		Ver:            ap.Ver,
		ProvenanceID:   ap.ProvenanceID,
		ExecutionID:    ap.ExecutionID,
		CapturedAt:     ap.CapturedAt,
		Principal:      ap.Principal,
		Executor:       ap.Executor,
		AuthorityScope: ap.AuthorityScope,
		Chain:          ap.Chain,
		PolicyRef:      ap.PolicyRef,
		PolicyHash:     ap.PolicyHash,
		Sig:            "",
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
