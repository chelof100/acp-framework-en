// Package policyctx implements ACP-POLICY-CTX-1.0.
//
// A PolicyContextSnapshot is a point-in-time evidence artifact that preserves
// the exact policy state in force at the moment an agent action was authorized.
// This enables deterministic retrospective policy reconstruction — a verifier
// can confirm that the action was policy-compliant when it occurred, even if the
// policy has since changed.
//
// Required for L3-FULL conformance (ACP-CONF-1.2).
package policyctx

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

// ─── Error Sentinels (ACP-POLICY-CTX-1.0 §9) ─────────────────────────────────

var (
	ErrExecutionIDMismatch = errors.New("PCTX-001: execution_id does not match bound ET")
	ErrSnapshotAtOutside   = errors.New("PCTX-002: snapshot_at outside ET validity window")
	ErrPolicyNotFound      = errors.New("PCTX-003: policy document not found in policy store")
	ErrPolicyHashMismatch  = errors.New("PCTX-004: policy hash mismatch")
	ErrDecisionMismatch    = errors.New("PCTX-005: policy re-evaluation disagrees with captured decision")
	ErrInstitutionalSig    = errors.New("PCTX-006: institutional signature invalid")
	ErrRequiredField       = errors.New("PCTX-007: required field missing")
	ErrNoETForApproval     = errors.New("PCTX-008: decision APPROVED but no bound ET found")
	ErrInvalidVersion      = errors.New("PCTX-010: unsupported version, expected 1.0")
)

// ─── Types (ACP-POLICY-CTX-1.0 §4) ───────────────────────────────────────────

// PolicyBlock identifies the policy document in force at snapshot time (§4.3).
type PolicyBlock struct {
	PolicyID      string `json:"policy_id"`
	PolicyVersion string `json:"policy_version"`
	PolicyHash    string `json:"policy_hash"`
	PolicyEngine  string `json:"policy_engine,omitempty"`
}

// EvaluationContext contains the inputs fed to the policy engine (§4.4).
type EvaluationContext struct {
	AgentID              string                 `json:"agent_id"`
	RequestedCapability  string                 `json:"requested_capability"`
	Resource             string                 `json:"resource"`
	RiskScore            *float64               `json:"risk_score"`
	DelegationActive     bool                   `json:"delegation_active"`
	AdditionalParams     map[string]interface{} `json:"additional_params,omitempty"`
}

// EvaluationCheck records one step of the policy evaluation (§4.6).
type EvaluationCheck struct {
	CheckName string `json:"check_name"`
	Result    string `json:"result"` // "passed" | "failed" | "skipped"
	Value     string `json:"value,omitempty"`
}

// EvaluationResult holds the output of the policy evaluation (§4.5).
type EvaluationResult struct {
	Decision     string            `json:"decision"` // "APPROVED" | "DENIED" | "ESCALATED"
	Checks       []EvaluationCheck `json:"checks"`
	DenialReason *string           `json:"denial_reason"`
}

// PolicyContextSnapshot is the top-level snapshot object (§4.1).
// The Sig field covers all other fields via Ed25519(SHA-256(JCS(signable))).
type PolicyContextSnapshot struct {
	Ver               string            `json:"ver"`
	SnapshotID        string            `json:"snapshot_id"`
	ExecutionID       string            `json:"execution_id"`
	ProvenanceID      string            `json:"provenance_id,omitempty"`
	SnapshotAt        int64             `json:"snapshot_at"`
	Policy            PolicyBlock       `json:"policy"`
	EvaluationContext EvaluationContext `json:"evaluation_context"`
	EvaluationResult  EvaluationResult  `json:"evaluation_result"`
	Sig               string            `json:"sig"`
}

// CaptureRequest holds the inputs for snapshot creation.
type CaptureRequest struct {
	ExecutionID       string
	ProvenanceID      string // optional; MUST at L3-FULL
	Policy            PolicyBlock
	EvaluationContext EvaluationContext
	EvaluationResult  EvaluationResult
}

// signableSnapshot excludes sig from the signing input (§5 — sig set to "").
type signableSnapshot struct {
	Ver               string            `json:"ver"`
	SnapshotID        string            `json:"snapshot_id"`
	ExecutionID       string            `json:"execution_id"`
	ProvenanceID      string            `json:"provenance_id,omitempty"`
	SnapshotAt        int64             `json:"snapshot_at"`
	Policy            PolicyBlock       `json:"policy"`
	EvaluationContext EvaluationContext `json:"evaluation_context"`
	EvaluationResult  EvaluationResult  `json:"evaluation_result"`
	Sig               string            `json:"sig"` // always "" when signing
}

// ─── Capture ──────────────────────────────────────────────────────────────────

// Capture creates and signs a PolicyContextSnapshot.
//
// privKey may be nil (dev/test mode — sig field will be empty).
//
// Per ACP-POLICY-CTX-1.0 §5:
//  1. Generate snapshot_id UUID v4
//  2. Set snapshot_at = now (moment of policy evaluation)
//  3. Copy policy, context, result from request
//  4. Sign with institutional private key
func Capture(req CaptureRequest, privKey ed25519.PrivateKey) (PolicyContextSnapshot, error) {
	if req.EvaluationResult.Decision == "" {
		return PolicyContextSnapshot{}, fmt.Errorf("%w: evaluation_result.decision", ErrRequiredField)
	}

	snapshotID, err := newUUID()
	if err != nil {
		return PolicyContextSnapshot{}, fmt.Errorf("policyctx: generate id: %w", err)
	}

	pcs := PolicyContextSnapshot{
		Ver:               "1.0",
		SnapshotID:        snapshotID,
		ExecutionID:       req.ExecutionID,
		ProvenanceID:      req.ProvenanceID,
		SnapshotAt:        time.Now().Unix(),
		Policy:            req.Policy,
		EvaluationContext: req.EvaluationContext,
		EvaluationResult:  req.EvaluationResult,
	}

	if privKey != nil {
		sig, err := signSnapshot(pcs, privKey)
		if err != nil {
			return PolicyContextSnapshot{}, fmt.Errorf("policyctx: sign: %w", err)
		}
		pcs.Sig = sig
	}

	return pcs, nil
}

// ─── Validation ───────────────────────────────────────────────────────────────

// VerifySig verifies the institutional signature on a PolicyContextSnapshot (§6 step 8).
func VerifySig(pcs PolicyContextSnapshot, pubKey ed25519.PublicKey) error {
	if pcs.Ver != "1.0" {
		return ErrInvalidVersion
	}
	if pcs.Sig == "" {
		return fmt.Errorf("%w: sig is empty", ErrInstitutionalSig)
	}

	s := signableSnapshot{
		Ver:               pcs.Ver,
		SnapshotID:        pcs.SnapshotID,
		ExecutionID:       pcs.ExecutionID,
		ProvenanceID:      pcs.ProvenanceID,
		SnapshotAt:        pcs.SnapshotAt,
		Policy:            pcs.Policy,
		EvaluationContext: pcs.EvaluationContext,
		EvaluationResult:  pcs.EvaluationResult,
		Sig:               "",
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("policyctx: marshal signable: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return fmt.Errorf("policyctx: jcs: %w", err)
	}
	digest := sha256.Sum256(canonical)
	sigBytes, err := base64.RawURLEncoding.DecodeString(pcs.Sig)
	if err != nil {
		return fmt.Errorf("%w: decode sig: %v", ErrInstitutionalSig, err)
	}
	if !ed25519.Verify(pubKey, digest[:], sigBytes) {
		return ErrInstitutionalSig
	}
	return nil
}

// VerifyPolicyHash verifies the policy document hash against a known hash.
// In production, `policyDocHash` is sha256(policy document bytes) as hex.
func VerifyPolicyHash(pcs PolicyContextSnapshot, policyDocHash string) error {
	if pcs.Policy.PolicyHash != policyDocHash {
		return fmt.Errorf("%w: stored %q != computed %q",
			ErrPolicyHashMismatch, pcs.Policy.PolicyHash, policyDocHash)
	}
	return nil
}

// ComputePolicyHash computes the SHA-256 hex digest of a policy document.
// Used to generate or verify PolicyBlock.PolicyHash.
func ComputePolicyHash(policyDoc []byte) string {
	sum := sha256.Sum256(policyDoc)
	return fmt.Sprintf("%x", sum)
}

// ─── In-memory Store ──────────────────────────────────────────────────────────

// InMemorySnapshotStore is a thread-safe store for PolicyContextSnapshot objects.
type InMemorySnapshotStore struct {
	mu      sync.RWMutex
	objects map[string]PolicyContextSnapshot // keyed by snapshot_id
	byExec  map[string]string                // execution_id → snapshot_id
}

// NewInMemorySnapshotStore creates an empty snapshot store.
func NewInMemorySnapshotStore() *InMemorySnapshotStore {
	return &InMemorySnapshotStore{
		objects: make(map[string]PolicyContextSnapshot),
		byExec:  make(map[string]string),
	}
}

// Store persists a PolicyContextSnapshot. Returns an error if snapshot_id already exists.
func (s *InMemorySnapshotStore) Store(pcs PolicyContextSnapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.objects[pcs.SnapshotID]; exists {
		return fmt.Errorf("policyctx: %s already stored", pcs.SnapshotID)
	}
	s.objects[pcs.SnapshotID] = pcs
	if pcs.ExecutionID != "" {
		s.byExec[pcs.ExecutionID] = pcs.SnapshotID
	}
	return nil
}

// Get retrieves a PolicyContextSnapshot by snapshot_id.
func (s *InMemorySnapshotStore) Get(snapshotID string) (PolicyContextSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pcs, ok := s.objects[snapshotID]
	return pcs, ok
}

// GetByExecutionID retrieves the PolicyContextSnapshot for a given execution token.
func (s *InMemorySnapshotStore) GetByExecutionID(executionID string) (PolicyContextSnapshot, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byExec[executionID]
	if !ok {
		return PolicyContextSnapshot{}, false
	}
	pcs, ok := s.objects[id]
	return pcs, ok
}

// Size returns the number of stored snapshots.
func (s *InMemorySnapshotStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.objects)
}

// ─── Signing helper ───────────────────────────────────────────────────────────

func signSnapshot(pcs PolicyContextSnapshot, privKey ed25519.PrivateKey) (string, error) {
	s := signableSnapshot{
		Ver:               pcs.Ver,
		SnapshotID:        pcs.SnapshotID,
		ExecutionID:       pcs.ExecutionID,
		ProvenanceID:      pcs.ProvenanceID,
		SnapshotAt:        pcs.SnapshotAt,
		Policy:            pcs.Policy,
		EvaluationContext: pcs.EvaluationContext,
		EvaluationResult:  pcs.EvaluationResult,
		Sig:               "",
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
