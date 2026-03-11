// Package execution implements ACP-EXEC-1.0 Execution Tokens.
//
// An Execution Token (ET) is a one-time-use cryptographic artefact that proves
// a specific action was authorized by ACP and may be executed exactly once
// within a short window (max 300 seconds).
//
// Lifecycle: issued → used | expired  (terminal states — no transitions out)
package execution

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gowebpki/jcs"
)

// ─── Error Sentinels (ACP-EXEC-1.0 §11) ───────────────────────────────────────

var (
	// ErrUnsupportedVersion is returned when ver != "1.0".
	ErrUnsupportedVersion = errors.New("EXEC-001: unsupported version")

	// ErrInvalidSignature is returned when the ET signature fails.
	ErrInvalidSignature = errors.New("EXEC-002: invalid signature")

	// ErrTokenExpired is returned when expires_at has passed.
	ErrTokenExpired = errors.New("EXEC-003: token expired")

	// ErrTokenAlreadyConsumed is returned when the ET was already marked USED.
	ErrTokenAlreadyConsumed = errors.New("EXEC-004: token already consumed")

	// ErrAgentIDMismatch is returned when agent_id does not match.
	ErrAgentIDMismatch = errors.New("EXEC-005: agent_id mismatch")

	// ErrResourceMismatch is returned when resource does not match.
	ErrResourceMismatch = errors.New("EXEC-006: resource mismatch")

	// ErrParamsHashMismatch is returned when action_parameters_hash fails verification.
	ErrParamsHashMismatch = errors.New("EXEC-007: action_parameters_hash mismatch")

	// ErrTokenNotFound is returned when et_id is not in the registry.
	ErrTokenNotFound = errors.New("EXEC-008: et_id not found in registry")

	// ErrUnauthorizedConsumer is returned when the consumer is not authorized.
	ErrUnauthorizedConsumer = errors.New("EXEC-009: unauthorized consumer")
)

// ─── State ────────────────────────────────────────────────────────────────────

// ETState represents the lifecycle state of an Execution Token.
type ETState string

const (
	// StateIssued means the ET was issued and not yet consumed or expired.
	StateIssued ETState = "issued"
	// StateUsed means the ET was successfully consumed by the target system.
	StateUsed ETState = "used"
	// StateExpired means expires_at was reached before consumption.
	StateExpired ETState = "expired"
)

// MaxWindowSeconds is the maximum ET validity window per ACP-EXEC-1.0 §5.7.
const MaxWindowSeconds = 300

// ─── Token Structure (ACP-EXEC-1.0 §4) ───────────────────────────────────────

// Token is the Execution Token as specified in ACP-EXEC-1.0 §4.
// The Sig field covers all other fields via Ed25519(SHA-256(JCS(signable))).
type Token struct {
	Ver                  string `json:"ver"`
	ETID                 string `json:"et_id"`
	AgentID              string `json:"agent_id"`
	AuthorizationID      string `json:"authorization_id"`
	Capability           string `json:"capability"`
	Resource             string `json:"resource"`
	ActionParametersHash string `json:"action_parameters_hash"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
	Used                 bool   `json:"used"`
	Sig                  string `json:"sig,omitempty"`
}

// RegistryEntry is the server-side record in the ET Registry (ACP-EXEC-1.0 §9).
type RegistryEntry struct {
	ETID             string  `json:"et_id"`
	AuthorizationID  string  `json:"authorization_id"`
	AgentID          string  `json:"agent_id"`
	Capability       string  `json:"capability"`
	Resource         string  `json:"resource"`
	IssuedAt         int64   `json:"issued_at"`
	ExpiresAt        int64   `json:"expires_at"`
	State            ETState `json:"state"`
	ConsumedAt       *int64  `json:"consumed_at"`
	ConsumedBySystem *string `json:"consumed_by_system"`
}

// IssueRequest holds the inputs for ET issuance from an APPROVED authorization.
type IssueRequest struct {
	AgentID          string
	AuthorizationID  string // request_id of the APPROVED AuthorizationDecision
	Capability       string
	Resource         string
	ActionParameters map[string]interface{}
}

// ConsumeRequest is the body for POST /acp/v1/exec-tokens/{et_id}/consume.
// Sent by the target system to report consumption (ACP-EXEC-1.0 §9).
type ConsumeRequest struct {
	ETID            string `json:"et_id"`
	ConsumedAt      int64  `json:"consumed_at"`
	ExecutionResult string `json:"execution_result"` // "success" | "failure" | "unknown"
	Sig             string `json:"sig"`
}

// ─── Issuance ─────────────────────────────────────────────────────────────────

// Issue creates and signs an Execution Token from an APPROVED authorization.
// privKey may be nil (dev mode — sig field will be empty).
//
// Process per ACP-EXEC-1.0 §7:
//  1. Generate et_id UUID v4
//  2. Copy fields from authorization
//  3. Compute action_parameters_hash
//  4. Set issued_at and expires_at (window from capability)
//  5. Sign with institution private key
func Issue(req IssueRequest, privKey ed25519.PrivateKey) (Token, error) {
	now := time.Now().Unix()
	window := windowForCapability(req.Capability)

	paramsHash, err := HashActionParameters(req.ActionParameters)
	if err != nil {
		return Token{}, fmt.Errorf("execution: hash params: %w", err)
	}

	etID, err := newUUID()
	if err != nil {
		return Token{}, fmt.Errorf("execution: generate et_id: %w", err)
	}

	tok := Token{
		Ver:                  "1.0",
		ETID:                 etID,
		AgentID:              req.AgentID,
		AuthorizationID:      req.AuthorizationID,
		Capability:           req.Capability,
		Resource:             req.Resource,
		ActionParametersHash: paramsHash,
		IssuedAt:             now,
		ExpiresAt:            now + int64(window.Seconds()),
		Used:                 false,
	}

	if privKey != nil {
		sig, err := signToken(tok, privKey)
		if err != nil {
			return Token{}, fmt.Errorf("execution: sign token: %w", err)
		}
		tok.Sig = sig
	}

	return tok, nil
}

// ─── Registry ─────────────────────────────────────────────────────────────────

// InMemoryETRegistry is a thread-safe in-memory ET Registry.
// Suitable for testing and single-node deployments. Production SHOULD use
// a persistent store (database) to survive restarts.
type InMemoryETRegistry struct {
	mu      sync.RWMutex
	entries map[string]*RegistryEntry
}

// NewInMemoryETRegistry creates an empty ET registry.
func NewInMemoryETRegistry() *InMemoryETRegistry {
	return &InMemoryETRegistry{entries: make(map[string]*RegistryEntry)}
}

// Register adds an issued ET to the registry.
// Returns an error if et_id already exists (duplicate prevention).
func (r *InMemoryETRegistry) Register(tok Token) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[tok.ETID]; exists {
		return fmt.Errorf("%w: %s", ErrTokenAlreadyConsumed, tok.ETID)
	}
	r.entries[tok.ETID] = &RegistryEntry{
		ETID:            tok.ETID,
		AuthorizationID: tok.AuthorizationID,
		AgentID:         tok.AgentID,
		Capability:      tok.Capability,
		Resource:        tok.Resource,
		IssuedAt:        tok.IssuedAt,
		ExpiresAt:       tok.ExpiresAt,
		State:           StateIssued,
	}
	return nil
}

// Get returns the RegistryEntry for an ET.
// Automatically computes EXPIRED state if expires_at < now and state is ISSUED.
func (r *InMemoryETRegistry) Get(etID string) (RegistryEntry, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.entries[etID]
	if !ok {
		return RegistryEntry{}, fmt.Errorf("%w: %s", ErrTokenNotFound, etID)
	}
	e := *entry // copy to avoid mutating under RLock
	if e.State == StateIssued && time.Now().Unix() > e.ExpiresAt {
		e.State = StateExpired
	}
	return e, nil
}

// Consume marks an ET as USED. Reports the consuming system and timestamp.
// Returns ErrTokenAlreadyConsumed if already USED.
// Returns ErrTokenExpired if expires_at has passed.
// Returns ErrTokenNotFound if et_id is unknown.
func (r *InMemoryETRegistry) Consume(etID, consumedBySystem string, consumedAt int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[etID]
	if !ok {
		return fmt.Errorf("%w: %s", ErrTokenNotFound, etID)
	}
	if entry.State == StateUsed {
		return fmt.Errorf("%w: %s", ErrTokenAlreadyConsumed, etID)
	}
	if entry.State == StateExpired || time.Now().Unix() > entry.ExpiresAt {
		entry.State = StateExpired
		return fmt.Errorf("%w: %s", ErrTokenExpired, etID)
	}
	entry.State = StateUsed
	entry.ConsumedAt = &consumedAt
	entry.ConsumedBySystem = &consumedBySystem
	return nil
}

// Size returns the total number of tracked ETs.
func (r *InMemoryETRegistry) Size() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// Prune removes USED or EXPIRED entries older than 30 days (per §9).
// Like Get, it computes live expiry state for ISSUED entries before deciding.
// Returns the number of entries removed.
func (r *InMemoryETRegistry) Prune() int {
	cutoff := time.Now().Add(-30 * 24 * time.Hour).Unix()
	now := time.Now().Unix()
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for id, entry := range r.entries {
		// Compute live state: issued tokens past expires_at count as expired.
		state := entry.State
		if state == StateIssued && now > entry.ExpiresAt {
			state = StateExpired
		}
		if (state == StateUsed || state == StateExpired) && entry.ExpiresAt < cutoff {
			delete(r.entries, id)
			n++
		}
	}
	return n
}

// ─── Signing & Verification ───────────────────────────────────────────────────

// signableToken defines the fields covered by the ET signature.
// The Sig field is excluded from its own signing input.
type signableToken struct {
	Ver                  string `json:"ver"`
	ETID                 string `json:"et_id"`
	AgentID              string `json:"agent_id"`
	AuthorizationID      string `json:"authorization_id"`
	Capability           string `json:"capability"`
	Resource             string `json:"resource"`
	ActionParametersHash string `json:"action_parameters_hash"`
	IssuedAt             int64  `json:"issued_at"`
	ExpiresAt            int64  `json:"expires_at"`
	Used                 bool   `json:"used"`
}

// signToken computes Ed25519(SHA-256(JCS(signable_fields))) per ACP-SIGN-1.0.
func signToken(tok Token, privKey ed25519.PrivateKey) (string, error) {
	s := signableToken{
		Ver:                  tok.Ver,
		ETID:                 tok.ETID,
		AgentID:              tok.AgentID,
		AuthorizationID:      tok.AuthorizationID,
		Capability:           tok.Capability,
		Resource:             tok.Resource,
		ActionParametersHash: tok.ActionParametersHash,
		IssuedAt:             tok.IssuedAt,
		ExpiresAt:            tok.ExpiresAt,
		Used:                 tok.Used,
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("execution: marshal signable: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("execution: jcs transform: %w", err)
	}
	digest := sha256.Sum256(canonical)
	sig := ed25519.Sign(privKey, digest[:])
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyToken verifies the Sig field of an ET against the institution public key.
// Returns ErrUnsupportedVersion or ErrInvalidSignature on failure.
func VerifyToken(tok Token, pubKey ed25519.PublicKey) error {
	if tok.Ver != "1.0" {
		return fmt.Errorf("%w: %q", ErrUnsupportedVersion, tok.Ver)
	}
	if tok.Sig == "" {
		return fmt.Errorf("%w: sig is empty", ErrInvalidSignature)
	}
	s := signableToken{
		Ver:                  tok.Ver,
		ETID:                 tok.ETID,
		AgentID:              tok.AgentID,
		AuthorizationID:      tok.AuthorizationID,
		Capability:           tok.Capability,
		Resource:             tok.Resource,
		ActionParametersHash: tok.ActionParametersHash,
		IssuedAt:             tok.IssuedAt,
		ExpiresAt:            tok.ExpiresAt,
		Used:                 tok.Used,
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("execution: marshal signable: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return fmt.Errorf("execution: jcs transform: %w", err)
	}
	digest := sha256.Sum256(canonical)
	sigBytes, err := base64.RawURLEncoding.DecodeString(tok.Sig)
	if err != nil {
		return fmt.Errorf("%w: decode sig: %v", ErrInvalidSignature, err)
	}
	if !ed25519.Verify(pubKey, digest[:], sigBytes) {
		return ErrInvalidSignature
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// HashActionParameters computes base64url(SHA-256(JCS(action_parameters))).
// If params is nil, hashes the canonical form of null ("null").
func HashActionParameters(params map[string]interface{}) (string, error) {
	raw, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("execution: marshal params: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("execution: jcs params: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

// windowForCapability returns the execution window for a given capability.
// Per ACP-EXEC-1.0 §5.7 table.
func windowForCapability(cap string) time.Duration {
	switch {
	case strings.HasPrefix(cap, "acp:cap:financial."):
		return 60 * time.Second
	case strings.Contains(cap, "infrastructure.delete"):
		return 30 * time.Second
	case strings.Contains(cap, "infrastructure.deploy"):
		return 120 * time.Second
	case strings.HasSuffix(cap, ".read"):
		return 300 * time.Second
	default:
		return 120 * time.Second
	}
}

// newUUID generates a random UUID v4 string.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
