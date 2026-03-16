// Package hist implements ACP-HIST-1.0 History Query API.
//
// ACP-HIST-1.0 is the query layer over the ACP Audit Ledger (ACP-LEDGER-1.3).
// LEDGER defines structure and storage; HIST defines access.
//
// Provides:
//   - HistoryQuery: filtered + paginated query of ledger events (§4)
//   - Single event lookup with integrity verification (§5)
//   - Agent history consolidation with computed summary (§6)
//   - ExportBundle: signed, self-verifiable portable audit segment (§7)
//
// Required for L4-EXTENDED conformance (ACP-CONF-1.2).
package hist

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/ledger"
	"github.com/gowebpki/jcs"
)

// ─── Error Sentinels (ACP-HIST-1.0 §4, §5, §7) ───────────────────────────────

var (
	ErrInvalidFilter       = errors.New("HIST-E001: invalid or incompatible filter parameters")
	ErrLimitOutOfRange     = errors.New("HIST-E002: limit out of range (< 1 or > 100)")
	ErrMixedTSAndSeq       = errors.New("HIST-E003: simultaneous ts and seq combination not allowed")
	ErrInsufficientRole    = errors.New("HIST-E004: insufficient role for requested scope")
	ErrCursorExpired       = errors.New("HIST-E005: expired or invalid cursor")
	ErrChainVerifyFailed   = errors.New("HIST-E006: chain verification failure")
	ErrEventNotFound       = errors.New("HIST-E010: event_id not found")
	ErrExportInvalidRange  = errors.New("HIST-E020: invalid export range (from_ts >= to_ts)")
	ErrExportTTLOutOfRange = errors.New("HIST-E021: ttl_seconds out of range")
	ErrExportEmptyScope    = errors.New("HIST-E023: scope produces zero events — empty bundle not allowed")
	ErrExportSignFailed    = errors.New("HIST-E024: error signing institutional bundle")
)

// ─── Query Types (ACP-HIST-1.0 §4) ───────────────────────────────────────────

// QueryFilter defines all supported filter parameters for GET /acp/v1/audit/query.
type QueryFilter struct {
	EventTypes    []string // comma-separated event_type values
	AgentID       string
	InstitutionID string
	Capability    string // prefix match allowed (e.g. "acp:cap:financial.*")
	Resource      string
	Decision      string // "APPROVED" | "DENIED" | "ESCALATED"
	FromTS        int64  // UNIX timestamp range start (inclusive)
	ToTS          int64  // UNIX timestamp range end (inclusive)
	FromSeq       int64  // minimum sequence (inclusive)
	ToSeq         int64  // maximum sequence (inclusive)
	Cursor        string // opaque pagination token
	Limit         int    // default 20, max 100
	VerifyChain   bool
}

// Pagination holds the pagination metadata in query responses (§4).
type Pagination struct {
	Cursor        string  `json:"cursor"`
	HasMore       bool    `json:"has_more"`
	ReturnedCount int     `json:"returned_count"`
	TotalCount    *int    `json:"total_count"` // always null per spec
}

// Integrity holds chain verification status in responses (§4).
type Integrity struct {
	ChainValid             *bool  `json:"chain_valid"`             // null if verify_chain=false
	VerifiedFromSeq        int64  `json:"verified_from_seq,omitempty"`
	VerifiedToSeq          int64  `json:"verified_to_seq,omitempty"`
	PolicyContext          string `json:"policy_context,omitempty"` // "v1.1" | "mixed" | "legacy"
	ArchiveSegments        bool   `json:"archive_segments,omitempty"`
}

// QueryResponse is the response for GET /acp/v1/audit/query (§4).
type QueryResponse struct {
	Ver           string         `json:"ver"`
	InstitutionID string         `json:"institution_id"`
	Events        []ledger.Event `json:"events"`
	Pagination    Pagination     `json:"pagination"`
	Integrity     Integrity      `json:"integrity"`
}

// EventResponse is the response for GET /acp/v1/audit/events/{event_id} (§5).
type EventResponse struct {
	Ver       string       `json:"ver"`
	Event     ledger.Event `json:"event"`
	Integrity struct {
		HashValid bool `json:"hash_valid"`
		SigValid  bool `json:"sig_valid"`
	} `json:"integrity"`
}

// ─── Agent History Types (ACP-HIST-1.0 §6) ───────────────────────────────────

// AgentHistoryFilter defines filters for GET /acp/v1/audit/agents/{agent_id}/history.
type AgentHistoryFilter struct {
	FromTS       int64
	ToTS         int64
	Cursor       string
	Limit        int
	IncludeTypes []string // default: all agent-relevant types
}

// AgentSummary is the computed aggregate view of an agent's activity (§6).
type AgentSummary struct {
	TotalAuthorizations   int     `json:"total_authorizations"`
	Approved              int     `json:"approved"`
	Denied                int     `json:"denied"`
	Escalated             int     `json:"escalated"`
	ExecutionsSuccessful  int     `json:"executions_successful"`
	ExecutionsFailed      int     `json:"executions_failed"`
	CurrentRepScore       float64 `json:"current_rep_score"`
	FirstEventTS          int64   `json:"first_event_ts"`
	LastEventTS           int64   `json:"last_event_ts"`
}

// AgentHistoryResponse is the response for GET /acp/v1/audit/agents/{agent_id}/history (§6).
type AgentHistoryResponse struct {
	Ver           string         `json:"ver"`
	AgentID       string         `json:"agent_id"`
	InstitutionID string         `json:"institution_id"`
	Events        []ledger.Event `json:"events"`
	Summary       AgentSummary   `json:"summary"`
	Pagination    Pagination     `json:"pagination"`
	Integrity     Integrity      `json:"integrity"`
}

// defaultAgentEventTypes are the event types included by default in agent history (§6).
var defaultAgentEventTypes = []string{
	"AUTHORIZATION", "RISK_EVALUATION", "REVOCATION",
	"TOKEN_ISSUED", "EXECUTION_TOKEN_ISSUED", "EXECUTION_TOKEN_CONSUMED",
	"LIABILITY_RECORD", "REPUTATION_UPDATED", "AGENT_STATE_CHANGE",
	"ESCALATION_CREATED", "ESCALATION_RESOLVED",
}

// ─── ExportBundle Types (ACP-HIST-1.0 §7) ────────────────────────────────────

// ExportScope defines the scope of events to include in an ExportBundle.
type ExportScope struct {
	FromTS     int64    `json:"from_ts"`
	ToTS       int64    `json:"to_ts"`
	AgentID    string   `json:"agent_id,omitempty"`
	EventTypes []string `json:"event_types,omitempty"`
}

// ExportRequest is the POST /acp/v1/audit/export request body (§7).
type ExportRequest struct {
	Scope         ExportScope
	Format        string // "full" | "hashes_only"
	IncludeAnchor bool
	TTLSeconds    int64
}

// AnchorEvent is the anchor for chain verification without the full ledger (§7).
type AnchorEvent struct {
	EventID  string `json:"event_id"`
	Sequence int64  `json:"sequence"`
	Hash     string `json:"hash"`
}

// ExportBundle is a signed, self-verifiable ledger segment (§7).
// bundle_sig covers all fields except itself via Ed25519(SHA-256(JCS(bundle))).
type ExportBundle struct {
	Ver         string         `json:"ver"`
	BundleID    string         `json:"bundle_id"`
	Issuer      string         `json:"issuer"`
	IssuedAt    int64          `json:"issued_at"`
	ExpiresAt   int64          `json:"expires_at"`
	Scope       ExportScope    `json:"scope"`
	Format      string         `json:"format"`
	AnchorEvent *AnchorEvent   `json:"anchor_event,omitempty"`
	Events      []ledger.Event `json:"events"`
	EventCount  int            `json:"event_count"`
	ChainValid  bool           `json:"chain_valid"`
	BundleHash  string         `json:"bundle_hash"`
	BundleSig   string         `json:"bundle_sig"`
}

// signableBundle excludes bundle_sig from the signing input.
type signableBundle struct {
	Ver         string         `json:"ver"`
	BundleID    string         `json:"bundle_id"`
	Issuer      string         `json:"issuer"`
	IssuedAt    int64          `json:"issued_at"`
	ExpiresAt   int64          `json:"expires_at"`
	Scope       ExportScope    `json:"scope"`
	Format      string         `json:"format"`
	AnchorEvent *AnchorEvent   `json:"anchor_event,omitempty"`
	Events      []ledger.Event `json:"events"`
	EventCount  int            `json:"event_count"`
	ChainValid  bool           `json:"chain_valid"`
	BundleHash  string         `json:"bundle_hash"`
	BundleSig   string         `json:"bundle_sig"` // always "" when signing
}

// ─── Query Engine ─────────────────────────────────────────────────────────────

// Query executes a filtered, paginated ledger query (§4 GET /acp/v1/audit/query).
//
// Returns ErrMixedTSAndSeq if both ts and seq filters are provided.
// Returns ErrLimitOutOfRange if limit < 1 or limit > 100.
func Query(l *ledger.InMemoryLedger, institutionID string, f QueryFilter) (QueryResponse, error) {
	if f.FromTS > 0 && f.FromSeq > 0 {
		return QueryResponse{}, ErrMixedTSAndSeq
	}
	if f.ToTS > 0 && f.ToSeq > 0 {
		return QueryResponse{}, ErrMixedTSAndSeq
	}

	limit := f.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		return QueryResponse{}, ErrLimitOutOfRange
	}

	// Decode cursor to get starting sequence.
	startSeq, err := decodeCursor(f.Cursor)
	if err != nil {
		return QueryResponse{}, ErrCursorExpired
	}

	// Build event type set for O(1) lookup.
	typeSet := make(map[string]struct{}, len(f.EventTypes))
	for _, t := range f.EventTypes {
		typeSet[t] = struct{}{}
	}

	// Pull all events and apply filters.
	all := l.List(1, 0)
	var filtered []ledger.Event
	for _, ev := range all {
		if startSeq > 0 && ev.Sequence <= startSeq {
			continue
		}
		if f.FromSeq > 0 && ev.Sequence < f.FromSeq {
			continue
		}
		if f.ToSeq > 0 && ev.Sequence > f.ToSeq {
			continue
		}
		if f.FromTS > 0 && ev.Timestamp < f.FromTS {
			continue
		}
		if f.ToTS > 0 && ev.Timestamp > f.ToTS {
			continue
		}
		if len(typeSet) > 0 {
			if _, ok := typeSet[ev.EventType]; !ok {
				continue
			}
		}
		if f.AgentID != "" && !eventMatchesAgent(ev, f.AgentID) {
			continue
		}
		if f.Capability != "" && !eventMatchesCapability(ev, f.Capability) {
			continue
		}
		filtered = append(filtered, ev)
	}

	// Paginate.
	hasMore := len(filtered) > limit
	page := filtered
	if hasMore {
		page = filtered[:limit]
	}

	// Build cursor.
	var nextCursor string
	if hasMore && len(page) > 0 {
		last := page[len(page)-1]
		nextCursor = encodeCursor(last.Sequence, last.Timestamp)
	}

	// Chain verification.
	integ := buildIntegrity(page, f.VerifyChain, l)

	return QueryResponse{
		Ver:           "1.0",
		InstitutionID: institutionID,
		Events:        page,
		Pagination: Pagination{
			Cursor:        nextCursor,
			HasMore:       hasMore,
			ReturnedCount: len(page),
			TotalCount:    nil,
		},
		Integrity: integ,
	}, nil
}

// GetEvent retrieves a single event by event_id with integrity verification (§5).
func GetEvent(l *ledger.InMemoryLedger, eventID string) (EventResponse, error) {
	ev, ok := l.Get(eventID)
	if !ok {
		return EventResponse{}, ErrEventNotFound
	}
	_, errs := l.VerifyEvent(eventID)
	hashValid := true
	sigValid := true
	for _, e := range errs {
		if e.Code == "LEDGER-003" {
			hashValid = false
		}
		if e.Code == "LEDGER-002" {
			sigValid = false
		}
	}
	resp := EventResponse{
		Ver:   "1.0",
		Event: ev,
	}
	resp.Integrity.HashValid = hashValid
	resp.Integrity.SigValid = sigValid
	return resp, nil
}

// AgentHistory returns the consolidated activity history for a specific agent (§6).
func AgentHistory(l *ledger.InMemoryLedger, institutionID, agentID string, f AgentHistoryFilter) AgentHistoryResponse {
	limit := f.Limit
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	includeTypes := f.IncludeTypes
	if len(includeTypes) == 0 {
		includeTypes = defaultAgentEventTypes
	}
	typeSet := make(map[string]struct{}, len(includeTypes))
	for _, t := range includeTypes {
		typeSet[t] = struct{}{}
	}

	startSeq, _ := decodeCursor(f.Cursor)
	all := l.List(1, 0)

	var agentEvents []ledger.Event
	var summary AgentSummary
	firstTS := int64(0)
	lastTS := int64(0)

	for _, ev := range all {
		if !eventMatchesAgent(ev, agentID) {
			continue
		}
		// Update summary across ALL agent events (not just page)
		updateSummary(&summary, ev)
		if firstTS == 0 || ev.Timestamp < firstTS {
			firstTS = ev.Timestamp
		}
		if ev.Timestamp > lastTS {
			lastTS = ev.Timestamp
		}

		// Apply page filters
		if startSeq > 0 && ev.Sequence <= startSeq {
			continue
		}
		if f.FromTS > 0 && ev.Timestamp < f.FromTS {
			continue
		}
		if f.ToTS > 0 && ev.Timestamp > f.ToTS {
			continue
		}
		if _, ok := typeSet[ev.EventType]; !ok {
			continue
		}
		agentEvents = append(agentEvents, ev)
	}

	summary.FirstEventTS = firstTS
	summary.LastEventTS = lastTS

	hasMore := len(agentEvents) > limit
	page := agentEvents
	if hasMore {
		page = agentEvents[:limit]
	}

	var nextCursor string
	if hasMore && len(page) > 0 {
		last := page[len(page)-1]
		nextCursor = encodeCursor(last.Sequence, last.Timestamp)
	}

	return AgentHistoryResponse{
		Ver:           "1.0",
		AgentID:       agentID,
		InstitutionID: institutionID,
		Events:        page,
		Summary:       summary,
		Pagination: Pagination{
			Cursor:        nextCursor,
			HasMore:       hasMore,
			ReturnedCount: len(page),
		},
		Integrity: Integrity{ChainValid: nil},
	}
}

// Export generates a signed ExportBundle for the given scope (§7).
//
// Returns ErrExportInvalidRange if from_ts >= to_ts.
// Returns ErrExportEmptyScope if the scope produces zero events.
// privKey may be nil (dev mode — bundle_sig and bundle_hash will be empty).
func Export(l *ledger.InMemoryLedger, institutionID string, req ExportRequest, privKey ed25519.PrivateKey) (ExportBundle, error) {
	if req.Scope.FromTS >= req.Scope.ToTS {
		return ExportBundle{}, ErrExportInvalidRange
	}
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 86400
	}
	if ttl > 604800 {
		return ExportBundle{}, ErrExportTTLOutOfRange
	}

	typeSet := make(map[string]struct{}, len(req.Scope.EventTypes))
	for _, t := range req.Scope.EventTypes {
		typeSet[t] = struct{}{}
	}

	all := l.List(1, 0)
	var events []ledger.Event
	var anchorEvent *AnchorEvent

	for i, ev := range all {
		// Anchor: the event immediately before the range
		if req.IncludeAnchor && ev.Timestamp < req.Scope.FromTS {
			if i+1 < len(all) && all[i+1].Timestamp >= req.Scope.FromTS {
				anchorEvent = &AnchorEvent{
					EventID:  ev.EventID,
					Sequence: ev.Sequence,
					Hash:     ev.Hash,
				}
			}
			continue
		}
		if ev.Timestamp < req.Scope.FromTS || ev.Timestamp > req.Scope.ToTS {
			continue
		}
		if req.Scope.AgentID != "" && !eventMatchesAgent(ev, req.Scope.AgentID) {
			continue
		}
		if len(typeSet) > 0 {
			if _, ok := typeSet[ev.EventType]; !ok {
				continue
			}
		}
		if req.Format == "hashes_only" {
			events = append(events, ledger.Event{
				EventID:  ev.EventID,
				Sequence: ev.Sequence,
				Hash:     ev.Hash,
				Sig:      ev.Sig,
			})
		} else {
			events = append(events, ev)
		}
	}

	if len(events) == 0 {
		return ExportBundle{}, ErrExportEmptyScope
	}

	// Verify chain of the segment.
	verifyErrs := l.Verify()
	chainValid := len(verifyErrs) == 0

	bundleID, err := newUUID()
	if err != nil {
		return ExportBundle{}, fmt.Errorf("hist: generate bundle_id: %w", err)
	}

	now := time.Now().Unix()
	bundle := ExportBundle{
		Ver:         "1.0",
		BundleID:    bundleID,
		Issuer:      institutionID,
		IssuedAt:    now,
		ExpiresAt:   now + ttl,
		Scope:       req.Scope,
		Format:      req.Format,
		AnchorEvent: anchorEvent,
		Events:      events,
		EventCount:  len(events),
		ChainValid:  chainValid,
	}

	if privKey != nil {
		bundleHash, sig, err := signBundle(bundle, privKey)
		if err != nil {
			return ExportBundle{}, ErrExportSignFailed
		}
		bundle.BundleHash = bundleHash
		bundle.BundleSig = sig
	}

	return bundle, nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

// cursorPayload is the internal structure of the opaque cursor.
type cursorPayload struct {
	Seq int64 `json:"seq"`
	TS  int64 `json:"ts"`
	Exp int64 `json:"exp"`
}

// encodeCursor encodes a cursor from a sequence number and timestamp.
func encodeCursor(seq, ts int64) string {
	p := cursorPayload{Seq: seq, TS: ts, Exp: time.Now().Add(24 * time.Hour).Unix()}
	raw, _ := json.Marshal(p)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// decodeCursor decodes a cursor and returns the sequence number.
// Returns 0 if cursor is empty. Returns an error if cursor is invalid or expired.
func decodeCursor(cursor string) (int64, error) {
	if cursor == "" {
		return 0, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, ErrCursorExpired
	}
	var p cursorPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return 0, ErrCursorExpired
	}
	if time.Now().Unix() > p.Exp {
		return 0, ErrCursorExpired
	}
	return p.Seq, nil
}

// buildIntegrity computes the Integrity struct for a query response.
func buildIntegrity(events []ledger.Event, verifyChain bool, l *ledger.InMemoryLedger) Integrity {
	integ := Integrity{ChainValid: nil}
	if len(events) == 0 {
		return integ
	}
	integ.VerifiedFromSeq = events[0].Sequence
	integ.VerifiedToSeq = events[len(events)-1].Sequence

	if verifyChain {
		errs := l.Verify()
		valid := len(errs) == 0
		integ.ChainValid = &valid
	}

	// Determine policy_context from whether events include policy_snapshot_ref.
	// Simplified: check if payload maps contain the field.
	hasRef := 0
	for _, ev := range events {
		if m, ok := ev.Payload.(map[string]interface{}); ok {
			if _, ok := m["policy_snapshot_ref"]; ok {
				hasRef++
			}
		}
	}
	switch {
	case hasRef == len(events):
		integ.PolicyContext = "v1.1"
	case hasRef == 0:
		integ.PolicyContext = "legacy"
	default:
		integ.PolicyContext = "mixed"
	}

	return integ
}

// eventMatchesAgent checks if an event is related to the given agentID.
// Checks common payload fields: agent_id, sub.
func eventMatchesAgent(ev ledger.Event, agentID string) bool {
	m, ok := ev.Payload.(map[string]interface{})
	if !ok {
		return false
	}
	for _, field := range []string{"agent_id", "sub", "agent"} {
		if v, ok := m[field].(string); ok && v == agentID {
			return true
		}
	}
	return false
}

// eventMatchesCapability checks if an event's capability matches the filter.
// Supports prefix wildcard: "acp:cap:financial.*"
func eventMatchesCapability(ev ledger.Event, capFilter string) bool {
	m, ok := ev.Payload.(map[string]interface{})
	if !ok {
		return false
	}
	cap, ok := m["capability"].(string)
	if !ok {
		return false
	}
	prefix := strings.TrimSuffix(capFilter, "*")
	if prefix != capFilter {
		return strings.HasPrefix(cap, prefix)
	}
	return cap == capFilter
}

// updateSummary accumulates an event into the AgentSummary.
func updateSummary(s *AgentSummary, ev ledger.Event) {
	m, ok := ev.Payload.(map[string]interface{})
	if !ok {
		return
	}
	switch ev.EventType {
	case "AUTHORIZATION":
		s.TotalAuthorizations++
		switch m["decision"] {
		case "APPROVED":
			s.Approved++
		case "DENIED":
			s.Denied++
		case "ESCALATED":
			s.Escalated++
		}
	case "EXECUTION_TOKEN_CONSUMED":
		if m["execution_result"] == "success" {
			s.ExecutionsSuccessful++
		} else {
			s.ExecutionsFailed++
		}
	case "REPUTATION_UPDATED":
		if score, ok := m["new_score"].(float64); ok {
			s.CurrentRepScore = score
		}
	}
}

// signBundle signs the bundle and returns (bundleHash, bundleSig).
// bundle_sig = base64url(Ed25519(SHA-256(JCS(bundle without bundle_sig)))).
func signBundle(b ExportBundle, privKey ed25519.PrivateKey) (string, string, error) {
	s := signableBundle{
		Ver:         b.Ver,
		BundleID:    b.BundleID,
		Issuer:      b.Issuer,
		IssuedAt:    b.IssuedAt,
		ExpiresAt:   b.ExpiresAt,
		Scope:       b.Scope,
		Format:      b.Format,
		AnchorEvent: b.AnchorEvent,
		Events:      b.Events,
		EventCount:  b.EventCount,
		ChainValid:  b.ChainValid,
		BundleHash:  "",
		BundleSig:   "",
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return "", "", fmt.Errorf("marshal: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", "", fmt.Errorf("jcs: %w", err)
	}
	digest := sha256.Sum256(canonical)
	bundleHash := base64.URLEncoding.EncodeToString(digest[:])
	sig := ed25519.Sign(privKey, digest[:])
	return bundleHash, base64.RawURLEncoding.EncodeToString(sig), nil
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
