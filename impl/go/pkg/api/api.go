// Package api implements the ACP-API-1.0 HTTP API layer.
//
// Provides:
//   - Standard response envelopes (§3): success {acp_version, request_id, timestamp, data, sig}
//     and error {acp_version, request_id, timestamp, error{code, message}}
//   - Middleware: adds X-ACP-Version and X-ACP-Request-ID to every response
//   - WriteSuccess / WriteError helpers used by all handlers
//   - Response signing via Ed25519 over SHA-256(JCS(signable_fields))
//   - Error code constants from §12
package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gowebpki/jcs"
)

// ─── Error Codes (ACP-API-1.0 §12) ─────────────────────────────────────────────────────────

const (
	// Handshake errors
	ErrHP004 = "HP-004" // X-ACP-PoP header absent
	ErrHP007 = "HP-007" // Challenge not found, expired, or already consumed
	ErrHP009 = "HP-009" // Invalid PoP signature
	ErrHP010 = "HP-010" // agent_id in PoP does not match CT sub
	ErrHP014 = "HP-014" // request_body_hash mismatch

	// Authentication errors
	ErrAUTH001 = "AUTH-001" // Token absent or expired
	ErrAUTH002 = "AUTH-002" // Insufficient capability
	ErrAUTH003 = "AUTH-003" // Insufficient capability for state transition
	ErrAUTH004 = "AUTH-004" // Duplicate request_id
	ErrAUTH005 = "AUTH-005" // Agent suspended or revoked
	ErrAUTH006 = "AUTH-006" // Token revoked
	ErrAUTH007 = "AUTH-007" // Token nonce reused — possible replay
	ErrAUTH008 = "AUTH-008" // Agent has no execution autonomy (level 0)

	// Agent errors
	ErrAGENT001 = "AGENT-001" // agent_id does not derive from public_key
	ErrAGENT002 = "AGENT-002" // autonomy_level out of range
	ErrAGENT003 = "AGENT-003" // authority_domain not registered
	ErrAGENT004 = "AGENT-004" // agent_id already registered
	ErrAGENT005 = "AGENT-005" // agent_id not found

	// State transition errors
	ErrSTATE001 = "STATE-001" // Invalid state transition
	ErrSTATE002 = "STATE-002" // Attempt to transition from revoked

	// Audit errors
	ErrAUDIT001 = "AUDIT-001" // Invalid hash chain

	// System errors
	ErrSYS001 = "SYS-001" // Agent Registry unavailable
	ErrSYS002 = "SYS-002" // Policy Engine unavailable
	ErrSYS003 = "SYS-003" // Audit Ledger unavailable
	ErrSYS004 = "SYS-004" // Malformed request body
	ErrSYS005 = "SYS-005" // Internal timeout
)

// ─── Response Envelopes (ACP-API-1.0 §3) ──────────────────────────────────────────────

// Response is the standard ACP-API-1.0 success envelope.
// The Sig field covers: acp_version, request_id, timestamp, data
// via Ed25519 over SHA-256(JCS(signable)). Omitted when no private key.
type Response struct {
	ACPVersion string      `json:"acp_version"`
	RequestID  string      `json:"request_id"`
	Timestamp  int64       `json:"timestamp"`
	Data       interface{} `json:"data"`
	Sig        string      `json:"sig,omitempty"`
}

// ErrorResponse is the standard ACP-API-1.0 error envelope.
// Per §3: error responses MUST NOT include the sig field.
type ErrorResponse struct {
	ACPVersion string    `json:"acp_version"`
	RequestID  string    `json:"request_id"`
	Timestamp  int64     `json:"timestamp"`
	Error      ErrorBody `json:"error"`
}

// ErrorBody contains the structured error detail.
type ErrorBody struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Detail  interface{} `json:"detail,omitempty"`
}

// ─── Context Key ────────────────────────────────────────────────────────────────────────

type contextKey string

// RequestIDKey is the context key used to store the request ID.
const RequestIDKey contextKey = "acp-request-id"

// ─── Middleware ─────────────────────────────────────────────────────────────────────────

// Middleware returns an http.Handler middleware that:
//   - Echoes X-ACP-Request-ID from request (or generates one if absent)
//   - Sets X-ACP-Version: 1.0 on every response
//   - Stores the request ID in the request context for handlers
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-ACP-Request-ID")
		if reqID == "" {
			reqID = newRequestID()
		}
		// Set response headers before the handler writes the status line.
		w.Header().Set("X-ACP-Version", "1.0")
		w.Header().Set("X-ACP-Request-ID", reqID)

		// Store in context so handlers can read it via GetRequestID.
		ctx := context.WithValue(r.Context(), RequestIDKey, reqID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRequestID retrieves the ACP request ID from the request context.
// Returns an empty string if not set (e.g., middleware not applied).
func GetRequestID(r *http.Request) string {
	if id, ok := r.Context().Value(RequestIDKey).(string); ok {
		return id
	}
	return ""
}

// ─── Response Writers ─────────────────────────────────────────────────────────────────

// WriteSuccess writes a signed ACP-API-1.0 success response.
//
//   - privKey may be nil — in that case the sig field is omitted (dev mode).
//   - The request ID is read from the context (set by Middleware).
//   - Callers must NOT call w.WriteHeader before this function.
func WriteSuccess(w http.ResponseWriter, r *http.Request, status int, data interface{}, privKey ed25519.PrivateKey) {
	reqID := GetRequestID(r)
	resp := Response{
		ACPVersion: "1.0",
		RequestID:  reqID,
		Timestamp:  time.Now().Unix(),
		Data:       data,
	}

	if privKey != nil {
		if sig, err := signResponse(resp, privKey); err == nil {
			resp.Sig = sig
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// WriteError writes an ACP-API-1.0 error response (no sig, per §3).
//
//   - code must be one of the Err* constants defined in this package.
//   - The request ID is read from the context (set by Middleware).
func WriteError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	reqID := GetRequestID(r)
	resp := ErrorResponse{
		ACPVersion: "1.0",
		RequestID:  reqID,
		Timestamp:  time.Now().Unix(),
		Error: ErrorBody{
			Code:    code,
			Message: message,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// WriteErrorDetail is like WriteError but includes a structured detail field.
func WriteErrorDetail(w http.ResponseWriter, r *http.Request, status int, code, message string, detail interface{}) {
	reqID := GetRequestID(r)
	resp := ErrorResponse{
		ACPVersion: "1.0",
		RequestID:  reqID,
		Timestamp:  time.Now().Unix(),
		Error: ErrorBody{
			Code:    code,
			Message: message,
			Detail:  detail,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

// ─── Response Signing ─────────────────────────────────────────────────────────────────

// signableResponse is the struct whose JCS serialization is signed.
// Per ACP-API-1.0 §3: covers acp_version, request_id, timestamp, data.
type signableResponse struct {
	ACPVersion string      `json:"acp_version"`
	RequestID  string      `json:"request_id"`
	Timestamp  int64       `json:"timestamp"`
	Data       interface{} `json:"data"`
}

// signResponse computes Ed25519(SHA-256(JCS(signable_fields))) and returns
// the signature as a base64url (no padding) encoded string.
func signResponse(resp Response, privKey ed25519.PrivateKey) (string, error) {
	s := signableResponse{
		ACPVersion: resp.ACPVersion,
		RequestID:  resp.RequestID,
		Timestamp:  resp.Timestamp,
		Data:       resp.Data,
	}

	// Marshal to JSON first, then canonicalize with JCS.
	raw, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("api: marshal signable: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return "", fmt.Errorf("api: jcs transform: %w", err)
	}

	digest := sha256.Sum256(canonical)
	sig := ed25519.Sign(privKey, digest[:])
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyResponseSig verifies the sig field of a Response envelope.
// Used in tests and by clients to authenticate server responses.
func VerifyResponseSig(resp Response, pubKey ed25519.PublicKey) error {
	s := signableResponse{
		ACPVersion: resp.ACPVersion,
		RequestID:  resp.RequestID,
		Timestamp:  resp.Timestamp,
		Data:       resp.Data,
	}
	raw, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("api: marshal signable: %w", err)
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return fmt.Errorf("api: jcs transform: %w", err)
	}
	digest := sha256.Sum256(canonical)
	sigBytes, err := base64.RawURLEncoding.DecodeString(resp.Sig)
	if err != nil {
		return fmt.Errorf("api: decode sig: %w", err)
	}
	if !ed25519.Verify(pubKey, digest[:], sigBytes) {
		return fmt.Errorf("api: signature verification failed")
	}
	return nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────────────────

// newRequestID generates a random UUID v4 string.
func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
