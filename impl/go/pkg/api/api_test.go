// Package api_test — tests for ACP-API-1.0 HTTP layer.
package api_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	acpapi "github.com/chelof100/acp-framework/acp-go/pkg/api"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// newKeyPair generates a fresh Ed25519 key pair for testing.
func newKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return pub, priv
}

// doReq builds and executes a test request through the given handler.
func doReq(t *testing.T, handler http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// doReqWithID like doReq but includes X-ACP-Request-ID header.
func doReqWithID(t *testing.T, handler http.Handler, method, path, reqID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-ACP-Request-ID", reqID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	return w
}

// ─── Middleware ────────────────────────────────────────────────────────────────

func TestMiddleware_SetsVersionHeader(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := acpapi.Middleware(inner)
	w := doReq(t, handler, http.MethodGet, "/test")

	if got := w.Header().Get("X-ACP-Version"); got != "1.0" {
		t.Errorf("X-ACP-Version = %q, want %q", got, "1.0")
	}
}

func TestMiddleware_EchoesRequestID(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := acpapi.Middleware(inner)

	const testID = "test-request-id-123"
	w := doReqWithID(t, handler, http.MethodGet, "/test", testID)

	if got := w.Header().Get("X-ACP-Request-ID"); got != testID {
		t.Errorf("X-ACP-Request-ID = %q, want %q", got, testID)
	}
}

func TestMiddleware_GeneratesRequestIDWhenAbsent(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := acpapi.Middleware(inner)
	w := doReq(t, handler, http.MethodGet, "/test")

	if got := w.Header().Get("X-ACP-Request-ID"); got == "" {
		t.Error("X-ACP-Request-ID should be auto-generated, got empty string")
	}
}

func TestMiddleware_InjectsRequestIDIntoContext(t *testing.T) {
	const testID = "ctx-test-id-456"
	var gotID string

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = acpapi.GetRequestID(r)
		w.WriteHeader(http.StatusOK)
	})
	handler := acpapi.Middleware(inner)

	doReqWithID(t, handler, http.MethodGet, "/test", testID)

	if gotID != testID {
		t.Errorf("context request_id = %q, want %q", gotID, testID)
	}
}

func TestMiddleware_UniqueGeneratedIDs(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := acpapi.Middleware(inner)

	ids := make(map[string]bool)
	for i := 0; i < 50; i++ {
		w := doReq(t, handler, http.MethodGet, "/test")
		id := w.Header().Get("X-ACP-Request-ID")
		if id == "" {
			t.Fatalf("iteration %d: generated empty request ID", i)
		}
		if ids[id] {
			t.Fatalf("iteration %d: duplicate request ID %q", i, id)
		}
		ids[id] = true
	}
}

// ─── WriteSuccess ─────────────────────────────────────────────────────────────

func TestWriteSuccess_Envelope(t *testing.T) {
	handler := acpapi.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acpapi.WriteSuccess(w, r, http.StatusOK, map[string]string{"key": "value"}, nil)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-ACP-Request-ID", "my-req-id")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var resp acpapi.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ACPVersion != "1.0" {
		t.Errorf("acp_version = %q, want %q", resp.ACPVersion, "1.0")
	}
	if resp.RequestID != "my-req-id" {
		t.Errorf("request_id = %q, want %q", resp.RequestID, "my-req-id")
	}
	if resp.Timestamp == 0 {
		t.Error("timestamp must not be 0")
	}
	if resp.Data == nil {
		t.Error("data must not be nil")
	}
	if resp.Sig != "" {
		t.Error("sig must be empty when no private key provided")
	}
}

func TestWriteSuccess_StatusCodes(t *testing.T) {
	cases := []struct {
		status int
	}{
		{http.StatusOK},
		{http.StatusCreated},
		{http.StatusAccepted},
	}

	for _, tc := range cases {
		handler := acpapi.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acpapi.WriteSuccess(w, r, tc.status, nil, nil)
		}))
		w := doReq(t, handler, http.MethodPost, "/test")
		if w.Code != tc.status {
			t.Errorf("status = %d, want %d", w.Code, tc.status)
		}
	}
}

func TestWriteSuccess_WithSignature(t *testing.T) {
	pub, priv := newKeyPair(t)

	handler := acpapi.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acpapi.WriteSuccess(w, r, http.StatusOK, map[string]string{"hello": "world"}, priv)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-ACP-Request-ID", "sig-test-id")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp acpapi.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Sig == "" {
		t.Fatal("sig must not be empty when private key provided")
	}

	// Verify signature with public key.
	if err := acpapi.VerifyResponseSig(resp, pub); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestWriteSuccess_SignatureTamperedData(t *testing.T) {
	pub, priv := newKeyPair(t)

	handler := acpapi.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acpapi.WriteSuccess(w, r, http.StatusOK, map[string]string{"balance": "1000"}, priv)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-ACP-Request-ID", "tamper-test")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var resp acpapi.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Tamper with data.
	resp.Data = map[string]string{"balance": "9999999"}

	if err := acpapi.VerifyResponseSig(resp, pub); err == nil {
		t.Error("expected signature verification to fail after data tampering, but it passed")
	}
}

func TestWriteSuccess_TimestampIsRecent(t *testing.T) {
	handler := acpapi.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acpapi.WriteSuccess(w, r, http.StatusOK, nil, nil)
	}))

	before := time.Now().Unix()
	w := doReq(t, handler, http.MethodGet, "/test")
	after := time.Now().Unix()

	var resp acpapi.Response
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Timestamp < before || resp.Timestamp > after {
		t.Errorf("timestamp %d not in range [%d, %d]", resp.Timestamp, before, after)
	}
}

// ─── WriteError ───────────────────────────────────────────────────────────────

func TestWriteError_Envelope(t *testing.T) {
	handler := acpapi.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acpapi.WriteError(w, r, http.StatusNotFound, acpapi.ErrAGENT005, "agent not found")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-ACP-Request-ID", "err-req-id")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}

	var resp acpapi.ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if resp.ACPVersion != "1.0" {
		t.Errorf("acp_version = %q, want %q", resp.ACPVersion, "1.0")
	}
	if resp.RequestID != "err-req-id" {
		t.Errorf("request_id = %q, want %q", resp.RequestID, "err-req-id")
	}
	if resp.Error.Code != acpapi.ErrAGENT005 {
		t.Errorf("error.code = %q, want %q", resp.Error.Code, acpapi.ErrAGENT005)
	}
	if resp.Error.Message != "agent not found" {
		t.Errorf("error.message = %q, want %q", resp.Error.Message, "agent not found")
	}
}

func TestWriteError_NoSigField(t *testing.T) {
	handler := acpapi.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acpapi.WriteError(w, r, http.StatusBadRequest, acpapi.ErrSYS004, "bad request")
	}))
	w := doReq(t, handler, http.MethodPost, "/test")

	// Decode as raw map to verify absence of "sig" field.
	var raw map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&raw); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	if _, hasSig := raw["sig"]; hasSig {
		t.Error("error responses MUST NOT include sig field (per ACP-API-1.0 §3)")
	}
}

func TestWriteError_AllCodes(t *testing.T) {
	codes := []struct {
		code   string
		status int
	}{
		{acpapi.ErrHP004, http.StatusBadRequest},
		{acpapi.ErrHP007, http.StatusUnauthorized},
		{acpapi.ErrHP009, http.StatusUnauthorized},
		{acpapi.ErrHP010, http.StatusUnauthorized},
		{acpapi.ErrHP014, http.StatusBadRequest},
		{acpapi.ErrAUTH001, http.StatusUnauthorized},
		{acpapi.ErrAUTH002, http.StatusForbidden},
		{acpapi.ErrAUTH003, http.StatusForbidden},
		{acpapi.ErrAUTH004, http.StatusBadRequest},
		{acpapi.ErrAUTH005, http.StatusForbidden},
		{acpapi.ErrAUTH006, http.StatusUnauthorized},
		{acpapi.ErrAUTH007, http.StatusUnauthorized},
		{acpapi.ErrAUTH008, http.StatusForbidden},
		{acpapi.ErrAGENT001, http.StatusBadRequest},
		{acpapi.ErrAGENT002, http.StatusBadRequest},
		{acpapi.ErrAGENT003, http.StatusBadRequest},
		{acpapi.ErrAGENT004, http.StatusConflict},
		{acpapi.ErrAGENT005, http.StatusNotFound},
		{acpapi.ErrSTATE001, http.StatusBadRequest},
		{acpapi.ErrSTATE002, http.StatusBadRequest},
		{acpapi.ErrAUDIT001, http.StatusInternalServerError},
		{acpapi.ErrSYS001, http.StatusServiceUnavailable},
		{acpapi.ErrSYS002, http.StatusServiceUnavailable},
		{acpapi.ErrSYS003, http.StatusServiceUnavailable},
		{acpapi.ErrSYS004, http.StatusBadRequest},
		{acpapi.ErrSYS005, http.StatusGatewayTimeout},
	}

	for _, tc := range codes {
		if tc.code == "" {
			t.Errorf("empty error code constant")
			continue
		}
		// Verify code format: "<PREFIX>-<NUM>"
		if !strings.Contains(tc.code, "-") {
			t.Errorf("error code %q must contain a hyphen (e.g. AUTH-001)", tc.code)
		}
	}

	// Write all codes through the handler and confirm valid JSON.
	for _, tc := range codes {
		handler := acpapi.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			acpapi.WriteError(w, r, tc.status, tc.code, "test error")
		}))
		w := doReq(t, handler, http.MethodGet, "/test")

		var resp acpapi.ErrorResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Errorf("code %s: decode error: %v", tc.code, err)
			continue
		}
		if resp.Error.Code != tc.code {
			t.Errorf("code %s: got code %q in body", tc.code, resp.Error.Code)
		}
	}
}

// ─── Response Signing Edge Cases ──────────────────────────────────────────────

func TestVerifyResponseSig_WrongKey(t *testing.T) {
	_, priv := newKeyPair(t)
	wrongPub, _ := newKeyPair(t)

	resp := acpapi.Response{
		ACPVersion: "1.0",
		RequestID:  "test-id",
		Timestamp:  time.Now().Unix(),
		Data:       map[string]string{"x": "y"},
	}

	// Build the handler to get a properly signed response.
	handler := acpapi.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acpapi.WriteSuccess(w, r, http.StatusOK, resp.Data, priv)
	}))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-ACP-Request-ID", "test-id")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var got acpapi.Response
	if err := json.NewDecoder(w.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Verify with the wrong public key — should fail.
	if err := acpapi.VerifyResponseSig(got, wrongPub); err == nil {
		t.Error("expected verification to fail with wrong public key")
	}
}

func TestVerifyResponseSig_EmptySig(t *testing.T) {
	pub, _ := newKeyPair(t)
	resp := acpapi.Response{
		ACPVersion: "1.0",
		RequestID:  "test",
		Timestamp:  time.Now().Unix(),
		Data:       nil,
		Sig:        "", // no sig
	}
	if err := acpapi.VerifyResponseSig(resp, pub); err == nil {
		t.Error("expected error with empty sig, got nil")
	}
}

// ─── GetRequestID ─────────────────────────────────────────────────────────────

func TestGetRequestID_NoMiddleware(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	if id := acpapi.GetRequestID(req); id != "" {
		t.Errorf("expected empty string without middleware, got %q", id)
	}
}

// ─── Middleware Headers Present on Error ─────────────────────────────────────

func TestMiddleware_HeadersOnError(t *testing.T) {
	handler := acpapi.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acpapi.WriteError(w, r, http.StatusInternalServerError, acpapi.ErrSYS001, "test error")
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-ACP-Request-ID", "err-headers-test")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if got := w.Header().Get("X-ACP-Version"); got != "1.0" {
		t.Errorf("X-ACP-Version on error = %q, want %q", got, "1.0")
	}
	if got := w.Header().Get("X-ACP-Request-ID"); got != "err-headers-test" {
		t.Errorf("X-ACP-Request-ID on error = %q, want %q", got, "err-headers-test")
	}
}
