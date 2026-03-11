// Package revocation implements ACP-REV-1.0 revocation checking.
// Provides two checker implementations:
//   - NoOpRevocationChecker: always returns not-revoked (testing/dev)
//   - HTTPRevocationChecker: calls a remote ACP-REV-1.0 endpoint
package revocation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/tokens"
)

// ─── Errors ───────────────────────────────────────────────────────────────────

var (
	ErrRevocationCheckFailed = errors.New("acp/revocation: endpoint check failed")
	ErrRevoked               = errors.New("acp/revocation: token is revoked")
)

// ─── NoOp (Testing) ───────────────────────────────────────────────────────────

// NoOpRevocationChecker always returns "not revoked".
// Use ONLY for testing and local development.
type NoOpRevocationChecker struct{}

// IsRevoked always returns false, nil.
func (n *NoOpRevocationChecker) IsRevoked(_ string, _ *tokens.Revocation) (bool, error) {
	return false, nil
}

// ─── HTTP Endpoint Checker (ACP-REV-1.0 §endpoint) ───────────────────────────

// HTTPRevocationChecker checks revocation status by calling an ACP-REV-1.0
// compatible HTTP endpoint (GET /acp/v1/rev/check).
//
// Request format (ACP-REV-1.0 §3.1):
//
//	GET <rev.URI>?token_id=<tokenNonce>
//	Accept: application/json
//
// Response format:
//
//	200 {"token_id":"...","status":"active"|"revoked","checked_at":...}
//	404 → token not found in store, treat as revoked (fail-closed per spec)
//	503 → endpoint offline; behaviour depends on OfflinePolicy
type HTTPRevocationChecker struct {
	client        *http.Client
	timeout       time.Duration
	OfflinePolicy OfflinePolicy
}

// OfflinePolicy controls what happens when the revocation endpoint is unreachable.
type OfflinePolicy int

const (
	// OfflineDeny rejects the token when the revocation endpoint is unreachable.
	// This is the secure default: unknown = denied.
	OfflineDeny OfflinePolicy = iota

	// OfflineAllow allows the token when the endpoint is unreachable.
	// Use only in environments where availability takes priority over security.
	OfflineAllow
)

// NewHTTPRevocationChecker creates an HTTP revocation checker with the given timeout.
// Default offline policy is OfflineDeny (fail-closed).
func NewHTTPRevocationChecker(timeout time.Duration) *HTTPRevocationChecker {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &HTTPRevocationChecker{
		client:        &http.Client{Timeout: timeout},
		timeout:       timeout,
		OfflinePolicy: OfflineDeny,
	}
}

// revCheckResponse is the expected JSON body from GET /acp/v1/rev/check.
type revCheckResponse struct {
	TokenID   string `json:"token_id"`
	Status    string `json:"status"`     // "active" or "revoked"
	CheckedAt int64  `json:"checked_at"`
}

// IsRevoked queries the ACP-REV-1.0 endpoint defined in the token's rev field.
//
// Status mapping:
//   - 200 + status="revoked" → (true, nil)
//   - 200 + status="active"  → (false, nil)
//   - 404                    → (true, nil)  — token unknown = treat as revoked
//   - 503 or network error   → depends on OfflinePolicy
func (c *HTTPRevocationChecker) IsRevoked(tokenNonce string, rev *tokens.Revocation) (bool, error) {
	if rev == nil {
		return false, nil
	}
	if rev.Type != "endpoint" {
		// CRL revocation not implemented in v1; fail open for CRL type.
		return false, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	url := fmt.Sprintf("%s?token_id=%s", rev.URI, tokenNonce)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return c.offlineResult()
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return c.offlineResult()
	}
	defer resp.Body.Close()

	// 404 = token not in store → treat as revoked (fail-closed).
	if resp.StatusCode == http.StatusNotFound {
		return true, nil
	}

	// 5xx or unexpected status = endpoint offline/broken.
	if resp.StatusCode != http.StatusOK {
		return c.offlineResult()
	}

	var result revCheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("%w: decoding response: %v", ErrRevocationCheckFailed, err)
	}

	return result.Status == "revoked", nil
}

func (c *HTTPRevocationChecker) offlineResult() (bool, error) {
	if c.OfflinePolicy == OfflineDeny {
		return true, fmt.Errorf("%w: endpoint unreachable (offline policy: deny)", ErrRevocationCheckFailed)
	}
	return false, nil
}

// ─── In-Memory Revocation List (Testing) ─────────────────────────────────────

// InMemoryRevocationChecker maintains an in-memory list of revoked nonces.
// Useful for integration tests where you want to test revocation paths.
type InMemoryRevocationChecker struct {
	revoked map[string]string // nonce → reason
}

// NewInMemoryRevocationChecker creates an empty in-memory revocation list.
func NewInMemoryRevocationChecker() *InMemoryRevocationChecker {
	return &InMemoryRevocationChecker{
		revoked: make(map[string]string),
	}
}

// Revoke marks a token nonce as revoked with an optional reason.
func (r *InMemoryRevocationChecker) Revoke(nonce, reason string) {
	r.revoked[nonce] = reason
}

// IsRevoked returns true if the nonce is in the revocation list.
func (r *InMemoryRevocationChecker) IsRevoked(tokenNonce string, _ *tokens.Revocation) (bool, error) {
	_, revoked := r.revoked[tokenNonce]
	return revoked, nil
}
