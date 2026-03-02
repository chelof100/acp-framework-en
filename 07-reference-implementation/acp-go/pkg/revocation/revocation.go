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
// compatible HTTP endpoint.
//
// The endpoint is called with:
//   GET <rev.uri>?nonce=<tokenNonce>
//
// Expected response:
//   {"revoked": false} or {"revoked": true, "reason": "..."}
type HTTPRevocationChecker struct {
	client  *http.Client
	timeout time.Duration
}

// NewHTTPRevocationChecker creates a new HTTP revocation checker.
func NewHTTPRevocationChecker(timeout time.Duration) *HTTPRevocationChecker {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &HTTPRevocationChecker{
		client:  &http.Client{Timeout: timeout},
		timeout: timeout,
	}
}

// revocationResponse is the expected JSON body from the revocation endpoint.
type revocationResponse struct {
	Revoked bool   `json:"revoked"`
	Reason  string `json:"reason,omitempty"`
}

// IsRevoked queries the ACP-REV-1.0 endpoint defined in the token's rev field.
// Returns (true, nil) if revoked, (false, nil) if not revoked,
// or (false, error) if the check itself failed.
func (c *HTTPRevocationChecker) IsRevoked(tokenNonce string, rev *tokens.Revocation) (bool, error) {
	if rev == nil {
		return false, nil
	}
	if rev.Type != "endpoint" {
		// CRL-type revocation not yet implemented; fail open for CRL.
		// In production, implement CRL checking or fail closed.
		return false, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	url := fmt.Sprintf("%s?nonce=%s", rev.URI, tokenNonce)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrRevocationCheckFailed, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrRevocationCheckFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("%w: status %d", ErrRevocationCheckFailed, resp.StatusCode)
	}

	var result revocationResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("%w: decoding response: %v", ErrRevocationCheckFailed, err)
	}

	return result.Revoked, nil
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
