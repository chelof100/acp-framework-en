package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// HTTPBackend evaluates requests by posting to an external ACP server.
//
// Limitations:
//   - Reset is a no-op; the server must be stateless or provide a /reset endpoint.
//   - State accumulation across steps is the server's responsibility.
//   - Sequence tests involving cooldown or F_anom Rule 3 require a stateful server.
type HTTPBackend struct {
	url string
}

// NewHTTPBackend returns an HTTPBackend targeting the given admission URL.
func NewHTTPBackend(url string) *HTTPBackend {
	return &HTTPBackend{url: url}
}

// Reset is a no-op for HTTP mode.
func (b *HTTPBackend) Reset() {}

// Evaluate posts the request to the configured URL and decodes the response.
func (b *HTTPBackend) Evaluate(req RunnerRequest) (ACPResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return ACPResponse{}, fmt.Errorf("marshal request: %w", err)
	}

	resp, err := http.Post(b.url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return ACPResponse{}, fmt.Errorf("POST %s: %w", b.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ACPResponse{}, fmt.Errorf("server returned %d", resp.StatusCode)
	}

	var result ACPResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ACPResponse{}, fmt.Errorf("decode response: %w", err)
	}
	return result, nil
}
