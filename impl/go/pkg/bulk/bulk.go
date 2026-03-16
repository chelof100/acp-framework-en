// Package bulk implements ACP-BULK-1.0 (batch authorization + bulk liability query).
//
// Provides request validation for batch authorization operations and bulk
// liability queries. This is a pass-through layer — no in-memory store.
package bulk

import (
	"errors"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	// MaxBatchItems is the maximum number of items allowed in a single batch request.
	MaxBatchItems = 100

	// MaxLiabilityPageSize is the maximum Limit value for a liability query.
	MaxLiabilityPageSize = 1000
)

// ─── Error Sentinels (ACP-BULK-1.0) ──────────────────────────────────────────

var (
	ErrBatchTooLarge      = errors.New("BULK-001: batch exceeds 100 items")
	ErrRateLimitExceeded  = errors.New("BULK-002: rate limit exceeded")
	ErrPartialFailure     = errors.New("BULK-003: one or more requests in batch failed")
	ErrQueryTooLarge      = errors.New("BULK-004: query result set too large, reduce limit")
	ErrEmptyBatch         = errors.New("BULK-005: batch must contain at least one item")
)

// ─── Types ────────────────────────────────────────────────────────────────────

// BatchItem represents a single authorization request within a batch.
type BatchItem struct {
	RequestID  string                 `json:"request_id"`
	AgentID    string                 `json:"agent_id"`
	ActionType string                 `json:"action_type"`
	Resource   string                 `json:"resource"`
	Context    map[string]interface{} `json:"context"`
}

// BatchRequest is a collection of authorization requests processed together.
type BatchRequest struct {
	BatchID string      `json:"batch_id"`
	Items   []BatchItem `json:"items"`
}

// ItemResult holds the authorization decision for a single BatchItem.
type ItemResult struct {
	RequestID  string   `json:"request_id"`
	Decision   string   `json:"decision"`    // "APPROVED" | "DENIED" | "ESCALATED"
	RiskScore  *float64 `json:"risk_score"`  // nil if not applicable
	ReasonCode string   `json:"reason_code"`
}

// BatchResponse summarizes the outcome of a BatchRequest.
type BatchResponse struct {
	BatchID        string       `json:"batch_id"`
	Processed      int          `json:"processed"`
	PartialFailure bool         `json:"partial_failure"`
	Results        []ItemResult `json:"results"`
}

// LiabilityQueryRequest defines the parameters for a bulk liability query.
type LiabilityQueryRequest struct {
	QueryID  string   `json:"query_id"`
	AgentIDs []string `json:"agent_ids"`
	FromTS   int64    `json:"from_ts"`
	ToTS     int64    `json:"to_ts"`
	Limit    int      `json:"limit"`
	Cursor   string   `json:"cursor"`
}

// LiabilityRecord is a single liability record returned by a bulk query.
type LiabilityRecord struct {
	LiabilityID       string `json:"liability_id"`
	ETID              string `json:"et_id"`
	AgentID           string `json:"agent_id"`
	Capability        string `json:"capability"`
	Resource          string `json:"resource"`
	ExecutionResult   string `json:"execution_result"`
	ExecutedAt        int64  `json:"executed_at"`
	LiabilityAssignee string `json:"liability_assignee"`
}

// LiabilityQueryResponse is the paginated result of a LiabilityQueryRequest.
type LiabilityQueryResponse struct {
	QueryID    string            `json:"query_id"`
	Total      int               `json:"total"`
	NextCursor string            `json:"next_cursor"`
	Records    []LiabilityRecord `json:"records"`
}

// ─── Core Functions ───────────────────────────────────────────────────────────

// ValidateBatchRequest returns ErrEmptyBatch if the batch is empty and
// ErrBatchTooLarge if it exceeds MaxBatchItems.
func ValidateBatchRequest(req BatchRequest) error {
	if len(req.Items) == 0 {
		return ErrEmptyBatch
	}
	if len(req.Items) > MaxBatchItems {
		return ErrBatchTooLarge
	}
	return nil
}

// NewBatchResponse assembles a BatchResponse from a BatchRequest and its results.
// PartialFailure is set to true if any result carries Decision=="DENIED".
func NewBatchResponse(req BatchRequest, results []ItemResult) BatchResponse {
	partial := false
	for _, r := range results {
		if r.Decision == "DENIED" {
			partial = true
			break
		}
	}
	return BatchResponse{
		BatchID:        req.BatchID,
		Processed:      len(results),
		PartialFailure: partial,
		Results:        results,
	}
}

// ValidateLiabilityQuery returns ErrQueryTooLarge if Limit exceeds MaxLiabilityPageSize.
func ValidateLiabilityQuery(req LiabilityQueryRequest) error {
	if req.Limit > MaxLiabilityPageSize {
		return ErrQueryTooLarge
	}
	return nil
}
