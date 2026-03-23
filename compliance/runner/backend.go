package main

// Backend is the interface the runner uses to evaluate requests.
//
// Two implementations are provided:
//   - LibraryBackend: calls pkg/risk directly (library mode, default)
//   - HTTPBackend: posts requests to an external ACP server (HTTP mode)
type Backend interface {
	// Evaluate submits a request and returns the engine decision.
	Evaluate(req RunnerRequest) (ACPResponse, error)
	// Reset clears accumulated state between test cases.
	Reset()
}
