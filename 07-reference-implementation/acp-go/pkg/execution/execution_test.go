package execution_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/execution"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

func mustGenKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}
	return pub, priv
}

func issueReq(agentID, authID, cap, resource string) execution.IssueRequest {
	return execution.IssueRequest{
		AgentID:          agentID,
		AuthorizationID:  authID,
		Capability:       cap,
		Resource:         resource,
		ActionParameters: map[string]interface{}{"amount": 100.0},
	}
}

// ─── Issue ────────────────────────────────────────────────────────────────────

func TestIssue_DevMode_NoSig(t *testing.T) {
	req := issueReq("agent-1", "auth-abc", "acp:cap:data.read", "db://users")
	tok, err := execution.Issue(req, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok.Ver != "1.0" {
		t.Errorf("ver=%q want 1.0", tok.Ver)
	}
	if tok.ETID == "" {
		t.Error("et_id is empty")
	}
	if tok.Sig != "" {
		t.Errorf("sig should be empty in dev mode, got %q", tok.Sig)
	}
	if tok.Used {
		t.Error("new token should not be used")
	}
}

func TestIssue_WithKey_HasSig(t *testing.T) {
	_, priv := mustGenKey(t)
	req := issueReq("agent-2", "auth-xyz", "acp:cap:data.read", "db://table")
	tok, err := execution.Issue(req, priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok.Sig == "" {
		t.Error("sig should be set when private key is provided")
	}
}

func TestIssue_Fields(t *testing.T) {
	req := issueReq("a1", "z1", "acp:cap:financial.payment", "bank://account")
	tok, err := execution.Issue(req, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if tok.AgentID != req.AgentID {
		t.Errorf("agent_id=%q want %q", tok.AgentID, req.AgentID)
	}
	if tok.AuthorizationID != req.AuthorizationID {
		t.Errorf("authorization_id=%q want %q", tok.AuthorizationID, req.AuthorizationID)
	}
	if tok.Capability != req.Capability {
		t.Errorf("capability=%q want %q", tok.Capability, req.Capability)
	}
	if tok.Resource != req.Resource {
		t.Errorf("resource=%q want %q", tok.Resource, req.Resource)
	}
	if tok.ActionParametersHash == "" {
		t.Error("action_parameters_hash is empty")
	}
}

func TestIssue_Window_Financial(t *testing.T) {
	req := issueReq("a1", "z1", "acp:cap:financial.payment", "bank://account")
	before := time.Now().Unix()
	tok, err := execution.Issue(req, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	window := tok.ExpiresAt - tok.IssuedAt
	if window != 60 {
		t.Errorf("financial window=%d want 60", window)
	}
	if tok.IssuedAt < before {
		t.Errorf("issued_at=%d before test start=%d", tok.IssuedAt, before)
	}
}

func TestIssue_Window_InfraDelete(t *testing.T) {
	req := issueReq("a1", "z1", "acp:cap:infrastructure.delete", "k8s://pod")
	tok, err := execution.Issue(req, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	window := tok.ExpiresAt - tok.IssuedAt
	if window != 30 {
		t.Errorf("infra.delete window=%d want 30", window)
	}
}

func TestIssue_Window_InfraDeploy(t *testing.T) {
	req := issueReq("a1", "z1", "acp:cap:infrastructure.deploy", "k8s://deploy")
	tok, err := execution.Issue(req, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	window := tok.ExpiresAt - tok.IssuedAt
	if window != 120 {
		t.Errorf("infra.deploy window=%d want 120", window)
	}
}

func TestIssue_Window_Read(t *testing.T) {
	req := issueReq("a1", "z1", "acp:cap:data.read", "db://table")
	tok, err := execution.Issue(req, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	window := tok.ExpiresAt - tok.IssuedAt
	if window != 300 {
		t.Errorf("read window=%d want 300", window)
	}
}

func TestIssue_Window_Default(t *testing.T) {
	req := issueReq("a1", "z1", "acp:cap:something.else", "resource://x")
	tok, err := execution.Issue(req, nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	window := tok.ExpiresAt - tok.IssuedAt
	if window != 120 {
		t.Errorf("default window=%d want 120", window)
	}
}

func TestIssue_UniqueETIDs(t *testing.T) {
	req := issueReq("a1", "z1", "acp:cap:data.read", "r://x")
	ids := make(map[string]bool)
	for i := 0; i < 10; i++ {
		tok, err := execution.Issue(req, nil)
		if err != nil {
			t.Fatalf("Issue %d: %v", i, err)
		}
		if ids[tok.ETID] {
			t.Errorf("duplicate et_id: %s", tok.ETID)
		}
		ids[tok.ETID] = true
	}
}

// ─── VerifyToken ──────────────────────────────────────────────────────────────

func TestVerifyToken_OK(t *testing.T) {
	pub, priv := mustGenKey(t)
	tok, err := execution.Issue(issueReq("a1", "z1", "acp:cap:data.read", "r://x"), priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := execution.VerifyToken(tok, pub); err != nil {
		t.Errorf("VerifyToken: %v", err)
	}
}

func TestVerifyToken_WrongKey(t *testing.T) {
	_, priv := mustGenKey(t)
	pub2, _ := mustGenKey(t)
	tok, err := execution.Issue(issueReq("a1", "z1", "acp:cap:data.read", "r://x"), priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := execution.VerifyToken(tok, pub2); err == nil {
		t.Error("expected error with wrong public key")
	}
}

func TestVerifyToken_EmptySig(t *testing.T) {
	pub, _ := mustGenKey(t)
	tok, err := execution.Issue(issueReq("a1", "z1", "acp:cap:data.read", "r://x"), nil)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// sig is empty (dev mode)
	if err := execution.VerifyToken(tok, pub); err == nil {
		t.Error("expected ErrInvalidSignature for empty sig")
	}
}

func TestVerifyToken_UnsupportedVersion(t *testing.T) {
	pub, priv := mustGenKey(t)
	tok, err := execution.Issue(issueReq("a1", "z1", "acp:cap:data.read", "r://x"), priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tok.Ver = "2.0" // tamper
	if err := execution.VerifyToken(tok, pub); err == nil {
		t.Error("expected ErrUnsupportedVersion")
	}
}

func TestVerifyToken_TamperedField(t *testing.T) {
	pub, priv := mustGenKey(t)
	tok, err := execution.Issue(issueReq("a1", "z1", "acp:cap:data.read", "r://x"), priv)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tok.AgentID = "tampered-agent" // tamper
	if err := execution.VerifyToken(tok, pub); err == nil {
		t.Error("expected ErrInvalidSignature after tampering agent_id")
	}
}

// ─── HashActionParameters ─────────────────────────────────────────────────────

func TestHashActionParameters_Nil(t *testing.T) {
	h, err := execution.HashActionParameters(nil)
	if err != nil {
		t.Fatalf("HashActionParameters(nil): %v", err)
	}
	if h == "" {
		t.Error("expected non-empty hash for nil params")
	}
}

func TestHashActionParameters_Deterministic(t *testing.T) {
	params := map[string]interface{}{"amount": 100.0, "currency": "USD"}
	h1, _ := execution.HashActionParameters(params)
	h2, _ := execution.HashActionParameters(params)
	if h1 != h2 {
		t.Errorf("hash not deterministic: %q vs %q", h1, h2)
	}
}

func TestHashActionParameters_DifferentInputs(t *testing.T) {
	h1, _ := execution.HashActionParameters(map[string]interface{}{"a": 1.0})
	h2, _ := execution.HashActionParameters(map[string]interface{}{"a": 2.0})
	if h1 == h2 {
		t.Error("different inputs produced same hash")
	}
}

func TestHashActionParameters_KeyOrderIndependent(t *testing.T) {
	// JCS canonicalizes key order — hashes must match regardless of insertion order.
	h1, _ := execution.HashActionParameters(map[string]interface{}{"a": "x", "b": "y"})
	h2, _ := execution.HashActionParameters(map[string]interface{}{"b": "y", "a": "x"})
	if h1 != h2 {
		t.Errorf("JCS should normalize key order but hashes differ: %q vs %q", h1, h2)
	}
}

// ─── InMemoryETRegistry ───────────────────────────────────────────────────────

func TestRegistry_RegisterAndGet(t *testing.T) {
	reg := execution.NewInMemoryETRegistry()
	tok, _ := execution.Issue(issueReq("a1", "z1", "acp:cap:data.read", "r://x"), nil)

	if err := reg.Register(tok); err != nil {
		t.Fatalf("Register: %v", err)
	}

	entry, err := reg.Get(tok.ETID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.ETID != tok.ETID {
		t.Errorf("et_id mismatch: %q vs %q", entry.ETID, tok.ETID)
	}
	if entry.State != execution.StateIssued {
		t.Errorf("state=%q want issued", entry.State)
	}
}

func TestRegistry_RegisterDuplicate(t *testing.T) {
	reg := execution.NewInMemoryETRegistry()
	tok, _ := execution.Issue(issueReq("a1", "z1", "acp:cap:data.read", "r://x"), nil)
	_ = reg.Register(tok)

	if err := reg.Register(tok); err == nil {
		t.Error("expected error on duplicate registration")
	}
}

func TestRegistry_GetNotFound(t *testing.T) {
	reg := execution.NewInMemoryETRegistry()
	_, err := reg.Get("nonexistent-id")
	if err == nil {
		t.Error("expected ErrTokenNotFound")
	}
}

func TestRegistry_ConsumeSuccess(t *testing.T) {
	reg := execution.NewInMemoryETRegistry()
	tok, _ := execution.Issue(issueReq("a1", "z1", "acp:cap:data.read", "r://x"), nil)
	_ = reg.Register(tok)

	consumedAt := time.Now().Unix()
	if err := reg.Consume(tok.ETID, "system-A", consumedAt); err != nil {
		t.Fatalf("Consume: %v", err)
	}

	entry, _ := reg.Get(tok.ETID)
	if entry.State != execution.StateUsed {
		t.Errorf("state=%q want used", entry.State)
	}
	if entry.ConsumedAt == nil || *entry.ConsumedAt != consumedAt {
		t.Errorf("consumed_at mismatch")
	}
	if entry.ConsumedBySystem == nil || *entry.ConsumedBySystem != "system-A" {
		t.Errorf("consumed_by_system mismatch")
	}
}

func TestRegistry_ConsumeAlreadyUsed(t *testing.T) {
	reg := execution.NewInMemoryETRegistry()
	tok, _ := execution.Issue(issueReq("a1", "z1", "acp:cap:data.read", "r://x"), nil)
	_ = reg.Register(tok)
	_ = reg.Consume(tok.ETID, "sys", time.Now().Unix())

	err := reg.Consume(tok.ETID, "sys", time.Now().Unix())
	if err == nil {
		t.Error("expected ErrTokenAlreadyConsumed on second consume")
	}
}

func TestRegistry_ConsumeNotFound(t *testing.T) {
	reg := execution.NewInMemoryETRegistry()
	err := reg.Consume("no-such-id", "sys", time.Now().Unix())
	if err == nil {
		t.Error("expected ErrTokenNotFound")
	}
}

func TestRegistry_GetExpired(t *testing.T) {
	reg := execution.NewInMemoryETRegistry()
	// Manually craft a token that is already expired.
	tok := execution.Token{
		Ver:                  "1.0",
		ETID:                 "expired-token-1",
		AgentID:              "a1",
		AuthorizationID:      "z1",
		Capability:           "acp:cap:data.read",
		Resource:             "r://x",
		ActionParametersHash: "abc",
		IssuedAt:             time.Now().Unix() - 400,
		ExpiresAt:            time.Now().Unix() - 100, // expired 100s ago
	}
	_ = reg.Register(tok)

	entry, err := reg.Get(tok.ETID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.State != execution.StateExpired {
		t.Errorf("state=%q want expired", entry.State)
	}
}

func TestRegistry_ConsumeExpired(t *testing.T) {
	reg := execution.NewInMemoryETRegistry()
	tok := execution.Token{
		Ver:                  "1.0",
		ETID:                 "expired-consume-1",
		AgentID:              "a1",
		AuthorizationID:      "z1",
		Capability:           "acp:cap:data.read",
		Resource:             "r://x",
		ActionParametersHash: "abc",
		IssuedAt:             time.Now().Unix() - 400,
		ExpiresAt:            time.Now().Unix() - 100,
	}
	_ = reg.Register(tok)

	err := reg.Consume(tok.ETID, "sys", time.Now().Unix())
	if err == nil {
		t.Error("expected ErrTokenExpired on expired token")
	}
}

func TestRegistry_Size(t *testing.T) {
	reg := execution.NewInMemoryETRegistry()
	if reg.Size() != 0 {
		t.Errorf("empty registry size=%d want 0", reg.Size())
	}

	for i := 0; i < 3; i++ {
		req := issueReq("a1", "z1", "acp:cap:data.read", "r://x")
		tok, _ := execution.Issue(req, nil)
		_ = reg.Register(tok)
	}
	if reg.Size() != 3 {
		t.Errorf("size=%d want 3", reg.Size())
	}
}

func TestRegistry_Prune(t *testing.T) {
	reg := execution.NewInMemoryETRegistry()

	// Register one old USED token (>30 days).
	old := execution.Token{
		Ver:                  "1.0",
		ETID:                 "old-used-1",
		AgentID:              "a1",
		AuthorizationID:      "z1",
		Capability:           "acp:cap:data.read",
		Resource:             "r://x",
		ActionParametersHash: "abc",
		IssuedAt:             time.Now().Unix() - 32*24*3600,
		ExpiresAt:            time.Now().Unix() - 31*24*3600, // expired >30d ago
	}
	_ = reg.Register(old)
	// Mark as used manually by consuming (it's already expired, won't consume).
	// Instead, just let prune check ExpiresAt; an expired entry older than 30d is pruned.

	// Register a fresh token.
	fresh, _ := execution.Issue(issueReq("a2", "z2", "acp:cap:data.read", "r://y"), nil)
	_ = reg.Register(fresh)

	if reg.Size() != 2 {
		t.Fatalf("pre-prune size=%d want 2", reg.Size())
	}

	pruned := reg.Prune()
	if pruned != 1 {
		t.Errorf("pruned=%d want 1", pruned)
	}
	if reg.Size() != 1 {
		t.Errorf("post-prune size=%d want 1", reg.Size())
	}
}

func TestRegistry_MaxWindowSeconds(t *testing.T) {
	if execution.MaxWindowSeconds != 300 {
		t.Errorf("MaxWindowSeconds=%d want 300", execution.MaxWindowSeconds)
	}
}
