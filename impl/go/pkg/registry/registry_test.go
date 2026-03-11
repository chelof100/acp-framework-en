package registry_test

import (
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"

	"github.com/chelof100/acp-framework/acp-go/pkg/registry"
)

// testPubKey generates a deterministic Ed25519 public key from a seed byte.
func testPubKey(seed byte) ed25519.PublicKey {
	s := make([]byte, ed25519.SeedSize)
	s[0] = seed
	pub, _, _ := ed25519.GenerateKey(nil)
	_ = pub
	sk := ed25519.NewKeyFromSeed(s)
	return sk.Public().(ed25519.PublicKey)
}

func newReg() *registry.InMemoryRegistry {
	return registry.NewInMemoryRegistry()
}

// ─── Register / GetPublicKey ──────────────────────────────────────────────────

func TestRegister_GetPublicKey(t *testing.T) {
	r := newReg()
	pub := testPubKey(1)

	if err := r.Register("agent-1", pub); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetPublicKey("agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Fatal("public key mismatch")
	}
}

func TestRegister_EmptyAgentID(t *testing.T) {
	r := newReg()
	if err := r.Register("", testPubKey(2)); err == nil {
		t.Fatal("expected error for empty agentID")
	}
}

func TestRegister_InvalidKeyLength(t *testing.T) {
	r := newReg()
	if err := r.Register("agent-x", ed25519.PublicKey([]byte{1, 2, 3})); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestGetPublicKey_NotFound(t *testing.T) {
	r := newReg()
	_, err := r.GetPublicKey("nobody")
	if !errors.Is(err, registry.ErrAgentNotFound) {
		t.Fatalf("want ErrAgentNotFound, got %v", err)
	}
}

// ─── RegisterFull / GetRecord ─────────────────────────────────────────────────

func makeRecord(agentID string, seed byte) registry.AgentRecord {
	return registry.AgentRecord{
		AgentID:         agentID,
		PublicKey:       testPubKey(seed),
		InstitutionID:   "inst-001",
		AutonomyLevel:   2,
		AuthorityDomain: "finance",
		Status:          registry.StatusActive,
	}
}

func TestRegisterFull_GetRecord(t *testing.T) {
	r := newReg()
	rec := makeRecord("agent-full-1", 10)

	if err := r.RegisterFull(rec); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetRecord("agent-full-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.AgentID != rec.AgentID {
		t.Fatalf("agent_id mismatch: %q vs %q", got.AgentID, rec.AgentID)
	}
	if !got.PublicKey.Equal(rec.PublicKey) {
		t.Fatal("public key mismatch after RegisterFull")
	}
	if got.Status != registry.StatusActive {
		t.Fatalf("expected active, got %q", got.Status)
	}
}

func TestRegisterFull_GetPublicKey_UsesRecord(t *testing.T) {
	r := newReg()
	rec := makeRecord("agent-full-2", 11)
	if err := r.RegisterFull(rec); err != nil {
		t.Fatal(err)
	}
	got, err := r.GetPublicKey("agent-full-2")
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(rec.PublicKey) {
		t.Fatal("GetPublicKey should use records store")
	}
}

func TestRegisterFull_DuplicateReturnsError(t *testing.T) {
	r := newReg()
	rec := makeRecord("agent-dup", 12)
	if err := r.RegisterFull(rec); err != nil {
		t.Fatal(err)
	}
	err := r.RegisterFull(rec)
	if !errors.Is(err, registry.ErrAgentAlreadyRegistered) {
		t.Fatalf("want ErrAgentAlreadyRegistered, got %v", err)
	}
}

func TestRegisterFull_AlreadyInLegacyStore(t *testing.T) {
	r := newReg()
	pub := testPubKey(13)
	if err := r.Register("agent-legacy", pub); err != nil {
		t.Fatal(err)
	}
	rec := makeRecord("agent-legacy", 13)
	err := r.RegisterFull(rec)
	if !errors.Is(err, registry.ErrAgentAlreadyRegistered) {
		t.Fatalf("want ErrAgentAlreadyRegistered when agentID already in legacy keys map, got %v", err)
	}
}

func TestRegisterFull_InvalidAutonomyLevel(t *testing.T) {
	r := newReg()
	rec := makeRecord("agent-bad-al", 14)
	rec.AutonomyLevel = 5
	if err := r.RegisterFull(rec); err == nil {
		t.Fatal("expected error for autonomy_level > 4")
	}
	rec.AutonomyLevel = -1
	if err := r.RegisterFull(rec); err == nil {
		t.Fatal("expected error for autonomy_level < 0")
	}
}

func TestRegisterFull_DefaultStatus(t *testing.T) {
	r := newReg()
	rec := makeRecord("agent-no-status", 15)
	rec.Status = ""
	if err := r.RegisterFull(rec); err != nil {
		t.Fatal(err)
	}
	got, _ := r.GetRecord("agent-no-status")
	if got.Status != registry.StatusActive {
		t.Fatalf("expected default status active, got %q", got.Status)
	}
}

func TestGetRecord_NotFound(t *testing.T) {
	r := newReg()
	_, err := r.GetRecord("nobody")
	if !errors.Is(err, registry.ErrAgentNotFound) {
		t.Fatalf("want ErrAgentNotFound, got %v", err)
	}
}

// ─── UpdateStatus / State transitions ─────────────────────────────────────────

func TestUpdateStatus_ValidTransitions(t *testing.T) {
	cases := []struct {
		name string
		from registry.AgentStatus
		to   registry.AgentStatus
	}{
		{"active→restricted", registry.StatusActive, registry.StatusRestricted},
		{"active→suspended", registry.StatusActive, registry.StatusSuspended},
		{"active→revoked", registry.StatusActive, registry.StatusRevoked},
		{"restricted→active", registry.StatusRestricted, registry.StatusActive},
		{"restricted→suspended", registry.StatusRestricted, registry.StatusSuspended},
		{"restricted→revoked", registry.StatusRestricted, registry.StatusRevoked},
		{"suspended→active", registry.StatusSuspended, registry.StatusActive},
		{"suspended→revoked", registry.StatusSuspended, registry.StatusRevoked},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newReg()
			agentID := "agent-transition"
			rec := makeRecord(agentID, byte(20+i))
			rec.Status = tc.from
			if err := r.RegisterFull(rec); err != nil {
				t.Fatal(err)
			}
			if err := r.UpdateStatus(agentID, tc.to); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			got, _ := r.GetRecord(agentID)
			if got.Status != tc.to {
				t.Fatalf("expected %q, got %q", tc.to, got.Status)
			}
		})
	}
}

func TestUpdateStatus_InvalidTransitions(t *testing.T) {
	cases := []struct {
		from registry.AgentStatus
		to   registry.AgentStatus
	}{
		{registry.StatusSuspended, registry.StatusRestricted}, // suspended cannot go to restricted
	}

	for _, tc := range cases {
		t.Run(string(tc.from)+"→"+string(tc.to), func(t *testing.T) {
			r := newReg()
			rec := makeRecord("agent-bad-transition", 30)
			rec.Status = tc.from
			if err := r.RegisterFull(rec); err != nil {
				t.Fatal(err)
			}
			err := r.UpdateStatus("agent-bad-transition", tc.to)
			if !errors.Is(err, registry.ErrInvalidTransition) {
				t.Fatalf("want ErrInvalidTransition, got %v", err)
			}
		})
	}
}

func TestUpdateStatus_FromRevoked_IsTerminal(t *testing.T) {
	r := newReg()
	rec := makeRecord("agent-revoked", 31)
	rec.Status = registry.StatusRevoked
	if err := r.RegisterFull(rec); err != nil {
		t.Fatal(err)
	}

	// Attempt any transition from revoked — all must fail with ErrAgentRevoked.
	for _, next := range []registry.AgentStatus{
		registry.StatusActive,
		registry.StatusRestricted,
		registry.StatusSuspended,
		registry.StatusRevoked,
	} {
		err := r.UpdateStatus("agent-revoked", next)
		if !errors.Is(err, registry.ErrAgentRevoked) {
			t.Fatalf("transition revoked→%s: want ErrAgentRevoked, got %v", next, err)
		}
	}
}

func TestUpdateStatus_AgentNotFound(t *testing.T) {
	r := newReg()
	err := r.UpdateStatus("nobody", registry.StatusSuspended)
	if !errors.Is(err, registry.ErrAgentNotFound) {
		t.Fatalf("want ErrAgentNotFound, got %v", err)
	}
}

// ─── Deregister / Size ────────────────────────────────────────────────────────

func TestDeregister(t *testing.T) {
	r := newReg()
	pub := testPubKey(40)
	if err := r.Register("agent-deregister", pub); err != nil {
		t.Fatal(err)
	}
	r.Deregister("agent-deregister")
	_, err := r.GetPublicKey("agent-deregister")
	if !errors.Is(err, registry.ErrAgentNotFound) {
		t.Fatalf("expected ErrAgentNotFound after deregister, got %v", err)
	}
}

func TestSize(t *testing.T) {
	r := newReg()
	if r.Size() != 0 {
		t.Fatal("empty registry should have size 0")
	}
	_ = r.Register("agent-s1", testPubKey(50))
	_ = r.RegisterFull(makeRecord("agent-s2", 51))
	if r.Size() != 2 {
		t.Fatalf("expected size 2, got %d", r.Size())
	}
	r.Deregister("agent-s1")
	if r.Size() != 1 {
		t.Fatalf("expected size 1 after deregister, got %d", r.Size())
	}
}

// ─── TouchLastActive ──────────────────────────────────────────────────────────

func TestTouchLastActive(t *testing.T) {
	r := newReg()
	rec := makeRecord("agent-touch", 60)
	rec.LastActiveAt = 1000
	if err := r.RegisterFull(rec); err != nil {
		t.Fatal(err)
	}
	r.TouchLastActive("agent-touch")
	got, _ := r.GetRecord("agent-touch")
	if got.LastActiveAt <= 1000 {
		t.Fatal("LastActiveAt should be updated by TouchLastActive")
	}
}

func TestTouchLastActive_UnknownAgent_NoPanic(t *testing.T) {
	r := newReg()
	// Should not panic for unknown agent.
	r.TouchLastActive("nobody")
}

// ─── Concurrent access (race detector) ───────────────────────────────────────

func TestConcurrentAccess(t *testing.T) {
	r := newReg()
	const n = 50

	var wg sync.WaitGroup
	wg.Add(n * 3)

	// Writers: register new agents.
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			agentID := "concurrent-agent-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
			_ = r.Register(agentID, testPubKey(byte(i)))
		}()
	}

	// Readers: get public key (may or may not exist yet).
	for i := 0; i < n; i++ {
		i := i
		go func() {
			defer wg.Done()
			agentID := "concurrent-agent-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
			_, _ = r.GetPublicKey(agentID)
		}()
	}

	// Size calls.
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_ = r.Size()
		}()
	}

	wg.Wait()
}
