package handshake_test

import (
	"testing"
	"time"

	"github.com/chelof100/acp-framework/acp-go/pkg/handshake"
)

func TestGenerateChallenge(t *testing.T) {
	store := handshake.NewChallengeStore()

	c1, err := store.GenerateChallenge()
	if err != nil {
		t.Fatalf("GenerateChallenge() error = %v", err)
	}
	if c1 == "" {
		t.Fatal("GenerateChallenge() returned empty string")
	}

	// Each call must produce a different challenge.
	c2, err := store.GenerateChallenge()
	if err != nil {
		t.Fatalf("second GenerateChallenge() error = %v", err)
	}
	if c1 == c2 {
		t.Error("two consecutive challenges are identical (CSPRNG issue?)")
	}
}

func TestConsumeChallenge_ValidOnce(t *testing.T) {
	store := handshake.NewChallengeStore()
	challenge, _ := store.GenerateChallenge()

	// First consumption: OK.
	if err := store.ConsumeChallenge(challenge); err != nil {
		t.Errorf("first consume failed: %v", err)
	}

	// Second consumption: must fail (anti-replay).
	if err := store.ConsumeChallenge(challenge); err == nil {
		t.Error("second consume of same challenge should fail (anti-replay)")
	}
}

func TestConsumeChallenge_Unknown(t *testing.T) {
	store := handshake.NewChallengeStore()
	err := store.ConsumeChallenge("this-challenge-was-never-issued")
	if err == nil {
		t.Error("consuming unknown challenge should return error")
	}
}

func TestChallengeStore_Size(t *testing.T) {
	store := handshake.NewChallengeStore()
	if store.Size() != 0 {
		t.Errorf("new store Size() = %d, want 0", store.Size())
	}

	store.GenerateChallenge()
	if store.Size() != 1 {
		t.Errorf("after 1 generate, Size() = %d, want 1", store.Size())
	}
}

func TestChallengeStore_Prune(t *testing.T) {
	store := handshake.NewChallengeStore()

	for i := 0; i < 5; i++ {
		store.GenerateChallenge()
	}
	if store.Size() != 5 {
		t.Fatalf("expected 5 challenges, got %d", store.Size())
	}

	// Fresh challenges won't be pruned yet — just ensure no panic.
	removed := store.Prune()
	_ = removed
	if store.Size() < 0 {
		t.Error("Size() < 0 after prune")
	}
}

func TestChallengeStore_Concurrent(t *testing.T) {
	store := handshake.NewChallengeStore()
	done := make(chan struct{})

	for i := 0; i < 50; i++ {
		go func() {
			store.GenerateChallenge()
			done <- struct{}{}
		}()
	}
	for i := 0; i < 50; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent goroutine timed out")
		}
	}
	if store.Size() != 50 {
		t.Errorf("concurrent Size() = %d, want 50", store.Size())
	}
}
