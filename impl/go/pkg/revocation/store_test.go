package revocation_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/chelof100/acp-framework/acp-go/pkg/revocation"
)

// ─── InMemoryRevocationStore ──────────────────────────────────────────────────

func TestRevoke_BasicRoundTrip(t *testing.T) {
	store := revocation.NewInMemoryRevocationStore()

	rec := revocation.RevocationRecord{
		TokenID:    "nonce-abc",
		RevokedBy:  "admin-agent",
		ReasonCode: revocation.ReasonKeyCompromise,
	}
	if err := store.Revoke(rec); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	revoked, got, err := store.IsRevoked("nonce-abc")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("expected token to be revoked")
	}
	if got == nil || got.TokenID != "nonce-abc" {
		t.Fatal("expected record with matching token_id")
	}
	if got.ReasonCode != revocation.ReasonKeyCompromise {
		t.Errorf("reason_code: got %q want %q", got.ReasonCode, revocation.ReasonKeyCompromise)
	}
}

func TestIsRevoked_UnknownToken(t *testing.T) {
	store := revocation.NewInMemoryRevocationStore()

	revoked, record, err := store.IsRevoked("unknown-nonce")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Fatal("expected unknown token to NOT be revoked")
	}
	if record != nil {
		t.Fatal("expected nil record for unknown token")
	}
}

func TestRevoke_AlreadyRevoked(t *testing.T) {
	store := revocation.NewInMemoryRevocationStore()

	rec := revocation.RevocationRecord{
		TokenID:    "dupe-nonce",
		RevokedBy:  "admin",
		ReasonCode: revocation.ReasonAdministrative,
	}
	if err := store.Revoke(rec); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}

	err := store.Revoke(rec)
	if !errors.Is(err, revocation.ErrAlreadyRevoked) {
		t.Fatalf("expected ErrAlreadyRevoked, got: %v", err)
	}
}

func TestRevoke_InvalidReasonCode(t *testing.T) {
	store := revocation.NewInMemoryRevocationStore()

	rec := revocation.RevocationRecord{
		TokenID:    "any-nonce",
		RevokedBy:  "admin",
		ReasonCode: "REV-999", // invalid
	}
	err := store.Revoke(rec)
	if !errors.Is(err, revocation.ErrInvalidReason) {
		t.Fatalf("expected ErrInvalidReason, got: %v", err)
	}
}

func TestRevoke_EmptyTokenID(t *testing.T) {
	store := revocation.NewInMemoryRevocationStore()

	rec := revocation.RevocationRecord{
		TokenID:    "",
		RevokedBy:  "admin",
		ReasonCode: revocation.ReasonAdministrative,
	}
	if err := store.Revoke(rec); err == nil {
		t.Fatal("expected error for empty token_id")
	}
}

func TestGetRecord_NotFound(t *testing.T) {
	store := revocation.NewInMemoryRevocationStore()
	_, err := store.GetRecord("missing")
	if !errors.Is(err, revocation.ErrTokenNotFound) {
		t.Fatalf("expected ErrTokenNotFound, got: %v", err)
	}
}

func TestGetRecord_Found(t *testing.T) {
	store := revocation.NewInMemoryRevocationStore()
	rec := revocation.RevocationRecord{
		TokenID:    "found-nonce",
		RevokedBy:  "system",
		ReasonCode: revocation.ReasonEmergency,
	}
	_ = store.Revoke(rec)

	got, err := store.GetRecord("found-nonce")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}
	if got.ReasonCode != revocation.ReasonEmergency {
		t.Errorf("reason_code: got %q want %q", got.ReasonCode, revocation.ReasonEmergency)
	}
}

func TestSize(t *testing.T) {
	store := revocation.NewInMemoryRevocationStore()
	if store.Size() != 0 {
		t.Fatalf("expected size 0, got %d", store.Size())
	}

	for i, code := range []string{
		revocation.ReasonAdministrative,
		revocation.ReasonKeyCompromise,
		revocation.ReasonPolicyViolation,
	} {
		_ = store.Revoke(revocation.RevocationRecord{
			TokenID:    fmt.Sprintf("nonce-%d", i),
			RevokedBy:  "admin",
			ReasonCode: code,
		})
	}
	if store.Size() != 3 {
		t.Fatalf("expected size 3, got %d", store.Size())
	}
}

// ─── All reason codes must be valid ───────────────────────────────────────────

func TestAllReasonCodesValid(t *testing.T) {
	codes := []string{
		revocation.ReasonEarlyExpiration,
		revocation.ReasonKeyCompromise,
		revocation.ReasonPolicyViolation,
		revocation.ReasonAgentDecommissioned,
		revocation.ReasonAdministrative,
		revocation.ReasonParentRevoked,
		revocation.ReasonInactivityExpiry,
		revocation.ReasonEmergency,
	}
	store := revocation.NewInMemoryRevocationStore()
	for i, code := range codes {
		rec := revocation.RevocationRecord{
			TokenID:    fmt.Sprintf("t-%d", i),
			RevokedBy:  "test",
			ReasonCode: code,
		}
		if err := store.Revoke(rec); err != nil {
			t.Errorf("code %q should be valid but got: %v", code, err)
		}
	}
}

// ─── StoreRevocationChecker ───────────────────────────────────────────────────

func TestStoreRevocationChecker_NotRevoked(t *testing.T) {
	store := revocation.NewInMemoryRevocationStore()
	checker := revocation.NewStoreRevocationChecker(store)

	revoked, err := checker.IsRevoked("active-nonce", nil)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Fatal("expected not revoked")
	}
}

func TestStoreRevocationChecker_Revoked(t *testing.T) {
	store := revocation.NewInMemoryRevocationStore()
	checker := revocation.NewStoreRevocationChecker(store)

	_ = store.Revoke(revocation.RevocationRecord{
		TokenID:    "bad-nonce",
		RevokedBy:  "admin",
		ReasonCode: revocation.ReasonEmergency,
	})

	revoked, err := checker.IsRevoked("bad-nonce", nil)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if !revoked {
		t.Fatal("expected revoked")
	}
}
