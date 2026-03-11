// Package crypto provides ACP cryptographic identity primitives.
// Implements ACP-SIGN-1.0: Ed25519 key generation and AgentID derivation.
package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	"github.com/mr-tron/base58"
)

// Errors
var (
	ErrKeyGeneration    = errors.New("acp/crypto: failed to generate Ed25519 keypair")
	ErrInvalidPublicKey = errors.New("acp/crypto: invalid public key length (must be 32 bytes)")
)

// AgentIdentity holds the cryptographic identity of an ACP agent.
// AgentID = base58(SHA-256(pk_bytes)) per ACP-CT-1.0 §3.
type AgentIdentity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
	AgentID    string
}

// GenerateIdentity creates a new Ed25519 keypair and derives the AgentID.
// Uses crypto/rand (CSPRNG) as required by ACP-SIGN-1.0.
func GenerateIdentity() (*AgentIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ErrKeyGeneration
	}
	agentID := DeriveAgentID(pub)
	return &AgentIdentity{
		PrivateKey: priv,
		PublicKey:  pub,
		AgentID:    agentID,
	}, nil
}

// NewIdentityFromPrivateKey loads an existing identity from a private key seed (32 bytes).
func NewIdentityFromPrivateKey(seed []byte) (*AgentIdentity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("acp/crypto: invalid seed length (must be 32 bytes)")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &AgentIdentity{
		PrivateKey: priv,
		PublicKey:  pub,
		AgentID:    DeriveAgentID(pub),
	}, nil
}

// DeriveAgentID computes AgentID = base58(SHA-256(pk_bytes)).
// pk must be a 32-byte Ed25519 public key (raw format).
// Output: 43-44 character string using Bitcoin base58 alphabet.
func DeriveAgentID(pk ed25519.PublicKey) string {
	hash := sha256.Sum256([]byte(pk))
	return base58.Encode(hash[:])
}

// ValidateAgentID returns true if the agentID string is well-formed.
// A valid AgentID is 43-44 characters in the base58 Bitcoin alphabet.
func ValidateAgentID(agentID string) bool {
	if len(agentID) < 43 || len(agentID) > 44 {
		return false
	}
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	for _, c := range agentID {
		found := false
		for _, a := range alphabet {
			if c == a {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// Sign signs a canonical payload using ACP-SIGN-1.0 procedure:
//   sig = Ed25519(sk, SHA-256(canonical_bytes))
//
// Returns the 64-byte signature encoded as base64url (no padding).
func (id *AgentIdentity) Sign(canonicalBytes []byte) string {
	hash := sha256.Sum256(canonicalBytes)
	sig := ed25519.Sign(id.PrivateKey, hash[:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

// Verify verifies an Ed25519 signature over canonical_bytes.
// sig is expected as base64url without padding.
// Returns false on any error or invalid signature.
func Verify(pk ed25519.PublicKey, canonicalBytes []byte, sigBase64url string) bool {
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigBase64url)
	if err != nil {
		return false
	}
	hash := sha256.Sum256(canonicalBytes)
	return ed25519.Verify(pk, hash[:], sigBytes)
}
