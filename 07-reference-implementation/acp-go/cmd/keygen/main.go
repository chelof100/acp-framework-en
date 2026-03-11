// cmd/keygen — Generate an Ed25519 key pair for ACP institution setup.
//
// Usage (from acp-go/ directory):
//
//	go run ./cmd/keygen
//
// Output:
//
//	ACP_INSTITUTION_PUBLIC_KEY=<base64url-encoded-32-byte-pubkey>
//	ACP_INSTITUTION_PRIVATE_KEY=<base64url-encoded-64-byte-privkey>
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
)

func main() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("keygen: failed to generate key: %v", err)
	}

	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	privB64 := base64.RawURLEncoding.EncodeToString(priv)

	fmt.Println("# Ed25519 key pair for ACP institution — keep the private key secret!")
	fmt.Println("# Copy these into your environment or .env file:")
	fmt.Printf("ACP_INSTITUTION_PUBLIC_KEY=%s\n", pubB64)
	fmt.Printf("ACP_INSTITUTION_PRIVATE_KEY=%s\n", privB64)
}
