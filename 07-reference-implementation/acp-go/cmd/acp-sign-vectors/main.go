// Command acp-sign-vectors replaces PLACEHOLDER signatures in ACP-TS-1.1 test
// vector files with real Ed25519 signatures computed from the RFC 8037 test
// key A.  It operates in-place on the vector directory.
//
// Usage:
//
//	acp-sign-vectors [dir]
//
// Default dir (relative to the acp-go module root):
//
//	../../03-acp-protocol/test-vectors
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chelof100/acp-framework/acp-go/pkg/iut"
)

// RFC 8037 test key A — seed (32 bytes, hex).
// DID: did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2
const testKeySeedHex = "9d61b19deffd59985ba34a442fa1c54cd044c9c565b66f2699171d66c9682252"

func main() {
	dir := "../../03-acp-protocol/test-vectors"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	seedBytes, err := hex.DecodeString(testKeySeedHex)
	if err != nil {
		fatalf("bad seed hex: %v", err)
	}
	sk := ed25519.NewKeyFromSeed(seedBytes)

	entries, err := os.ReadDir(dir)
	if err != nil {
		fatalf("read dir %q: %v", dir, err)
	}

	ok, skipped, errCount := 0, 0, 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			skipped++
			continue
		}
		path := filepath.Join(dir, e.Name())
		changed, err := signVectorFile(path, sk)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERR  %s: %v\n", e.Name(), err)
			errCount++
			continue
		}
		if changed {
			fmt.Printf("SIGN %s\n", e.Name())
		} else {
			fmt.Printf("SKIP %s (no PLACEHOLDER)\n", e.Name())
		}
		ok++
	}

	fmt.Printf("\n%d processed, %d skipped, %d errors\n", ok, skipped, errCount)
	if errCount > 0 {
		os.Exit(1)
	}
}

// signVectorFile reads a test vector JSON file, replaces any PLACEHOLDER
// capability signature with a real Ed25519 signature, and writes it back.
// Returns true if the file was modified.
func signVectorFile(path string, sk ed25519.PrivateKey) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	// Use a generic map so we can round-trip without losing unknown fields.
	var vec map[string]interface{}
	if err := json.Unmarshal(data, &vec); err != nil {
		return false, fmt.Errorf("parse: %w", err)
	}

	input, _ := vec["input"].(map[string]interface{})
	if input == nil {
		return false, nil
	}
	cap, _ := input["capability"].(map[string]interface{})
	if cap == nil {
		return false, nil
	}

	sig, _ := cap["signature"].(string)
	if !strings.HasPrefix(sig, "PLACEHOLDER:") {
		return false, nil // nothing to do
	}

	realSig, err := iut.SignCapability(cap, sk)
	if err != nil {
		return false, fmt.Errorf("sign: %w", err)
	}
	cap["signature"] = realSig
	input["capability"] = cap
	vec["input"] = input

	out, err := json.MarshalIndent(vec, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0644); err != nil {
		return false, err
	}
	return true, nil
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "acp-sign-vectors: "+format+"\n", args...)
	os.Exit(1)
}
