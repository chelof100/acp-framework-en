package iut_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chelof100/acp-framework/acp-go/pkg/iut"
)

// RFC 8037 test key A (Ed25519 seed).
// DID: did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2
const testKeySeedHex = "9d61b19deffd59985ba34a442fa1c54cd044c9c565b66f2699171d66c9682252"

func testPrivKey() ed25519.PrivateKey {
	b, err := hex.DecodeString(testKeySeedHex)
	if err != nil {
		panic("bad test seed: " + err.Error())
	}
	return ed25519.NewKeyFromSeed(b)
}

// vectorDir returns the test vector directory.
// Override via ACP_TEST_VECTORS_DIR env var.
func vectorDir() string {
	if d := os.Getenv("ACP_TEST_VECTORS_DIR"); d != "" {
		return d
	}
	return "../../../../03-acp-protocol/test-vectors"
}

// signIfPlaceholder replaces a PLACEHOLDER:... signature with a real Ed25519
// signature computed from the test key. Other signatures are left unchanged.
func signIfPlaceholder(cap map[string]interface{}, sk ed25519.PrivateKey) (map[string]interface{}, error) {
	sig, _ := cap["signature"].(string)
	if !strings.HasPrefix(sig, "PLACEHOLDER:") {
		return cap, nil
	}
	realSig, err := iut.SignCapability(cap, sk)
	if err != nil {
		return nil, err
	}
	// Deep-copy via JSON round-trip to avoid mutating the original.
	raw, _ := json.Marshal(cap)
	var c map[string]interface{}
	_ = json.Unmarshal(raw, &c)
	c["signature"] = realSig
	return c, nil
}

// TestCompliance loads every *.json file from the test-vectors directory and
// runs ACP L1/L2 compliance evaluation against each one.
func TestCompliance(t *testing.T) {
	dir := vectorDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("test vectors not found at %q (set ACP_TEST_VECTORS_DIR): %v", dir, err)
	}

	sk := testPrivKey()

	ran := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		name := e.Name()
		ran++

		t.Run(strings.TrimSuffix(name, ".json"), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatalf("read: %v", err)
			}

			var vec iut.TestVector
			if err := json.Unmarshal(data, &vec); err != nil {
				t.Fatalf("parse: %v", err)
			}

			// Replace PLACEHOLDER signature with real Ed25519 signature.
			signed, err := signIfPlaceholder(vec.Input.Capability, sk)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			vec.Input.Capability = signed

			got := iut.Evaluate(vec)

			if got.Decision != vec.Expected.Decision {
				t.Errorf("decision: got %q, want %q", got.Decision, vec.Expected.Decision)
			}

			wantCode := vec.Expected.ErrorCode
			switch {
			case wantCode == nil && got.ErrorCode != nil:
				t.Errorf("error_code: got %q, want nil", *got.ErrorCode)
			case wantCode != nil && got.ErrorCode == nil:
				t.Errorf("error_code: got nil, want %q", *wantCode)
			case wantCode != nil && got.ErrorCode != nil && *got.ErrorCode != *wantCode:
				t.Errorf("error_code: got %q, want %q", *got.ErrorCode, *wantCode)
			}
		})
	}

	if ran == 0 {
		t.Skip("no test vector files found")
	}
}
