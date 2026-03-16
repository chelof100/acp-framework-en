// Command acp-sign-vectors replaces PLACEHOLDER signatures in ACP-TS-1.1 test
// vector files with real Ed25519 signatures. It operates in-place on the
// vector directory.
//
// For CORE/DCMA vectors: signs capability.signature and
// delegation.delegation_signature using the institution key (RFC 8037 key A)
// and per-agent delegation keys.
//
// For HP vectors (meta.layer == "HP"): signs input.pop_token.sig using the
// agent's private key identified by pop_token.agent_id.
//
// Usage:
//
//	acp-sign-vectors [dir]
//
// Default dir (relative to the acp-go module root):
//
//	../../compliance/test-vectors
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/chelof100/acp-framework/acp-go/pkg/iut"
)

// RFC 8037 test key A — institution key (32-byte seed, hex).
// DID: did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2
const testKeySeedHex = "9d61b19deffd59985ba34a442fa1c54cd044c9c565b66f2699171d66c9682252"

// Secondary test key seeds for DCMA delegation signing — one per delegating agent.
// These deterministic seeds are used only in test vectors; never in production.
const (
	aliceKeySeedHex = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4d0bd6d8" // alice (RFC 8037 key B)
	bobKeySeedHex   = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7" // bob
	a3KeySeedHex    = "f5e287302bfa55e4ae4b18c2f793a3a09e74e5c9547e80d22b55d3a51b3ddbc1" // agent-a3
)

// delegationKeys maps agent DID → Ed25519 private key.
// Used for delegation_signature (DCMA) and pop_token.sig (HP) signing.
var delegationKeys map[string]ed25519.PrivateKey

func init() {
	mustKey := func(seedHex string) ed25519.PrivateKey {
		b, err := hex.DecodeString(seedHex)
		if err != nil {
			panic("bad key seed: " + err.Error())
		}
		return ed25519.NewKeyFromSeed(b)
	}
	delegationKeys = map[string]ed25519.PrivateKey{
		"did:example:agent-alice": mustKey(aliceKeySeedHex),
		"did:example:agent-bob":   mustKey(bobKeySeedHex),
		"did:example:agent-a3":    mustKey(a3KeySeedHex),
	}
}

func main() {
	dir := "../../compliance/test-vectors"
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

// signVectorFile reads a test vector JSON file, replaces PLACEHOLDER signatures
// with real Ed25519 signatures, and writes it back.
//
// Dispatch: HP vectors (meta.layer == "HP") use signHPVector; all other vectors
// use signCoreVector (capability + optional delegation).
//
// Returns true if the file was modified.
func signVectorFile(path string, sk ed25519.PrivateKey) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}

	var vec map[string]interface{}
	if err := json.Unmarshal(data, &vec); err != nil {
		return false, fmt.Errorf("parse: %w", err)
	}

	// Dispatch on layer.
	meta, _ := vec["meta"].(map[string]interface{})
	layer, _ := meta["layer"].(string)

	var changed bool
	if layer == "HP" {
		changed, err = signHPVector(vec)
	} else {
		changed, err = signCoreVector(vec, sk)
	}
	if err != nil || !changed {
		return changed, err
	}

	out, err := json.MarshalIndent(vec, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(path, append(out, '\n'), 0644); err != nil {
		return false, err
	}
	return true, nil
}

// signCoreVector handles CORE and DCMA vectors (capability + optional delegation).
//
// Signing order for vectors with delegation:
//  1. Sign delegation_signature first (with the delegator's key).
//  2. Re-sign the top-level capability signature (with the institution key)
//     because the signed payload includes the updated delegation object.
func signCoreVector(vec map[string]interface{}, sk ed25519.PrivateKey) (bool, error) {
	input, _ := vec["input"].(map[string]interface{})
	if input == nil {
		return false, nil
	}
	cap, _ := input["capability"].(map[string]interface{})
	if cap == nil {
		return false, nil
	}

	changed := false

	// Step 1: sign delegation_signature if PLACEHOLDER.
	if delegation, _ := cap["delegation"].(map[string]interface{}); delegation != nil {
		delSig, _ := delegation["delegation_signature"].(string)
		if strings.HasPrefix(delSig, "PLACEHOLDER:") {
			delegator, _ := delegation["delegator"].(string)
			delSK, ok := delegationKeys[delegator]
			if !ok {
				return false, fmt.Errorf("no delegation key for delegator %q", delegator)
			}
			realDelSig, err := iut.SignDelegation(delegation, delSK)
			if err != nil {
				return false, fmt.Errorf("sign delegation: %w", err)
			}
			delegation["delegation_signature"] = realDelSig
			cap["delegation"] = delegation

			// Update the delegator's public_key in context.delegation_registry.
			if context, _ := vec["context"].(map[string]interface{}); context != nil {
				if reg, _ := context["delegation_registry"].(map[string]interface{}); reg != nil {
					if entry, _ := reg[delegator].(map[string]interface{}); entry != nil {
						pubKey := delSK.Public().(ed25519.PublicKey)
						entry["public_key"] = base64.RawURLEncoding.EncodeToString(pubKey)
						reg[delegator] = entry
						context["delegation_registry"] = reg
						vec["context"] = context
					}
				}
			}

			// Force re-sign of the capability signature (delegation changed).
			cap["signature"] = "PLACEHOLDER:needs-resign-after-delegation"
			changed = true
		}
	}

	// Step 2: sign top-level capability signature if PLACEHOLDER (or forced above).
	sig, _ := cap["signature"].(string)
	if strings.HasPrefix(sig, "PLACEHOLDER:") {
		realSig, err := iut.SignCapability(cap, sk)
		if err != nil {
			return false, fmt.Errorf("sign capability: %w", err)
		}
		cap["signature"] = realSig
		changed = true
	}

	if changed {
		input["capability"] = cap
		vec["input"] = input
	}
	return changed, nil
}

// signHPVector handles HP (handshake) vectors.
// Signs pop_token.sig with the agent's private key (identified by pop_token.agent_id).
// Also updates context.agent_registry[agent_id].public_key if needed.
func signHPVector(vec map[string]interface{}) (bool, error) {
	input, _ := vec["input"].(map[string]interface{})
	if input == nil {
		return false, nil
	}
	pop, _ := input["pop_token"].(map[string]interface{})
	if pop == nil {
		// Vector has no pop_token (e.g. HP-004 missing header test) — nothing to sign.
		return false, nil
	}

	sig, _ := pop["sig"].(string)
	if !strings.HasPrefix(sig, "PLACEHOLDER:") {
		return false, nil
	}

	agentID, _ := pop["agent_id"].(string)
	agentSK, ok := delegationKeys[agentID]
	if !ok {
		return false, fmt.Errorf("no agent key for agent_id %q", agentID)
	}

	realSig, err := iut.SignPoP(pop, agentSK)
	if err != nil {
		return false, fmt.Errorf("sign PoP: %w", err)
	}
	pop["sig"] = realSig

	// Update context.agent_registry[agent_id].public_key with the actual public key.
	if context, _ := vec["context"].(map[string]interface{}); context != nil {
		if reg, _ := context["agent_registry"].(map[string]interface{}); reg != nil {
			if entry, _ := reg[agentID].(map[string]interface{}); entry != nil {
				pubKey := agentSK.Public().(ed25519.PublicKey)
				entry["public_key"] = base64.RawURLEncoding.EncodeToString(pubKey)
				reg[agentID] = entry
				context["agent_registry"] = reg
				vec["context"] = context
			}
		}
	}

	input["pop_token"] = pop
	vec["input"] = input
	return true, nil
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "acp-sign-vectors: "+format+"\n", args...)
	os.Exit(1)
}
