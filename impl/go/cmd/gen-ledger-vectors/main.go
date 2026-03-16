// Command gen-ledger-vectors generates compliance/test-vectors/TS-LEDGER-*.json.
//
// Produces 3 positive and 8 negative test vectors covering ACP-LEDGER-1.3
// chain verification (LEDGER-002 through LEDGER-012).
// Uses RFC 8037 test key A (same seed as acp-sign-vectors) to create
// real Ed25519 signatures and SHA-256 hash chains.
//
// Run from the module root:
//
//	go run ./cmd/gen-ledger-vectors
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/chelof100/acp-framework/acp-go/pkg/ledger"
	"github.com/gowebpki/jcs"
)

// RFC 8037 test key A — institution key (32-byte seed, hex).
// DID: did:key:z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2
const testKeySeedHex = "9d61b19deffd59985ba34a442fa1c54cd044c9c565b66f2699171d66c9682252"

const institutionID = "org.example.banking"

// ─── Test Vector Schema ───────────────────────────────────────────────────────

// TestVector is the on-disk representation of a LEDGER compliance test.
type TestVector struct {
	Meta     VectorMeta     `json:"meta"`
	Input    VectorInput    `json:"input"`
	Expected VectorExpected `json:"expected"`
}

// VectorMeta contains identifying and descriptive metadata.
type VectorMeta struct {
	ID               string `json:"id"`
	Layer            string `json:"layer"`
	Severity         string `json:"severity"`
	ACPVersion       string `json:"acp_version"`
	ConformanceLevel string `json:"conformance_level"`
	Description      string `json:"description"`
}

// VectorInput holds the institution public key and the event chain to verify.
// Events are stored as raw JSON so negative vectors can carry tampered fields.
type VectorInput struct {
	InstitutionPublicKey string            `json:"institution_public_key"`
	Events               []json.RawMessage `json:"events"`
}

// VectorExpected declares the required outcome for a conformant verifier.
type VectorExpected struct {
	Decision  string  `json:"decision"`
	ErrorCode *string `json:"error_code"`
}

// ─── Generator ────────────────────────────────────────────────────────────────

type generator struct {
	privKey   ed25519.PrivateKey
	pubKeyB64 string
	outDir    string
}

func main() {
	seed, err := hex.DecodeString(testKeySeedHex)
	must(err, "decode test key seed")
	privKey := ed25519.NewKeyFromSeed(seed)
	pubKey := privKey.Public().(ed25519.PublicKey)
	pubKeyB64 := base64.RawURLEncoding.EncodeToString(pubKey)

	// Default output dir is relative to the cmd directory.
	outDir := filepath.Join("..", "..", "compliance", "test-vectors")
	if len(os.Args) > 1 {
		outDir = os.Args[1]
	}

	g := &generator{privKey: privKey, pubKeyB64: pubKeyB64, outDir: outDir}
	g.run()
}

func (g *generator) run() {
	vectors := []TestVector{
		// ── Positive ──────────────────────────────────────────────────────────
		g.posGenesis(),
		g.posThreeEventChain(),
		g.posSixEventChain(),
		// ── Negative ──────────────────────────────────────────────────────────
		g.negMissingSig(),
		g.negInvalidSig(),
		g.negHashMismatch(),
		g.negBrokenPrevHash(),
		g.negSequenceGap(),
		g.negTimestampRegression(),
		g.negUnknownEventType(),
		g.negMissingPolicySnapshotRef(),
	}
	for _, v := range vectors {
		g.writeVector(v)
	}
	fmt.Printf("Generated %d LEDGER test vectors in %s\n", len(vectors), g.outDir)
}

// ─── Positive Vectors ─────────────────────────────────────────────────────────

func (g *generator) posGenesis() TestVector {
	l := g.newLedger()
	// Verify before export (positive vectors must have zero errors).
	g.mustVerify(l, "POS-001")
	return TestVector{
		Meta: VectorMeta{
			ID:               "TS-LEDGER-POS-001",
			Layer:            "LEDGER",
			Severity:         "mandatory",
			ACPVersion:       "1.3",
			ConformanceLevel: "L1",
			Description:      "Valid single-event ledger — genesis event only; hash and signature correct",
		},
		Input:    VectorInput{InstitutionPublicKey: g.pubKeyB64, Events: g.allEvents(l)},
		Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
	}
}

func (g *generator) posThreeEventChain() TestVector {
	l := g.newLedger()
	ts := int64(1718920000) // fixed for reproducibility
	g.append(l, ledger.EventAuthorization, map[string]interface{}{
		"agent_id":            "did:example:agent-alice",
		"authorization_id":    "auth-ledger-pos-002",
		"decision":            "APPROVED",
		"capability":          "acp:cap:data.read",
		"resource":            "doc:finance:report-2024",
		"policy_snapshot_ref": "policy:v2.1:abc123",
		"authorized_at":       ts,
	})
	g.append(l, ledger.EventExecutionTokenIssued, map[string]interface{}{
		"et_id":            "et-ledger-pos-002",
		"authorization_id": "auth-ledger-pos-002",
		"agent_id":         "did:example:agent-alice",
		"capability":       "acp:cap:data.read",
		"resource":         "doc:finance:report-2024",
		"expires_at":       ts + 300,
	})
	g.mustVerify(l, "POS-002")
	return TestVector{
		Meta: VectorMeta{
			ID:               "TS-LEDGER-POS-002",
			Layer:            "LEDGER",
			Severity:         "mandatory",
			ACPVersion:       "1.3",
			ConformanceLevel: "L1",
			Description:      "Valid 3-event chain — LEDGER_GENESIS + AUTHORIZATION + EXECUTION_TOKEN_ISSUED",
		},
		Input:    VectorInput{InstitutionPublicKey: g.pubKeyB64, Events: g.allEvents(l)},
		Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
	}
}

func (g *generator) posSixEventChain() TestVector {
	l := g.newLedger()
	ts := int64(1718920100)
	g.append(l, ledger.EventAgentRegistered, map[string]interface{}{
		"agent_id":       "did:example:agent-bob",
		"institution_id": institutionID,
		"registered_at":  ts,
		"capabilities":   []string{"acp:cap:data.read", "acp:cap:report.write"},
	})
	g.append(l, ledger.EventRiskEvaluation, map[string]interface{}{
		"agent_id":            "did:example:agent-bob",
		"risk_score":          0.15,
		"decision":            "LOW",
		"policy_snapshot_ref": "policy:v2.1:abc123",
		"evaluated_at":        ts + 1,
	})
	g.append(l, ledger.EventAuthorization, map[string]interface{}{
		"agent_id":            "did:example:agent-bob",
		"authorization_id":    "auth-ledger-pos-003",
		"decision":            "APPROVED",
		"capability":          "acp:cap:data.read",
		"resource":            "doc:hr:employees",
		"policy_snapshot_ref": "policy:v2.1:abc123",
		"authorized_at":       ts + 2,
	})
	g.append(l, ledger.EventExecutionTokenIssued, map[string]interface{}{
		"et_id":            "et-ledger-pos-003",
		"authorization_id": "auth-ledger-pos-003",
		"agent_id":         "did:example:agent-bob",
		"capability":       "acp:cap:data.read",
		"resource":         "doc:hr:employees",
		"expires_at":       ts + 302,
	})
	g.append(l, ledger.EventExecutionTokenConsumed, map[string]interface{}{
		"et_id":            "et-ledger-pos-003",
		"consumed_at":      ts + 10,
		"execution_result": "success",
		"consumed_by":      "system:hr-service",
	})
	g.mustVerify(l, "POS-003")
	return TestVector{
		Meta: VectorMeta{
			ID:               "TS-LEDGER-POS-003",
			Layer:            "LEDGER",
			Severity:         "mandatory",
			ACPVersion:       "1.3",
			ConformanceLevel: "L1",
			Description:      "Valid 6-event chain — full lifecycle: GENESIS + AGENT_REGISTERED + RISK_EVALUATION + AUTHORIZATION + EXECUTION_TOKEN_ISSUED + EXECUTION_TOKEN_CONSUMED",
		},
		Input:    VectorInput{InstitutionPublicKey: g.pubKeyB64, Events: g.allEvents(l)},
		Expected: VectorExpected{Decision: "VALID", ErrorCode: nil},
	}
}

// ─── Negative Vectors ─────────────────────────────────────────────────────────

// negMissingSig: event 2 sig field absent → LEDGER-012 per ACP-LEDGER-1.3 §4.4.
// NOTE: The reference Go verifier currently skips sig checks for empty sig fields
// (verifySingleEvent line: `if pubKey != nil && ev.Sig != ""`).
// This vector documents a known gap; conformant L3-FULL implementations MUST reject.
func (g *generator) negMissingSig() TestVector {
	l := g.newLedger()
	ts := int64(1718920200)
	g.append(l, ledger.EventAuthorization, map[string]interface{}{
		"agent_id":            "did:example:agent-alice",
		"authorization_id":    "auth-neg-001",
		"decision":            "APPROVED",
		"policy_snapshot_ref": "policy:v2.1:abc123",
		"authorized_at":       ts,
	})
	events := g.allEvents(l)
	// Remove sig from event[1].
	e := g.toMap(events[1])
	delete(e, "sig")
	events[1] = g.toRaw(e)
	errCode := "LEDGER-012"
	return TestVector{
		Meta: VectorMeta{
			ID:               "TS-LEDGER-NEG-001",
			Layer:            "LEDGER",
			Severity:         "mandatory",
			ACPVersion:       "1.3",
			ConformanceLevel: "L1",
			Description:      "Invalid — event 2 sig field absent; conformant verifier MUST report LEDGER-012 (sig MUST per §4.4)",
		},
		Input:    VectorInput{InstitutionPublicKey: g.pubKeyB64, Events: events},
		Expected: VectorExpected{Decision: "INVALID", ErrorCode: &errCode},
	}
}

// negInvalidSig: event 2 sig replaced with 64 zero bytes → LEDGER-002.
func (g *generator) negInvalidSig() TestVector {
	l := g.newLedger()
	ts := int64(1718920300)
	g.append(l, ledger.EventAuthorization, map[string]interface{}{
		"agent_id":            "did:example:agent-alice",
		"authorization_id":    "auth-neg-002",
		"decision":            "APPROVED",
		"policy_snapshot_ref": "policy:v2.1:abc123",
		"authorized_at":       ts,
	})
	events := g.allEvents(l)
	e := g.toMap(events[1])
	e["sig"] = base64.RawURLEncoding.EncodeToString(make([]byte, 64)) // 64 zero bytes
	events[1] = g.toRaw(e)
	errCode := "LEDGER-002"
	return TestVector{
		Meta: VectorMeta{
			ID:               "TS-LEDGER-NEG-002",
			Layer:            "LEDGER",
			Severity:         "mandatory",
			ACPVersion:       "1.3",
			ConformanceLevel: "L1",
			Description:      "Invalid — event 2 sig is 64 zero bytes (wrong signature); verifier MUST report LEDGER-002",
		},
		Input:    VectorInput{InstitutionPublicKey: g.pubKeyB64, Events: events},
		Expected: VectorExpected{Decision: "INVALID", ErrorCode: &errCode},
	}
}

// negHashMismatch: event 2 hash replaced with GenesisHash then re-signed → LEDGER-003.
// Sig is valid (covers tampered hash), but hash != recomputed → only LEDGER-003 fires.
func (g *generator) negHashMismatch() TestVector {
	l := g.newLedger()
	ts := int64(1718920400)
	g.append(l, ledger.EventAuthorization, map[string]interface{}{
		"agent_id":            "did:example:agent-alice",
		"authorization_id":    "auth-neg-003",
		"decision":            "APPROVED",
		"policy_snapshot_ref": "policy:v2.1:abc123",
		"authorized_at":       ts,
	})
	events := g.allEvents(l)
	e := g.toMap(events[1])
	e["hash"] = ledger.GenesisHash // wrong hash (all-zeros sentinel)
	// Re-sign so LEDGER-002 does not fire — only LEDGER-003.
	e["sig"] = g.signMap(e)
	events[1] = g.toRaw(e)
	errCode := "LEDGER-003"
	return TestVector{
		Meta: VectorMeta{
			ID:               "TS-LEDGER-NEG-003",
			Layer:            "LEDGER",
			Severity:         "mandatory",
			ACPVersion:       "1.3",
			ConformanceLevel: "L1",
			Description:      "Invalid — event 2 hash tampered to genesis hash sentinel (re-signed to isolate LEDGER-003); stored hash != recomputed hash",
		},
		Input:    VectorInput{InstitutionPublicKey: g.pubKeyB64, Events: events},
		Expected: VectorExpected{Decision: "INVALID", ErrorCode: &errCode},
	}
}

// negBrokenPrevHash: event 3 prev_hash set to GenesisHash → LEDGER-004.
// Hash and sig are also invalidated by the tamper (multi-error scenario).
func (g *generator) negBrokenPrevHash() TestVector {
	l := g.newLedger()
	ts := int64(1718920500)
	g.append(l, ledger.EventAuthorization, map[string]interface{}{
		"agent_id":            "did:example:agent-alice",
		"authorization_id":    "auth-neg-004",
		"decision":            "APPROVED",
		"policy_snapshot_ref": "policy:v2.1:abc123",
		"authorized_at":       ts,
	})
	g.append(l, ledger.EventExecutionTokenIssued, map[string]interface{}{
		"et_id":            "et-neg-004",
		"authorization_id": "auth-neg-004",
		"agent_id":         "did:example:agent-alice",
		"expires_at":       ts + 300,
	})
	events := g.allEvents(l)
	e := g.toMap(events[2])
	e["prev_hash"] = ledger.GenesisHash // breaks chain linkage
	events[2] = g.toRaw(e)
	errCode := "LEDGER-004"
	return TestVector{
		Meta: VectorMeta{
			ID:               "TS-LEDGER-NEG-004",
			Layer:            "LEDGER",
			Severity:         "mandatory",
			ACPVersion:       "1.3",
			ConformanceLevel: "L1",
			Description:      "Invalid — event 3 prev_hash set to genesis hash (does not match event 2 hash); verifier MUST report LEDGER-004",
		},
		Input:    VectorInput{InstitutionPublicKey: g.pubKeyB64, Events: events},
		Expected: VectorExpected{Decision: "INVALID", ErrorCode: &errCode},
	}
}

// negSequenceGap: event 3 sequence set to 5 (gap from 2) → LEDGER-005.
func (g *generator) negSequenceGap() TestVector {
	l := g.newLedger()
	ts := int64(1718920600)
	g.append(l, ledger.EventAuthorization, map[string]interface{}{
		"agent_id":            "did:example:agent-alice",
		"authorization_id":    "auth-neg-005",
		"decision":            "APPROVED",
		"policy_snapshot_ref": "policy:v2.1:abc123",
		"authorized_at":       ts,
	})
	g.append(l, ledger.EventTokenIssued, map[string]interface{}{
		"token_id":         "tok-neg-005",
		"authorization_id": "auth-neg-005",
		"agent_id":         "did:example:agent-alice",
	})
	events := g.allEvents(l)
	e := g.toMap(events[2])
	e["sequence"] = float64(5) // sequence gap (3 → 5)
	events[2] = g.toRaw(e)
	errCode := "LEDGER-005"
	return TestVector{
		Meta: VectorMeta{
			ID:               "TS-LEDGER-NEG-005",
			Layer:            "LEDGER",
			Severity:         "mandatory",
			ACPVersion:       "1.3",
			ConformanceLevel: "L1",
			Description:      "Invalid — event 3 sequence tampered to 5 (gap from 2); verifier MUST report LEDGER-005",
		},
		Input:    VectorInput{InstitutionPublicKey: g.pubKeyB64, Events: events},
		Expected: VectorExpected{Decision: "INVALID", ErrorCode: &errCode},
	}
}

// negTimestampRegression: event 3 timestamp set before event 1 → LEDGER-006.
func (g *generator) negTimestampRegression() TestVector {
	l := g.newLedger()
	ts := int64(1718920700)
	g.append(l, ledger.EventAgentRegistered, map[string]interface{}{
		"agent_id":      "did:example:agent-bob",
		"registered_at": ts,
	})
	g.append(l, ledger.EventAgentStateChange, map[string]interface{}{
		"agent_id":   "did:example:agent-bob",
		"state":      "active",
		"changed_at": ts + 5,
	})
	events := g.allEvents(l)
	// Set event[2].timestamp to well before genesis.
	e := g.toMap(events[2])
	e["timestamp"] = float64(1000000000) // Unix 2001 — before all other events
	events[2] = g.toRaw(e)
	errCode := "LEDGER-006"
	return TestVector{
		Meta: VectorMeta{
			ID:               "TS-LEDGER-NEG-006",
			Layer:            "LEDGER",
			Severity:         "mandatory",
			ACPVersion:       "1.3",
			ConformanceLevel: "L1",
			Description:      "Invalid — event 3 timestamp (2001-09-09) is before event 2 timestamp; verifier MUST report LEDGER-006",
		},
		Input:    VectorInput{InstitutionPublicKey: g.pubKeyB64, Events: events},
		Expected: VectorExpected{Decision: "INVALID", ErrorCode: &errCode},
	}
}

// negUnknownEventType: event 2 event_type not in registry → LEDGER-008.
func (g *generator) negUnknownEventType() TestVector {
	l := g.newLedger()
	ts := int64(1718920800)
	g.append(l, ledger.EventTokenIssued, map[string]interface{}{
		"token_id":  "tok-neg-007",
		"agent_id":  "did:example:agent-alice",
		"issued_at": ts,
	})
	events := g.allEvents(l)
	e := g.toMap(events[1])
	e["event_type"] = "CUSTOM_UNKNOWN_EVENT_TYPE"
	events[1] = g.toRaw(e)
	errCode := "LEDGER-008"
	return TestVector{
		Meta: VectorMeta{
			ID:               "TS-LEDGER-NEG-007",
			Layer:            "LEDGER",
			Severity:         "mandatory",
			ACPVersion:       "1.3",
			ConformanceLevel: "L1",
			Description:      "Invalid — event 2 event_type is 'CUSTOM_UNKNOWN_EVENT_TYPE' (not in registry); verifier MUST report LEDGER-008",
		},
		Input:    VectorInput{InstitutionPublicKey: g.pubKeyB64, Events: events},
		Expected: VectorExpected{Decision: "INVALID", ErrorCode: &errCode},
	}
}

// negMissingPolicySnapshotRef: AUTHORIZATION payload missing policy_snapshot_ref → LEDGER-010.
// NOTE: The current Go verifier does not enforce LEDGER-010 (payload content not checked
// during chain verify). This vector documents the spec requirement.
func (g *generator) negMissingPolicySnapshotRef() TestVector {
	l := g.newLedger()
	ts := int64(1718920900)
	// Ledger Append does not validate payload content — this stores without error.
	g.append(l, ledger.EventAuthorization, map[string]interface{}{
		"agent_id":         "did:example:agent-alice",
		"authorization_id": "auth-neg-008",
		"decision":         "APPROVED",
		"authorized_at":    ts,
		// policy_snapshot_ref intentionally omitted
	})
	errCode := "LEDGER-010"
	return TestVector{
		Meta: VectorMeta{
			ID:               "TS-LEDGER-NEG-008",
			Layer:            "LEDGER",
			Severity:         "mandatory",
			ACPVersion:       "1.3",
			ConformanceLevel: "L1",
			Description:      "Invalid — AUTHORIZATION payload missing required policy_snapshot_ref field; conformant verifier MUST report LEDGER-010 per §5.2",
		},
		Input:    VectorInput{InstitutionPublicKey: g.pubKeyB64, Events: g.allEvents(l)},
		Expected: VectorExpected{Decision: "INVALID", ErrorCode: &errCode},
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func (g *generator) newLedger() *ledger.InMemoryLedger {
	l, err := ledger.NewInMemoryLedger(institutionID, g.privKey)
	must(err, "create ledger")
	return l
}

func (g *generator) append(l *ledger.InMemoryLedger, eventType string, payload interface{}) {
	_, err := l.Append(eventType, payload)
	must(err, "ledger append "+eventType)
}

// mustVerify aborts if the ledger has any chain verification errors.
func (g *generator) mustVerify(l *ledger.InMemoryLedger, id string) {
	errs := l.Verify()
	if len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "BUG: positive vector %s failed chain verification:\n", id)
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "  %s\n", e)
		}
		os.Exit(1)
	}
}

// allEvents returns all ledger events as raw JSON messages.
func (g *generator) allEvents(l *ledger.InMemoryLedger) []json.RawMessage {
	events := l.List(0, 0)
	result := make([]json.RawMessage, len(events))
	for i, ev := range events {
		b, err := json.Marshal(ev)
		must(err, "marshal event")
		result[i] = b
	}
	return result
}

// toMap deserializes raw JSON into a generic map for tampering.
func (g *generator) toMap(raw json.RawMessage) map[string]interface{} {
	var m map[string]interface{}
	must(json.Unmarshal(raw, &m), "unmarshal to map")
	return m
}

// toRaw serializes a map back to raw JSON.
func (g *generator) toRaw(m map[string]interface{}) json.RawMessage {
	b, err := json.Marshal(m)
	must(err, "marshal map to raw")
	return b
}

// signMap computes Ed25519(SHA-256(JCS(all fields except "sig"))) over the event map.
// Used to re-sign tampered events (e.g. for the LEDGER-003 vector).
func (g *generator) signMap(m map[string]interface{}) string {
	signable := make(map[string]interface{}, len(m))
	for k, v := range m {
		if k != "sig" {
			signable[k] = v
		}
	}
	raw, err := json.Marshal(signable)
	must(err, "marshal signable")
	canonical, err := jcs.Transform(raw)
	must(err, "jcs transform")
	digest := sha256.Sum256(canonical)
	sig := ed25519.Sign(g.privKey, digest[:])
	return base64.RawURLEncoding.EncodeToString(sig)
}

func (g *generator) writeVector(v TestVector) {
	filename := v.Meta.ID + ".json"
	outPath := filepath.Join(g.outDir, filename)
	data, err := json.MarshalIndent(v, "", "  ")
	must(err, "marshal vector "+v.Meta.ID)
	must(os.WriteFile(outPath, data, 0644), "write vector "+v.Meta.ID)
	fmt.Printf("  %s\n", filename)
}

func must(err error, msg ...string) {
	if err == nil {
		return
	}
	if len(msg) > 0 {
		fmt.Fprintf(os.Stderr, "fatal (%s): %v\n", msg[0], err)
	} else {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
	}
	os.Exit(1)
}
