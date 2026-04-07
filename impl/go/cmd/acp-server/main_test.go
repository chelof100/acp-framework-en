package main_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ─── One-time binary build via TestMain ───────────────────────────────────────

var serverBin string // set by TestMain

func TestMain(m *testing.M) {
	// Build acp-server once for all tests in this package.
	dir, err := os.MkdirTemp("", "acp-server-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mktempdir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(dir)

	bin := filepath.Join(dir, "acp-server")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}

	_, file, _, _ := runtime.Caller(0)
	// file = …/cmd/acp-server/main_test.go → go up 3 levels to get acp-go root
	modRoot := filepath.Dir(filepath.Dir(filepath.Dir(file)))

	cmd := exec.Command("go", "build", "-o", bin, "./cmd/acp-server/")
	cmd.Dir = modRoot
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build acp-server: %v\n%s\n", err, out)
		os.Exit(1)
	}
	serverBin = bin
	os.Exit(m.Run())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// testKeyPair returns a deterministic Ed25519 key pair for tests.
func testKeyPair() (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, 32)
	seed[0] = 0xAA
	sk := ed25519.NewKeyFromSeed(seed)
	return sk.Public().(ed25519.PublicKey), sk
}

// startServer launches acp-server on a free port and returns its base URL.
func startServer(t *testing.T) string {
	t.Helper()
	pub, priv := testKeyPair()
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	privB64 := base64.RawURLEncoding.EncodeToString(priv)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	addr := fmt.Sprintf(":%d", port)
	cmd := exec.Command(serverBin)
	cmd.Env = append(os.Environ(),
		"ACP_INSTITUTION_PUBLIC_KEY="+pubB64,
		"ACP_INSTITUTION_PRIVATE_KEY="+privB64,
		"ACP_ADDR="+addr,
		"ACP_LOG_LEVEL=error",
	)

	if err := cmd.Start(); err != nil {
		t.Fatalf("start acp-server: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	base := fmt.Sprintf("http://127.0.0.1%s", addr)
	waitForHealth(t, base)
	return base
}

func waitForHealth(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + "/acp/v1/health")
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return
		}
		if resp != nil {
			resp.Body.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("acp-server did not become healthy within 10s")
}

// doJSON sends a JSON request and returns (statusCode, top-level body, data-field body).
// The ACP server wraps success responses in {"data": {...}}.
func doJSON(t *testing.T, method, url string, body interface{}) (int, map[string]interface{}, map[string]interface{}) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	var envelope map[string]interface{}
	_ = json.Unmarshal(raw, &envelope)

	// Unwrap the "data" field if present.
	var data map[string]interface{}
	if d, ok := envelope["data"]; ok {
		if dm, ok := d.(map[string]interface{}); ok {
			data = dm
		}
		// data field might also be the top-level for error responses.
	}
	if data == nil {
		data = envelope // for error responses that don't wrap
	}
	return resp.StatusCode, envelope, data
}

// agentKey generates a deterministic Ed25519 key pair from a single seed byte.
func agentKey(b byte) (ed25519.PublicKey, string) {
	seed := make([]byte, 32)
	seed[0] = b
	sk := ed25519.NewKeyFromSeed(seed)
	pub := sk.Public().(ed25519.PublicKey)
	return pub, base64.RawURLEncoding.EncodeToString(pub)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

func TestServer_Health(t *testing.T) {
	base := startServer(t)
	status, envelope, _ := doJSON(t, http.MethodGet, base+"/acp/v1/health", nil)
	if status != http.StatusOK {
		t.Fatalf("health: got %d, want 200; body=%v", status, envelope)
	}
	// Health endpoint should return something in the envelope — just verify 200.
}

func TestServer_StartupRequiresPubKey(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	cmd := exec.Command(serverBin)
	// Build env without ACP_INSTITUTION_PUBLIC_KEY.
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "ACP_INSTITUTION_PUBLIC_KEY") {
			cmd.Env = append(cmd.Env, e)
		}
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("ACP_ADDR=:%d", port))

	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit when ACP_INSTITUTION_PUBLIC_KEY is missing")
	}
}

func TestServer_AgentRegisterAndGet(t *testing.T) {
	base := startServer(t)
	_, pubB64 := agentKey(0x42)
	agentID := "test-agent-001"

	// Register.
	status, _, _ := doJSON(t, http.MethodPost, base+"/acp/v1/agents", map[string]interface{}{
		"agent_id":         agentID,
		"public_key":       pubB64,
		"autonomy_level":   2,
		"authority_domain": "finance",
	})
	if status != http.StatusCreated {
		t.Fatalf("register: got %d, want 201", status)
	}

	// Get — unwrap data envelope.
	status, _, data := doJSON(t, http.MethodGet, base+"/acp/v1/agents/"+agentID, nil)
	if status != http.StatusOK {
		t.Fatalf("get agent: got %d, want 200; data=%v", status, data)
	}
	if gotID, _ := data["agent_id"].(string); gotID != agentID {
		t.Errorf("agent_id: got %q, want %q", gotID, agentID)
	}
}

func TestServer_AgentRegister_Duplicate(t *testing.T) {
	base := startServer(t)
	_, pubB64 := agentKey(0x55)
	payload := map[string]interface{}{
		"agent_id":   "dup-agent",
		"public_key": pubB64,
	}
	doJSON(t, http.MethodPost, base+"/acp/v1/agents", payload)
	status, _, _ := doJSON(t, http.MethodPost, base+"/acp/v1/agents", payload)
	if status != http.StatusConflict {
		t.Fatalf("duplicate register: got %d, want 409", status)
	}
}

func TestServer_AgentGet_NotFound(t *testing.T) {
	base := startServer(t)
	status, _, _ := doJSON(t, http.MethodGet, base+"/acp/v1/agents/nobody", nil)
	if status != http.StatusNotFound {
		t.Fatalf("get unknown agent: got %d, want 404", status)
	}
}

func TestServer_Challenge(t *testing.T) {
	base := startServer(t)
	status, _, data := doJSON(t, http.MethodGet, base+"/acp/v1/handshake/challenge", nil)
	if status != http.StatusOK {
		t.Fatalf("challenge: got %d, want 200; data=%v", status, data)
	}
	challenge, _ := data["challenge"].(string)
	if challenge == "" {
		t.Errorf("challenge field missing or empty in data: %v", data)
	}
}

func TestServer_AgentState_InvalidTransition(t *testing.T) {
	base := startServer(t)
	_, pubB64 := agentKey(0x77)
	agentID := "state-agent"

	doJSON(t, http.MethodPost, base+"/acp/v1/agents", map[string]interface{}{
		"agent_id":   agentID,
		"public_key": pubB64,
	})
	// Suspend the agent.
	doJSON(t, http.MethodPost, base+"/acp/v1/agents/"+agentID+"/state",
		map[string]interface{}{"status": "suspended"})

	// Suspended → Restricted is invalid.
	status, _, _ := doJSON(t, http.MethodPost, base+"/acp/v1/agents/"+agentID+"/state",
		map[string]interface{}{"status": "restricted"})
	// Server returns 400 (ErrSTATE001) for invalid transitions and 409 for revoked agents.
	if status != http.StatusBadRequest && status != http.StatusConflict {
		t.Fatalf("invalid transition: got %d, want 400 or 409", status)
	}
}

// ─── Counterfactual Endpoint ──────────────────────────────────────────────────

// TestServer_Counterfactual_StructuralMutation verifies that a structural
// mutation (financial.transfer + RESTRICTED) produces DENIED and BAR=1.00.
func TestServer_Counterfactual_StructuralMutation(t *testing.T) {
	base := startServer(t)

	body := map[string]interface{}{
		"base": map[string]interface{}{
			"agent_id":       "cf-test-agent",
			"capability":     "acp:cap:data.read",
			"resource":       "metrics/public",
			"resource_class": "PUBLIC",
		},
		"mutations": []interface{}{
			map[string]interface{}{
				"label":          "structural",
				"capability":     "acp:cap:financial.transfer",
				"resource":       "accounts/restricted-fund",
				"resource_class": "RESTRICTED",
			},
		},
	}

	status, _, data := doJSON(t, http.MethodPost, base+"/acp/v1/counterfactual", body)
	if status != http.StatusOK {
		t.Fatalf("got %d, want 200", status)
	}

	bar, ok := data["bar"].(float64)
	if !ok {
		t.Fatalf("bar missing or not float64: %v", data)
	}
	if bar != 1.0 {
		t.Fatalf("BAR=%.2f, want 1.0", bar)
	}

	results, ok := data["results"].([]interface{})
	if !ok || len(results) != 1 {
		t.Fatalf("results: expected 1 entry, got %v", data["results"])
	}
	r0 := results[0].(map[string]interface{})
	if r0["decision"] != "DENIED" {
		t.Fatalf("decision=%v, want DENIED", r0["decision"])
	}
}

// TestServer_Counterfactual_MultiMutation verifies structural + behavioral mutations
// both produce DENIED and BAR=1.00.
func TestServer_Counterfactual_MultiMutation(t *testing.T) {
	base := startServer(t)

	body := map[string]interface{}{
		"base": map[string]interface{}{
			"agent_id":       "cf-multi-agent",
			"capability":     "acp:cap:data.read",
			"resource":       "metrics/public",
			"resource_class": "PUBLIC",
		},
		"mutations": []interface{}{
			map[string]interface{}{
				"label":          "structural",
				"capability":     "acp:cap:financial.transfer",
				"resource":       "accounts/restricted-fund",
				"resource_class": "RESTRICTED",
			},
			map[string]interface{}{
				"label":          "behavioral",
				"capability":     "acp:cap:financial.transfer",
				"resource":       "accounts/restricted-fund",
				"resource_class": "RESTRICTED",
				"context": map[string]interface{}{
					"external_ip": true,
					"off_hours":   true,
				},
				"history": map[string]interface{}{
					"recent_denial": true,
					"freq_anomaly":  true,
				},
			},
		},
	}

	status, _, data := doJSON(t, http.MethodPost, base+"/acp/v1/counterfactual", body)
	if status != http.StatusOK {
		t.Fatalf("got %d, want 200", status)
	}

	bar, _ := data["bar"].(float64)
	if bar != 1.0 {
		t.Fatalf("BAR=%.2f, want 1.0 for all-DENIED mutations", bar)
	}

	results, _ := data["results"].([]interface{})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	for i, rr := range results {
		rm := rr.(map[string]interface{})
		if rm["decision"] != "DENIED" {
			t.Fatalf("result[%d]: decision=%v, want DENIED", i, rm["decision"])
		}
	}
}

// TestServer_Counterfactual_NilMutation verifies a nil (no-op) mutation on a
// low-risk base produces APPROVED and BAR=0.
func TestServer_Counterfactual_NilMutation(t *testing.T) {
	base := startServer(t)

	body := map[string]interface{}{
		"base": map[string]interface{}{
			"agent_id":       "cf-nil-agent",
			"capability":     "acp:cap:data.read",
			"resource":       "metrics/public",
			"resource_class": "PUBLIC",
		},
		"mutations": []interface{}{
			map[string]interface{}{
				"label": "nil-mutation",
				// all fields nil: keep base unchanged
			},
		},
	}

	status, _, data := doJSON(t, http.MethodPost, base+"/acp/v1/counterfactual", body)
	if status != http.StatusOK {
		t.Fatalf("got %d, want 200", status)
	}

	bar, _ := data["bar"].(float64)
	if bar != 0.0 {
		t.Fatalf("BAR=%.2f, want 0.0 for nil mutation on low-risk base", bar)
	}

	results, _ := data["results"].([]interface{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r0 := results[0].(map[string]interface{})
	if r0["decision"] != "APPROVED" {
		t.Fatalf("decision=%v, want APPROVED for data.read+public with no overrides", r0["decision"])
	}
}

// TestServer_Counterfactual_MissingBase validates required field checks.
func TestServer_Counterfactual_MissingBase(t *testing.T) {
	base := startServer(t)

	body := map[string]interface{}{
		"base": map[string]interface{}{
			// agent_id missing
			"capability":     "acp:cap:data.read",
			"resource":       "metrics/public",
			"resource_class": "PUBLIC",
		},
		"mutations": []interface{}{
			map[string]interface{}{"label": "m1"},
		},
	}

	status, _, _ := doJSON(t, http.MethodPost, base+"/acp/v1/counterfactual", body)
	if status != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 for missing agent_id", status)
	}
}

// TestServer_Counterfactual_EmptyMutations validates that an empty mutations
// array is rejected with 400.
func TestServer_Counterfactual_EmptyMutations(t *testing.T) {
	base := startServer(t)

	body := map[string]interface{}{
		"base": map[string]interface{}{
			"agent_id":       "cf-empty-agent",
			"capability":     "acp:cap:data.read",
			"resource":       "metrics/public",
			"resource_class": "PUBLIC",
		},
		"mutations": []interface{}{},
	}

	status, _, _ := doJSON(t, http.MethodPost, base+"/acp/v1/counterfactual", body)
	if status != http.StatusBadRequest {
		t.Fatalf("got %d, want 400 for empty mutations", status)
	}
}

// TestServer_Counterfactual_Labels verifies that result labels match mutation labels.
func TestServer_Counterfactual_Labels(t *testing.T) {
	base := startServer(t)

	labels := []string{"alpha", "beta", "gamma"}
	mutations := make([]interface{}, len(labels))
	for i, l := range labels {
		mutations[i] = map[string]interface{}{"label": l}
	}

	body := map[string]interface{}{
		"base": map[string]interface{}{
			"agent_id":       "cf-labels-agent",
			"capability":     "acp:cap:data.read",
			"resource":       "metrics/public",
			"resource_class": "PUBLIC",
		},
		"mutations": mutations,
	}

	status, _, data := doJSON(t, http.MethodPost, base+"/acp/v1/counterfactual", body)
	if status != http.StatusOK {
		t.Fatalf("got %d, want 200", status)
	}

	results, _ := data["results"].([]interface{})
	if len(results) != len(labels) {
		t.Fatalf("expected %d results, got %d", len(labels), len(results))
	}
	for i, rr := range results {
		rm := rr.(map[string]interface{})
		if rm["label"] != labels[i] {
			t.Fatalf("result[%d] label=%v, want %q", i, rm["label"], labels[i])
		}
	}
}

// TestServer_Counterfactual_UnknownResourceClass falls back to PUBLIC for unknown values.
func TestServer_Counterfactual_UnknownResourceClass(t *testing.T) {
	base := startServer(t)
	rc := "UNKNOWN_CLASS"
	body := map[string]interface{}{
		"base": map[string]interface{}{
			"agent_id":       "cf-rc-agent",
			"capability":     "acp:cap:data.read",
			"resource":       "metrics/public",
			"resource_class": rc, // unknown
		},
		"mutations": []interface{}{
			map[string]interface{}{"label": "baseline"},
		},
	}
	status, _, data := doJSON(t, http.MethodPost, base+"/acp/v1/counterfactual", body)
	if status != http.StatusOK {
		t.Fatalf("got %d, want 200", status)
	}
	// data.read + UNKNOWN (→ PUBLIC, RS=0) with nil mutation → APPROVED
	results, _ := data["results"].([]interface{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result")
	}
	r0 := results[0].(map[string]interface{})
	if r0["decision"] != "APPROVED" {
		t.Fatalf("decision=%v, want APPROVED (unknown RC defaults to PUBLIC)", r0["decision"])
	}
	_ = strings.ToUpper(rc) // use strings package to avoid import error
}
