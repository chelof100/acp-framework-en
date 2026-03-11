package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// vectorsDir returns the absolute path to the test-vectors directory.
func vectorsDir(t *testing.T) string {
	t.Helper()
	// From cmd/acp-evaluate/ go up 5 levels: cmd/acp-evaluate → cmd → acp-go →
	// 07-reference-implementation → ACP-PROTOCOL-EN → … → 03-acp-protocol/test-vectors
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// file = …/cmd/acp-evaluate/main_test.go
	base := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(file)))))
	dir := filepath.Join(base, "03-acp-protocol", "test-vectors")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("test-vectors dir not found at %s — skipping: %v", dir, err)
	}
	return dir
}

// buildBinary compiles acp-evaluate and returns the path to the binary.
// The binary is placed in a temp dir and cleaned up when the test ends.
func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "acp-evaluate")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	// Resolve the module root (acp-go/).
	_, file, _, _ := runtime.Caller(0)
	modRoot := filepath.Dir(filepath.Dir(filepath.Dir(file))) // …/acp-go
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/acp-evaluate/")
	cmd.Dir = modRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build acp-evaluate: %v\n%s", err, out)
	}
	return bin
}

// runVector pipes a vector JSON file to acp-evaluate and returns the parsed response.
func runVector(t *testing.T, bin, vectorPath string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read vector %s: %v", vectorPath, err)
	}
	cmd := exec.Command(bin)
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("acp-evaluate failed for %s: %v\nstdout: %s", filepath.Base(vectorPath), err, out)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("parse response from %s: %v\nraw: %s", filepath.Base(vectorPath), err, out)
	}
	return resp
}

// TestEvaluate_AllVectors runs acp-evaluate against every test vector and
// verifies the decision matches the expected field.
func TestEvaluate_AllVectors(t *testing.T) {
	bin := buildBinary(t)
	dir := vectorsDir(t)

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}

	vectorCount := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("read %s: %v", e.Name(), err)
			continue
		}
		var vec map[string]interface{}
		if err := json.Unmarshal(data, &vec); err != nil {
			t.Errorf("parse %s: %v", e.Name(), err)
			continue
		}
		expected, _ := vec["expected"].(map[string]interface{})
		if expected == nil {
			continue // not a evaluatable vector (e.g. README)
		}
		wantDecision, _ := expected["decision"].(string)
		if wantDecision == "" {
			continue
		}

		t.Run(e.Name(), func(t *testing.T) {
			resp := runVector(t, bin, path)
			gotDecision, _ := resp["decision"].(string)
			if gotDecision != wantDecision {
				t.Errorf("decision: got %q, want %q", gotDecision, wantDecision)
			}

			// If a specific error_code is expected, check it too.
			if wantCode, _ := expected["error_code"].(string); wantCode != "" {
				gotCode, _ := resp["error_code"].(string)
				if gotCode != wantCode {
					t.Errorf("error_code: got %q, want %q", gotCode, wantCode)
				}
			}
		})
		vectorCount++
	}

	if vectorCount == 0 {
		t.Fatal("no vectors found — check vectorsDir")
	}
	t.Logf("ran %d vectors", vectorCount)
}

// TestEvaluate_Manifest verifies that --manifest flag outputs a valid JSON
// manifest with required fields.
func TestEvaluate_Manifest(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin, "--manifest")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("--manifest failed: %v", err)
	}
	var manifest map[string]interface{}
	if err := json.Unmarshal(out, &manifest); err != nil {
		t.Fatalf("parse manifest: %v\nraw: %s", err, out)
	}
	for _, field := range []string{"name", "version", "acp_version", "conformance_levels"} {
		if manifest[field] == nil {
			t.Errorf("manifest missing field %q", field)
		}
	}
	levels, _ := manifest["conformance_levels"].([]interface{})
	if len(levels) == 0 {
		t.Error("conformance_levels is empty")
	}
}

// TestEvaluate_InvalidJSON verifies that invalid input causes a non-zero exit.
func TestEvaluate_InvalidJSON(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader("{invalid json}")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit for invalid JSON input")
	}
}

// TestEvaluate_EmptyInput verifies that empty stdin causes a non-zero exit.
func TestEvaluate_EmptyInput(t *testing.T) {
	bin := buildBinary(t)
	cmd := exec.Command(bin)
	cmd.Stdin = strings.NewReader("")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit for empty input")
	}
}
