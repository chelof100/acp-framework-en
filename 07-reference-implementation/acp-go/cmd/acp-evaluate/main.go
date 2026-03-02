// Command acp-evaluate is the ACP reference IUT (Implementation Under Test).
// It reads an ACP-TS-1.1 test vector from STDIN and writes the evaluation
// result to STDOUT as JSON, conforming to the ACP-IUT-PROTOCOL-1.0 spec.
//
// Usage:
//
//	echo '<vector-json>' | acp-evaluate
//	acp-evaluate --manifest
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/chelof100/acp-framework/acp-go/pkg/iut"
)

// manifest is printed when --manifest flag is given (ACR-1.0 §3.1).
var manifest = map[string]interface{}{
	"name":               "acp-evaluate",
	"version":            "1.0.0",
	"acp_version":        "1.1",
	"conformance_levels": []string{"L1", "L2"},
	"contact":            "https://github.com/chelof100/acp-framework-en",
}

func main() {
	showManifest := flag.Bool("manifest", false, "print implementation manifest as JSON and exit")
	flag.Parse()

	if *showManifest {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(manifest); err != nil {
			fatal("marshal manifest", err)
		}
		os.Exit(0)
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal("read stdin", err)
	}

	var vec iut.TestVector
	if err := json.Unmarshal(data, &vec); err != nil {
		fatal("parse vector", err)
	}

	resp := iut.Evaluate(vec)

	out, err := json.Marshal(resp)
	if err != nil {
		fatal("marshal response", err)
	}
	fmt.Println(string(out))
}

func fatal(msg string, err error) {
	fmt.Fprintf(os.Stderr, "acp-evaluate: %s: %v\n", msg, err)
	os.Exit(1)
}
