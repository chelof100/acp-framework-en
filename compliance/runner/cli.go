package main

import (
	"flag"
	"fmt"
	"os"
)

// Config holds all CLI flags for the runner.
type Config struct {
	Mode   string // "library" | "http"
	URL    string // HTTP backend admission URL
	Dir    string // directory with test case JSON files
	Out    string // output report file (empty = stdout)
	Strict bool   // exit 1 on any failure
}

func parseFlags() Config {
	mode   := flag.String("mode",   "library",                        "Backend mode: library|http")
	url    := flag.String("url",    "http://localhost:8080/admission", "HTTP backend URL (--mode=http only)")
	dir    := flag.String("dir",    "testcases",                      "Directory with test case JSON files")
	out    := flag.String("out",    "",                               "Output report JSON file (default: stdout)")
	strict := flag.Bool("strict",  true,                              "Exit 1 on any failure")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "ACP Compliance Runner (ACR-1.0) — sequence mode\n\n")
		fmt.Fprintf(os.Stderr, "Usage: acp-risk-runner [flags]\n\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  acp-risk-runner --mode library --dir testcases\n")
		fmt.Fprintf(os.Stderr, "  acp-risk-runner --mode http --url http://localhost:8080/admission --dir testcases\n")
		fmt.Fprintf(os.Stderr, "  acp-risk-runner --mode library --dir testcases --out report.json\n")
	}
	flag.Parse()

	return Config{
		Mode:   *mode,
		URL:    *url,
		Dir:    *dir,
		Out:    *out,
		Strict: *strict,
	}
}
