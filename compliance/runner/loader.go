package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// loadTestCases reads all .json files in dir and parses them as TestCase objects.
// Files are sorted alphabetically for deterministic execution order.
func loadTestCases(dir string) ([]TestCase, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("open test case dir %q: %w", dir, err)
	}

	// Collect and sort filenames for deterministic order.
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	var cases []TestCase
	for _, name := range names {
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var tc TestCase
		if err := json.Unmarshal(data, &tc); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if tc.ID == "" {
			return nil, fmt.Errorf("%s: missing required field 'id'", path)
		}
		if len(tc.Steps) == 0 {
			return nil, fmt.Errorf("%s: no steps defined", path)
		}
		cases = append(cases, tc)
	}
	return cases, nil
}
