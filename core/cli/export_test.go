package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportInventoryAnonymize(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"export", "--format", "inventory", "--anonymize", "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("export failed: %d (%s)", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse export payload: %v", err)
	}
	org, _ := payload["org"].(string)
	if org == "" || !strings.HasPrefix(org, "org-") {
		t.Fatalf("expected anonymized org prefix org-*, got %q", org)
	}
}

func TestExportAppendixJSONAndCSV(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	csvDir := filepath.Join(tmp, "appendix-csv")
	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"export", "--format", "appendix", "--csv-dir", csvDir, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("appendix export failed: %d (%s)", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse appendix payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected status: %v", payload["status"])
	}
	appendix, ok := payload["appendix"].(map[string]any)
	if !ok {
		t.Fatalf("expected appendix object, got %T", payload["appendix"])
	}
	for _, key := range []string{"inventory_rows", "privilege_rows", "approval_gap_rows", "regulatory_rows"} {
		if _, exists := appendix[key]; !exists {
			t.Fatalf("appendix missing key %s: %v", key, appendix)
		}
	}
	csvFiles, ok := payload["csv_files"].(map[string]any)
	if !ok {
		t.Fatalf("expected csv_files map, got %T", payload["csv_files"])
	}
	for _, key := range []string{"inventory", "privilege_map", "approval_gap", "regulatory_matrix"} {
		value, exists := csvFiles[key]
		if !exists {
			t.Fatalf("missing csv key %s in %v", key, csvFiles)
		}
		if _, ok := value.(string); !ok {
			t.Fatalf("expected csv path string for %s, got %T", key, value)
		}
	}
}

func TestExportInventoryRejectsCSVDir(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"export", "--format", "inventory", "--csv-dir", filepath.Join(tmp, "csv"), "--state", statePath, "--json"}, &out, &errOut); code != 6 {
		t.Fatalf("expected exit 6, got %d (%s)", code, errOut.String())
	}
}
