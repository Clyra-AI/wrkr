package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestReportPairedShareProfileWritesExternalArtifactsAndPrivateJoinMap(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	mdPath := filepath.Join(tmp, "report.md")
	evidencePath := filepath.Join(tmp, "report-evidence.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed to seed state: %d", code)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"report",
		"--state", statePath,
		"--md",
		"--md-path", mdPath,
		"--evidence-json",
		"--evidence-json-path", evidencePath,
		"--paired-share-profile", "customer-redacted",
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected paired report to succeed, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	paths, ok := payload["artifact_paths"].(map[string]any)
	if !ok {
		t.Fatalf("expected artifact_paths map, got %T", payload["artifact_paths"])
	}
	required := []string{
		"markdown",
		"markdown_customer_redacted",
		"evidence_json",
		"evidence_json_customer_redacted",
		"private_join_map",
	}
	for _, key := range required {
		path, ok := paths[key].(string)
		if !ok || path == "" {
			t.Fatalf("expected artifact path for %s, got %v", key, paths[key])
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s at %s: %v", key, path, err)
		}
	}
}
