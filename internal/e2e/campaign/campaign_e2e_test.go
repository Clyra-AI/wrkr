package campaigne2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestE2ECampaignAggregateFromScanArtifacts(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir alpha repo: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(reposPath, "beta"), 0o755); err != nil {
		t.Fatalf("mkdir beta repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reposPath, "alpha", "AGENTS.md"), []byte("# alpha"), 0o600); err != nil {
		t.Fatalf("write alpha AGENTS.md: %v", err)
	}

	scanAPath := filepath.Join(tmp, "scan-a.json")
	scanBPath := filepath.Join(tmp, "scan-b.json")
	runScanAndPersistJSON(t, reposPath, filepath.Join(tmp, "state-a.json"), scanAPath)
	runScanAndPersistJSON(t, reposPath, filepath.Join(tmp, "state-b.json"), scanBPath)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"campaign", "aggregate", "--input-glob", filepath.Join(tmp, "scan-*.json"), "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("campaign aggregate failed: %d (%s)", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse campaign payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected status: %v", payload["status"])
	}
	campaign, ok := payload["campaign"].(map[string]any)
	if !ok {
		t.Fatalf("expected campaign object, got %T", payload["campaign"])
	}
	methodology, ok := campaign["methodology"].(map[string]any)
	if !ok {
		t.Fatalf("expected methodology object, got %T", campaign["methodology"])
	}
	if methodology["scan_count"] != float64(2) {
		t.Fatalf("expected scan_count=2, got %v", methodology["scan_count"])
	}
	metrics, ok := campaign["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected metrics object, got %T", campaign["metrics"])
	}
	for _, key := range []string{"approved_tools", "unapproved_tools", "unknown_tools", "approved_percent", "unapproved_percent", "unknown_percent"} {
		if _, exists := metrics[key]; !exists {
			t.Fatalf("expected metrics key %s, got %v", key, metrics)
		}
	}
	segments, ok := campaign["segments"].(map[string]any)
	if !ok {
		t.Fatalf("expected segments object, got %T", campaign["segments"])
	}
	if _, ok := segments["org_size_bands"]; !ok {
		t.Fatalf("expected org_size_bands in segments, got %v", segments)
	}
}

func runScanAndPersistJSON(t *testing.T, scanPath, statePath, outputPath string) {
	t.Helper()

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, errOut.String())
	}
	if err := os.WriteFile(outputPath, out.Bytes(), 0o600); err != nil {
		t.Fatalf("write scan artifact: %v", err)
	}
}
