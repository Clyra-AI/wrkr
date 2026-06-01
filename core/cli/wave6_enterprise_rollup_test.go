package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestWave6ReportJSONIncludesExecutiveRollupAndGovernedUsageMetrics(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
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
		"--template", "agent-action-bom",
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected report to succeed, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary payload, got %T", payload["summary"])
	}
	if _, ok := summary["executive_rollup"].(map[string]any); !ok {
		t.Fatalf("expected summary executive_rollup, got %v", summary["executive_rollup"])
	}
	summaryMetrics, ok := summary["governed_usage_metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary governed_usage_metrics, got %v", summary["governed_usage_metrics"])
	}
	if summaryMetrics["audit_exports"] == nil {
		t.Fatalf("expected audit_exports metric, got %v", summaryMetrics)
	}

	bom, ok := payload["agent_action_bom"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level agent_action_bom, got %T", payload["agent_action_bom"])
	}
	bomSummary, ok := bom["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected BOM summary, got %T", bom["summary"])
	}
	if _, ok := bomSummary["executive_rollup"].(map[string]any); !ok {
		t.Fatalf("expected BOM executive_rollup, got %v", bomSummary["executive_rollup"])
	}
	if bomSummary["governed_usage_metrics"] == nil {
		t.Fatalf("expected BOM governed_usage_metrics, got %v", bomSummary["governed_usage_metrics"])
	}
}

func TestWave6EvidenceJSONIncludesGovernedUsageMetrics(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed to seed state: %d", code)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"evidence",
		"--state", statePath,
		"--frameworks", "soc2",
		"--output", filepath.Join(tmp, "wrkr-evidence"),
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected evidence to succeed, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse evidence payload: %v", err)
	}
	metrics, ok := payload["governed_usage_metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected governed_usage_metrics, got %T", payload["governed_usage_metrics"])
	}
	if metrics["audit_exports"] == nil {
		t.Fatalf("expected audit_exports metric, got %v", metrics)
	}
}
