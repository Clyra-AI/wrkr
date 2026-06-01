//go:build scenario

package scenarios

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScenarioWave6ExecutiveRollupAndGovernedUsageMetrics(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "wave6-state.json")
	mdPath := filepath.Join(tmp, "wave6-report.md")

	runScenarioCommandJSON(t, []string{"scan", "--path", scanRoot, "--state", statePath, "--json"})
	reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "agent-action-bom", "--json"})

	summary := requireScenarioObject(t, reportPayload, "summary")
	rollup := requireScenarioObject(t, summary, "executive_rollup")
	if rollup["total_groups"].(float64) < 1 || rollup["total_paths"].(float64) < 1 {
		t.Fatalf("expected non-empty executive rollup, got %v", rollup)
	}

	metrics := requireScenarioObject(t, summary, "governed_usage_metrics")
	if metrics["audit_exports"].(float64) < 2 || metrics["active_monitored_action_paths"].(float64) < 1 {
		t.Fatalf("expected non-zero governed usage metrics, got %v", metrics)
	}

	bomSummary := requireScenarioObject(t, requireScenarioObject(t, requireScenarioObject(t, reportPayload, "agent_action_bom"), "summary"), "executive_rollup")
	if bomSummary["total_groups"] != rollup["total_groups"] || bomSummary["total_paths"] != rollup["total_paths"] {
		t.Fatalf("expected BOM rollup to mirror top-level summary, summary=%v bom=%v", rollup, bomSummary)
	}

	bomMetrics := requireScenarioObject(t, requireScenarioObject(t, requireScenarioObject(t, reportPayload, "agent_action_bom"), "summary"), "governed_usage_metrics")
	if bomMetrics["audit_exports"] != metrics["audit_exports"] {
		t.Fatalf("expected BOM governed usage metrics to mirror top-level summary, summary=%v bom=%v", metrics, bomMetrics)
	}

	runScenarioCommandJSON(t, []string{
		"report",
		"--state", statePath,
		"--template", "ciso",
		"--md",
		"--md-path", mdPath,
		"--json",
	})
	payload, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read markdown: %v", err)
	}
	markdown := string(payload)
	rollupAt := strings.Index(markdown, "## Executive Rollup")
	backlogAt := strings.Index(markdown, "## Control Backlog")
	if rollupAt == -1 || backlogAt == -1 || rollupAt > backlogAt {
		t.Fatalf("expected executive rollup ahead of backlog detail, got %q", markdown)
	}
}
