//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestApprovalGapModelingScenario(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "approval-gap-modeling", "repos")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})

	findings, ok := payload["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings payload, got %v", payload["findings"])
	}
	violations := map[string]bool{}
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["finding_type"] == "policy_violation" {
			ruleID, _ := finding["rule_id"].(string)
			if ruleID != "" {
				violations[ruleID] = true
			}
		}
	}
	for _, ruleID := range []string{"WRKR-A001", "WRKR-A002", "WRKR-A009"} {
		if !violations[ruleID] {
			t.Fatalf("expected policy violation %s, got %v", ruleID, violations)
		}
	}

	actionPaths, ok := payload["action_paths"].([]any)
	if !ok || len(actionPaths) == 0 {
		t.Fatalf("expected action_paths payload, got %v", payload["action_paths"])
	}
	first, ok := actionPaths[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected action path payload: %T", actionPaths[0])
	}
	reasons := toStringSlice(first["approval_gap_reasons"])
	for _, expected := range []string{"approval_source_missing", "deployment_gate_ambiguous", "proof_requirement_missing"} {
		if !containsString(reasons, expected) {
			t.Fatalf("expected approval gap reason %q in %v", expected, reasons)
		}
	}
}
