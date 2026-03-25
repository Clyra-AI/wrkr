//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestWorkflowCapabilitiesScenario(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "workflow-capabilities", "repos")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})

	findings, ok := payload["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}

	var workflowFinding map[string]any
	for _, item := range findings {
		typed, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if typed["finding_type"] == "ci_autonomy" {
			workflowFinding = typed
			break
		}
	}
	if workflowFinding == nil {
		t.Fatalf("expected ci_autonomy finding, got %v", findings)
	}
	permissions := toStringSlice(workflowFinding["permissions"])
	for _, required := range []string{"repo.write", "pull_request.write", "merge.execute", "deploy.write", "db.write", "iac.write"} {
		if !containsString(permissions, required) {
			t.Fatalf("expected permission %q in %v", required, permissions)
		}
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
