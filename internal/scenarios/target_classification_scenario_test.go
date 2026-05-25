//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestTargetClassificationScenario(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "target-classification", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
	actionPaths := requireArray(t, payload, "action_paths")

	releasePath := findActionPathByLocation(t, actionPaths, ".github/workflows/release.yml")
	if releasePath["target_class"] != "production_impacting" || releasePath["action_path_type"] != "ci_cd_workflow" {
		t.Fatalf("expected release workflow production/ci-cd classification, got %v", releasePath)
	}

	openAPIPath := findActionPathByLocation(t, actionPaths, "openapi/payments-openapi.yaml")
	if openAPIPath["target_class"] != "customer_data_adjacent" || openAPIPath["action_path_type"] != "plain_source_code" {
		t.Fatalf("expected openapi customer-data/plain-source classification, got %v", openAPIPath)
	}

	codexPath := findActionPathByLocation(t, actionPaths, ".codex/config.toml")
	if codexPath["target_class"] != "developer_productivity" || codexPath["action_path_type"] != "ai_assisted_workflow" {
		t.Fatalf("expected codex config productivity/ai-workflow classification, got %v", codexPath)
	}
}
