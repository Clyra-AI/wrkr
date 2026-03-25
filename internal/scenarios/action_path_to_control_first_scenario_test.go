//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestActionPathToControlFirstScenario(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "agent-policy-outcomes", "repos")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})

	actionPaths, ok := payload["action_paths"].([]any)
	if !ok || len(actionPaths) == 0 {
		t.Fatalf("expected action_paths payload, got %v", payload["action_paths"])
	}
	choice, ok := payload["action_path_to_control_first"].(map[string]any)
	if !ok {
		t.Fatalf("expected action_path_to_control_first payload, got %v", payload["action_path_to_control_first"])
	}
	path, ok := choice["path"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested control-first path, got %v", choice["path"])
	}
	if action := path["recommended_action"]; action == "" {
		t.Fatalf("expected recommended_action on control-first path, got %v", path)
	}
	topAttackPaths, ok := payload["top_attack_paths"].([]any)
	if !ok || len(topAttackPaths) == 0 {
		t.Fatalf("expected legacy top_attack_paths to remain available, got %v", payload["top_attack_paths"])
	}
}
