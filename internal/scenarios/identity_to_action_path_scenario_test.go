//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestIdentityToActionPathScenario(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "non-human-identities", "repos")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})

	actionPaths, ok := payload["action_paths"].([]any)
	if !ok || len(actionPaths) == 0 {
		t.Fatalf("expected action_paths payload, got %v", payload["action_paths"])
	}
	first, ok := actionPaths[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected action path payload: %T", actionPaths[0])
	}
	if first["execution_identity_status"] != "known" {
		t.Fatalf("expected execution_identity_status=known, got %v", first["execution_identity_status"])
	}
	if first["execution_identity_type"] != "github_app" {
		t.Fatalf("expected github_app execution identity, got %v", first["execution_identity_type"])
	}
}
