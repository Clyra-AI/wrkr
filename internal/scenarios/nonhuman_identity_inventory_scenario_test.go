//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestNonHumanIdentityInventoryScenario(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "non-human-identities", "repos")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})

	inventoryObj, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory payload, got %T", payload["inventory"])
	}
	identities, ok := inventoryObj["non_human_identities"].([]any)
	if !ok || len(identities) == 0 {
		t.Fatalf("expected non_human_identities inventory, got %v", inventoryObj["non_human_identities"])
	}
	first, ok := identities[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected non-human identity payload: %T", identities[0])
	}
	if first["identity_type"] != "github_app" {
		t.Fatalf("expected github_app identity, got %v", first["identity_type"])
	}
}
