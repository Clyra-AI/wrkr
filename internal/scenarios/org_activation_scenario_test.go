//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestOrgActivationScenario(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "agent-policy-outcomes", "repos")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})

	activation, ok := payload["activation"].(map[string]any)
	if !ok {
		t.Fatalf("expected activation payload, got %v", payload["activation"])
	}
	if activation["target_mode"] != "path" {
		t.Fatalf("expected path activation target, got %v", activation["target_mode"])
	}
	items, ok := activation["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected govern-first activation items, got %v", activation["items"])
	}
	topFindings, ok := payload["top_findings"].([]any)
	if !ok || len(topFindings) == 0 {
		t.Fatalf("expected raw top_findings to remain available, got %v", payload["top_findings"])
	}
	firstItem, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected activation item type: %T", items[0])
	}
	if _, ok := firstItem["item_class"].(string); !ok {
		t.Fatalf("expected item_class on activation item, got %v", firstItem)
	}
}
