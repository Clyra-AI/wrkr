//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestMCPActionSurfaceScenario(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "mcp-action-surface", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")
	_ = runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
	payload := runScenarioCommandJSON(t, []string{"mcp-list", "--state", statePath, "--json"})

	rows, ok := payload["rows"].([]any)
	if !ok || len(rows) != 1 {
		t.Fatalf("expected one mcp-list row, got %v", payload["rows"])
	}
	first, ok := rows[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected row payload: %T", rows[0])
	}
	privilegeSurface := toStringSlice(first["privilege_surface"])
	if !containsString(privilegeSurface, "admin") {
		t.Fatalf("expected admin privilege surface, got %v", privilegeSurface)
	}
	if first["gateway_coverage"] != "unprotected" {
		t.Fatalf("expected gateway_coverage=unprotected, got %v", first["gateway_coverage"])
	}
}
