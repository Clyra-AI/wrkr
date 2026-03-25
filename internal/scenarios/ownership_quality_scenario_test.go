//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestOwnershipQualityScenario(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "ownership-quality", "repos")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})

	agentMap, ok := payload["agent_privilege_map"].([]any)
	if !ok || len(agentMap) == 0 {
		t.Fatalf("expected agent_privilege_map payload, got %v", payload["agent_privilege_map"])
	}

	explicit := findPrivilegeEntryByLocation(agentMap, ".github/workflows/owned.yml")
	if explicit == nil {
		t.Fatalf("expected explicit ownership entry, got %v", agentMap)
	}
	if explicit["operational_owner"] != "@local/security" || explicit["ownership_status"] != "explicit" {
		t.Fatalf("expected explicit operational owner, got %v", explicit)
	}

	inferred := findPrivilegeEntryByLocation(agentMap, ".github/workflows/inferred.yml")
	if inferred == nil {
		t.Fatalf("expected inferred ownership entry, got %v", agentMap)
	}
	if inferred["ownership_status"] != "inferred" {
		t.Fatalf("expected inferred ownership status, got %v", inferred)
	}

	unresolved := findPrivilegeEntryByLocation(agentMap, ".github/workflows/release.yml")
	if unresolved == nil {
		t.Fatalf("expected unresolved ownership entry, got %v", agentMap)
	}
	if unresolved["ownership_status"] != "unresolved" {
		t.Fatalf("expected unresolved ownership status, got %v", unresolved)
	}
}

func findPrivilegeEntryByLocation(entries []any, location string) map[string]any {
	for _, item := range entries {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if entry["location"] == location {
			return entry
		}
	}
	return nil
}
