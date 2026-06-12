//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestControlEvidenceStateScenario(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "control-evidence-state", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	scanPayload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
	actionPaths := requireArray(t, scanPayload, "action_paths")
	releasePath := findActionPathByLocation(t, actionPaths, ".github/workflows/release.yml")
	if releasePath["control_resolution_state"] != "external_control_reference" {
		t.Fatalf("expected external control reference on scan action path, got %v", releasePath)
	}
	if releasePath["approval_evidence_state"] != "declared" || releasePath["owner_evidence_state"] != "verified" {
		t.Fatalf("expected declared approval evidence and verified owner evidence, got %v", releasePath)
	}

	reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "agent-action-bom", "--share-profile", "internal", "--json"})
	summary := requireObject(t, reportPayload, "summary")
	bom := requireObject(t, summary, "agent_action_bom")
	items := requireArrayFromObject(t, bom, "items")
	first := findActionPathByLocation(t, items, ".github/workflows/release.yml")
	if first["control_resolution_state"] != "external_control_reference" {
		t.Fatalf("expected external control reference on BOM item, got %v", first)
	}
	if first["approval_evidence_state"] != "declared" || first["owner_evidence_state"] != "verified" {
		t.Fatalf("expected declared approval evidence and verified owner evidence on BOM item, got %v", first)
	}
}

func findActionPathByLocation(t *testing.T, items []any, location string) map[string]any {
	t.Helper()
	for _, item := range items {
		obj := requireObjectItem(t, item)
		if obj["location"] == location {
			return obj
		}
	}
	t.Fatalf("expected location %q in %v", location, items)
	return nil
}
