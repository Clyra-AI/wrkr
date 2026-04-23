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
	statePath := filepath.Join(t.TempDir(), "state.json")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})

	agentMap, ok := payload["agent_privilege_map"].([]any)
	if !ok || len(agentMap) == 0 {
		t.Fatalf("expected agent_privilege_map payload, got %v", payload["agent_privilege_map"])
	}

	explicit := findPrivilegeEntryByLocation(agentMap, ".github/workflows/owned.yml")
	if explicit == nil {
		t.Fatalf("expected explicit ownership entry, got %v", agentMap)
	}
	if explicit["operational_owner"] != "@local/security" || explicit["ownership_status"] != "explicit" || explicit["ownership_state"] != "explicit_owner" {
		t.Fatalf("expected explicit operational owner, got %v", explicit)
	}
	if confidence, ok := explicit["ownership_confidence"].(float64); !ok || confidence < 0.9 {
		t.Fatalf("expected high explicit owner confidence, got %v", explicit)
	}

	inferred := findPrivilegeEntryByLocation(agentMap, ".github/workflows/inferred.yml")
	if inferred == nil {
		t.Fatalf("expected inferred ownership entry, got %v", agentMap)
	}
	if inferred["ownership_status"] != "inferred" || inferred["ownership_state"] != "inferred_owner" {
		t.Fatalf("expected inferred ownership status, got %v", inferred)
	}

	unresolved := findPrivilegeEntryByLocation(agentMap, ".github/workflows/release.yml")
	if unresolved == nil {
		t.Fatalf("expected unresolved ownership entry, got %v", agentMap)
	}
	if unresolved["ownership_status"] != "unresolved" || unresolved["ownership_state"] != "conflicting_owner" {
		t.Fatalf("expected conflicting ownership status, got %v", unresolved)
	}

	actionPaths, ok := payload["action_paths"].([]any)
	if !ok || len(actionPaths) == 0 {
		t.Fatalf("expected action_paths payload, got %v", payload["action_paths"])
	}
	firstPath, ok := actionPaths[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected action path type: %T", actionPaths[0])
	}
	if firstPath["recommended_action"] != "control" {
		t.Fatalf("expected strongest control-first path to rank first, got %v", firstPath)
	}
	foundWeakOwnership := false
	for _, item := range actionPaths {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if row["owner_source"] == "multi_repo_conflict" {
			foundWeakOwnership = true
			break
		}
	}
	if !foundWeakOwnership {
		t.Fatalf("expected weak ownership path to remain visible, got %v", actionPaths)
	}

	reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--json"})
	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected report summary, got %T", reportPayload["summary"])
	}
	assessmentSummary, ok := summary["assessment_summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected report assessment_summary, got %v", summary["assessment_summary"])
	}
	ownerlessExposure, ok := assessmentSummary["ownerless_exposure"].(map[string]any)
	if !ok {
		t.Fatalf("expected ownerless_exposure summary, got %v", assessmentSummary["ownerless_exposure"])
	}
	if ownerlessExposure["conflict_owner_paths"] == float64(0) {
		t.Fatalf("expected conflict_owner_paths > 0, got %v", ownerlessExposure)
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
