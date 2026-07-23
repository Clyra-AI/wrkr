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

	alpha := findPrivilegeEntryByRepoLocation(agentMap, "alpha-service", ".github/workflows/release.yml")
	if alpha == nil {
		t.Fatalf("expected alpha-service ownership entry, got %v", agentMap)
	}
	if alpha["operational_owner"] != "@local/alpha" || alpha["ownership_status"] != "explicit" || alpha["ownership_state"] != "explicit_owner" {
		t.Fatalf("expected repo-local alpha-service owner, got %v", alpha)
	}
	beta := findPrivilegeEntryByRepoLocation(agentMap, "beta-service", ".github/workflows/release.yml")
	if beta == nil {
		t.Fatalf("expected beta-service ownership entry, got %v", agentMap)
	}
	if beta["operational_owner"] != "@local/beta" || beta["ownership_status"] != "explicit" || beta["ownership_state"] != "explicit_owner" {
		t.Fatalf("expected repo-local beta-service owner, got %v", beta)
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
	foundAlpha := false
	foundBeta := false
	for _, item := range actionPaths {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if row["owner_source"] == "multi_repo_conflict" {
			t.Fatalf("did not expect cross-repository owner conflict, got %v", row)
		}
		switch row["repo"] {
		case "alpha-service":
			foundAlpha = row["operational_owner"] == "@local/alpha" && row["ownership_status"] == "explicit"
		case "beta-service":
			foundBeta = row["operational_owner"] == "@local/beta" && row["ownership_status"] == "explicit"
		}
	}
	if !foundAlpha || !foundBeta {
		t.Fatalf("expected both repo-local ownership paths to remain visible, got %v", actionPaths)
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
	if ownerlessExposure["conflict_owner_paths"] != float64(0) {
		t.Fatalf("expected no synthetic cross-repository owner conflicts, got %v", ownerlessExposure)
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

func findPrivilegeEntryByRepoLocation(entries []any, repo string, location string) map[string]any {
	for _, item := range entries {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		repos, _ := entry["repos"].([]any)
		if scenarioArrayContains(repos, repo) && entry["location"] == location {
			return entry
		}
	}
	return nil
}
