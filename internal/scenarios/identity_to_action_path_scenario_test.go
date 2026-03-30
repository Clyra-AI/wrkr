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
	statePath := filepath.Join(t.TempDir(), "state.json")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})

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

	reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--json"})
	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected report summary, got %T", reportPayload["summary"])
	}
	assessmentSummary, ok := summary["assessment_summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected assessment_summary, got %v", summary["assessment_summary"])
	}
	identitySummary, ok := assessmentSummary["identity_exposure_summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected identity_exposure_summary, got %v", assessmentSummary["identity_exposure_summary"])
	}
	if identitySummary["total_non_human_identities_observed"] == float64(0) {
		t.Fatalf("expected non-zero identity exposure summary, got %v", identitySummary)
	}
	reviewFirst, ok := assessmentSummary["identity_to_review_first"].(map[string]any)
	if !ok {
		t.Fatalf("expected identity_to_review_first, got %v", assessmentSummary["identity_to_review_first"])
	}
	if reviewFirst["execution_identity_type"] != "github_app" {
		t.Fatalf("expected github_app review target, got %v", reviewFirst)
	}
}
