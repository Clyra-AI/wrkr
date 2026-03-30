package contracts

import (
	"path/filepath"
	"testing"
)

func TestStory23OwnershipAndIdentityAssessmentSummaryContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "ownership-quality", "repos")
	_ = runJSONCommand(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
	reportPayload := runReportJSON(t, statePath, []string{"--template", "operator", "--share-profile", "internal", "--top", "5"})

	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %T", reportPayload["summary"])
	}
	assessmentSummary, ok := summary["assessment_summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected assessment_summary, got %v", summary["assessment_summary"])
	}
	ownerlessExposure, ok := assessmentSummary["ownerless_exposure"].(map[string]any)
	if !ok {
		t.Fatalf("expected ownerless_exposure summary, got %v", assessmentSummary["ownerless_exposure"])
	}
	for _, key := range []string{"explicit_owner_paths", "inferred_owner_paths", "unresolved_owner_paths", "conflict_owner_paths"} {
		if _, present := ownerlessExposure[key]; !present {
			t.Fatalf("ownerless_exposure missing %q: %v", key, ownerlessExposure)
		}
	}
}

func TestStory23IdentityAndExposureGroupContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "non-human-identities", "repos")
	_ = runJSONCommand(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
	reportPayload := runReportJSON(t, statePath, []string{"--template", "operator", "--share-profile", "internal", "--top", "5"})

	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary object, got %T", reportPayload["summary"])
	}
	assessmentSummary, ok := summary["assessment_summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected assessment_summary, got %v", summary["assessment_summary"])
	}
	for _, key := range []string{"identity_exposure_summary", "identity_to_review_first", "identity_to_revoke_first"} {
		if _, present := assessmentSummary[key]; !present {
			t.Fatalf("assessment_summary missing %q: %v", key, assessmentSummary)
		}
	}
	exposureGroups, ok := reportPayload["exposure_groups"].([]any)
	if !ok || len(exposureGroups) == 0 {
		t.Fatalf("expected additive exposure_groups, got %v", reportPayload["exposure_groups"])
	}
	firstGroup, ok := exposureGroups[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected exposure group type: %T", exposureGroups[0])
	}
	for _, key := range []string{"group_id", "delivery_chain_status", "recommended_action", "path_count", "path_ids"} {
		if _, present := firstGroup[key]; !present {
			t.Fatalf("exposure group missing %q: %v", key, firstGroup)
		}
	}
}

func TestStory23BusinessStateSurfaceContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "workflow-capabilities", "repos")
	scanPayload := runJSONCommand(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})

	actionPaths, ok := scanPayload["action_paths"].([]any)
	if !ok || len(actionPaths) == 0 {
		t.Fatalf("expected action_paths payload, got %v", scanPayload["action_paths"])
	}
	for _, item := range actionPaths {
		path, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if _, present := path["business_state_surface"]; !present {
			t.Fatalf("expected business_state_surface on action path, got %v", path)
		}
	}
}
