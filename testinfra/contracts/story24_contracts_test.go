package contracts

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
)

func TestStory24NoisePackAssessmentContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	standardState := filepath.Join(t.TempDir(), "standard-state.json")
	assessmentState := filepath.Join(t.TempDir(), "assessment-state.json")
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "first-offer-noise-pack", "repos")

	standard := runJSONCommand(t, []string{"scan", "--path", scanPath, "--state", standardState, "--profile", "standard", "--json"})
	assessment := runJSONCommand(t, []string{"scan", "--path", scanPath, "--state", assessmentState, "--profile", "assessment", "--json"})
	standardExpected := mustLoadStory24Expected(t, repoRoot, "scenarios/wrkr/first-offer-noise-pack/expected/standard-scan.json")
	assessmentExpected := mustLoadStory24Expected(t, repoRoot, "scenarios/wrkr/first-offer-noise-pack/expected/assessment-scan.json")
	if projected := projectStory24NoisePackScan(t, standard); !reflect.DeepEqual(projected, standardExpected) {
		t.Fatalf("standard noise-pack contract drifted\nprojected=%v\nexpected=%v", projected, standardExpected)
	}
	if projected := projectStory24NoisePackScan(t, assessment); !reflect.DeepEqual(projected, assessmentExpected) {
		t.Fatalf("assessment noise-pack contract drifted\nprojected=%v\nexpected=%v", projected, assessmentExpected)
	}
}

func TestStory24DuplicatePathFixtureContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	fixturePath := filepath.Join(repoRoot, "scenarios", "wrkr", "first-offer-duplicate-paths", "action_path_fixture.json")
	payload, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read duplicate path fixture: %v", err)
	}

	var fixture struct {
		AttackPaths []riskattack.ScoredPath `json:"attack_paths"`
		Inventory   agginventory.Inventory  `json:"inventory"`
	}
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatalf("parse duplicate path fixture: %v", err)
	}

	paths, choice := risk.BuildActionPaths(fixture.AttackPaths, &fixture.Inventory)
	expected := mustLoadStory24Expected(t, repoRoot, "scenarios/wrkr/first-offer-duplicate-paths/expected/action-paths.json")
	if projected := projectStory24DuplicateFixture(paths, choice); !reflect.DeepEqual(projected, expected) {
		t.Fatalf("duplicate-path fixture contract drifted\nprojected=%v\nexpected=%v", projected, expected)
	}
}

func TestStory24ReportUsefulnessContract(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "first-offer-mixed-governance", "repos")
	_ = runJSONCommand(t, []string{"scan", "--path", scanPath, "--state", statePath, "--profile", "assessment", "--json"})
	reportPayload := runReportJSON(t, statePath, []string{"--template", "operator", "--share-profile", "internal", "--top", "5"})
	expected := mustLoadStory24Expected(t, repoRoot, "scenarios/wrkr/first-offer-mixed-governance/expected/assessment-report.json")
	if projected := projectStory24MixedGovernanceReport(t, reportPayload); !reflect.DeepEqual(projected, expected) {
		t.Fatalf("mixed-governance report usefulness contract drifted\nprojected=%v\nexpected=%v", projected, expected)
	}
}

func mustLoadStory24Expected(t *testing.T, repoRoot, rel string) map[string]any {
	t.Helper()

	payload, err := os.ReadFile(filepath.Join(repoRoot, rel))
	if err != nil {
		t.Fatalf("read expected fixture %s: %v", rel, err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("parse expected fixture %s: %v", rel, err)
	}
	return out
}

func projectStory24NoisePackScan(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()

	return map[string]any{
		"status":            story24RequireString(t, payload, "status"),
		"findings_count":    float64(len(story24RequireSlice(t, payload, "findings"))),
		"top_finding_types": story24ProjectTopFindingTypes(t, payload),
		"action_path_count": float64(len(story24OptionalSlice(payload, "action_paths"))),
		"action_paths":      story24ProjectActionPaths(t, story24OptionalSlice(payload, "action_paths")),
		"control_first":     story24ProjectOptionalControlFirst(t, payload["action_path_to_control_first"]),
		"activation": map[string]any{
			"eligible_count": float64(story24RequireInt(t, story24RequireMap(t, payload, "activation"), "eligible_count")),
			"message":        story24RequireString(t, story24RequireMap(t, payload, "activation"), "message"),
			"item_classes":   story24ProjectActivationClasses(t, story24RequireMap(t, payload, "activation")),
		},
	}
}

func projectStory24DuplicateFixture(paths []risk.ActionPath, choice *risk.ActionPathToControlFirst) map[string]any {
	out := map[string]any{
		"action_path_count": float64(len(paths)),
		"action_paths":      story24ProjectRiskActionPaths(paths),
	}
	if choice == nil {
		out["control_first"] = nil
		return out
	}
	out["control_first"] = map[string]any{
		"summary": map[string]any{
			"total_paths":                    float64(choice.Summary.TotalPaths),
			"write_capable_paths":            float64(choice.Summary.WriteCapablePaths),
			"production_target_backed_paths": float64(choice.Summary.ProductionTargetBackedPaths),
			"govern_first_paths":             float64(choice.Summary.GovernFirstPaths),
		},
		"path": story24ProjectRiskActionPath(choice.Path),
	}
	return out
}

func projectStory24MixedGovernanceReport(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()

	summary := story24RequireMap(t, payload, "summary")
	assessmentSummary := story24RequireMap(t, payload, "assessment_summary")
	return map[string]any{
		"status":         story24RequireString(t, payload, "status"),
		"top_risk_types": story24ProjectSummaryRiskTypes(t, summary),
		"action_paths":   story24ProjectActionPaths(t, story24RequireSlice(t, payload, "action_paths")),
		"control_first":  story24ProjectRequiredControlFirst(t, story24RequireMap(t, payload, "action_path_to_control_first")),
		"assessment_summary": map[string]any{
			"governable_path_count":               float64(story24RequireInt(t, assessmentSummary, "governable_path_count")),
			"write_capable_path_count":            float64(story24RequireInt(t, assessmentSummary, "write_capable_path_count")),
			"production_target_backed_path_count": float64(story24RequireInt(t, assessmentSummary, "production_target_backed_path_count")),
			"ownerless_exposure":                  story24RequireMap(t, assessmentSummary, "ownerless_exposure"),
			"identity_exposure_summary":           story24RequireMap(t, assessmentSummary, "identity_exposure_summary"),
			"identity_to_review_first":            story24ProjectIdentityActionTarget(t, story24RequireMap(t, assessmentSummary, "identity_to_review_first")),
			"identity_to_revoke_first":            story24ProjectIdentityActionTarget(t, story24RequireMap(t, assessmentSummary, "identity_to_revoke_first")),
		},
		"exposure_groups": story24ProjectExposureGroups(t, story24RequireSlice(t, payload, "exposure_groups")),
	}
}

func story24ProjectTopFindingTypes(t *testing.T, payload map[string]any) []any {
	t.Helper()

	topFindings := story24RequireSlice(t, payload, "top_findings")
	out := make([]any, 0, len(topFindings))
	for _, item := range topFindings {
		record := story24RequireMapItem(t, item, "top_finding")
		finding := story24RequireMap(t, record, "finding")
		out = append(out, story24RequireString(t, finding, "finding_type"))
	}
	return out
}

func story24ProjectSummaryRiskTypes(t *testing.T, summary map[string]any) []any {
	t.Helper()

	topRisks := story24RequireSlice(t, summary, "top_risks")
	out := make([]any, 0, len(topRisks))
	for _, item := range topRisks {
		record := story24RequireMapItem(t, item, "top_risk")
		out = append(out, story24RequireString(t, record, "finding_type"))
	}
	return out
}

func story24ProjectActivationClasses(t *testing.T, activation map[string]any) []any {
	t.Helper()

	items := story24RequireSlice(t, activation, "items")
	out := make([]any, 0, len(items))
	for _, item := range items {
		record := story24RequireMapItem(t, item, "activation_item")
		out = append(out, story24RequireString(t, record, "item_class"))
	}
	return out
}

func story24ProjectActionPaths(t *testing.T, items []any) []any {
	t.Helper()

	out := make([]any, 0, len(items))
	for _, item := range items {
		record := story24RequireMapItem(t, item, "action_path")
		projected := map[string]any{
			"path_id":                story24RequireString(t, record, "path_id"),
			"repo":                   story24RequireString(t, record, "repo"),
			"tool_type":              story24RequireString(t, record, "tool_type"),
			"recommended_action":     story24RequireString(t, record, "recommended_action"),
			"business_state_surface": story24RequireString(t, record, "business_state_surface"),
		}
		if ownerSource, ok := record["owner_source"].(string); ok && ownerSource != "" {
			projected["owner_source"] = ownerSource
		}
		if ownershipStatus, ok := record["ownership_status"].(string); ok && ownershipStatus != "" {
			projected["ownership_status"] = ownershipStatus
		}
		out = append(out, projected)
	}
	return out
}

func story24ProjectOptionalControlFirst(t *testing.T, raw any) any {
	t.Helper()
	if raw == nil {
		return nil
	}
	return story24ProjectRequiredControlFirst(t, story24RequireMapItem(t, raw, "action_path_to_control_first"))
}

func story24ProjectRequiredControlFirst(t *testing.T, controlFirst map[string]any) map[string]any {
	t.Helper()

	path := story24RequireMap(t, controlFirst, "path")
	summary := story24RequireMap(t, controlFirst, "summary")
	projected := map[string]any{
		"summary": map[string]any{
			"total_paths":                    float64(story24RequireInt(t, summary, "total_paths")),
			"write_capable_paths":            float64(story24RequireInt(t, summary, "write_capable_paths")),
			"production_target_backed_paths": float64(story24RequireInt(t, summary, "production_target_backed_paths")),
			"govern_first_paths":             float64(story24RequireInt(t, summary, "govern_first_paths")),
		},
		"path": map[string]any{
			"path_id":            story24RequireString(t, path, "path_id"),
			"repo":               story24RequireString(t, path, "repo"),
			"tool_type":          story24RequireString(t, path, "tool_type"),
			"recommended_action": story24RequireString(t, path, "recommended_action"),
		},
	}
	if surface, ok := path["business_state_surface"].(string); ok && surface != "" {
		projected["path"].(map[string]any)["business_state_surface"] = surface
	}
	return projected
}

func story24ProjectIdentityActionTarget(t *testing.T, target map[string]any) map[string]any {
	t.Helper()

	return map[string]any{
		"execution_identity":        story24RequireString(t, target, "execution_identity"),
		"path_count":                float64(story24RequireInt(t, target, "path_count")),
		"write_capable_path_count":  float64(story24RequireInt(t, target, "write_capable_path_count")),
		"shared_execution_identity": story24RequireBool(t, target, "shared_execution_identity"),
		"standing_privilege":        story24RequireBool(t, target, "standing_privilege"),
	}
}

func story24ProjectExposureGroups(t *testing.T, groups []any) []any {
	t.Helper()

	out := make([]any, 0, len(groups))
	for _, item := range groups {
		group := story24RequireMapItem(t, item, "exposure_group")
		out = append(out, map[string]any{
			"group_id":               story24RequireString(t, group, "group_id"),
			"tool_types":             story24RequireSlice(t, group, "tool_types"),
			"delivery_chain_status":  story24RequireString(t, group, "delivery_chain_status"),
			"business_state_surface": story24RequireString(t, group, "business_state_surface"),
			"recommended_action":     story24RequireString(t, group, "recommended_action"),
			"path_count":             float64(story24RequireInt(t, group, "path_count")),
			"path_ids":               story24RequireSlice(t, group, "path_ids"),
		})
	}
	return out
}

func story24ProjectRiskActionPaths(paths []risk.ActionPath) []any {
	out := make([]any, 0, len(paths))
	for _, path := range paths {
		out = append(out, story24ProjectRiskActionPath(path))
	}
	return out
}

func story24ProjectRiskActionPath(path risk.ActionPath) map[string]any {
	return map[string]any{
		"path_id":                   path.PathID,
		"repo":                      path.Repo,
		"tool_type":                 path.ToolType,
		"recommended_action":        path.RecommendedAction,
		"delivery_chain_status":     path.DeliveryChainStatus,
		"production_target_status":  path.ProductionTargetStatus,
		"production_write":          path.ProductionWrite,
		"execution_identity_status": path.ExecutionIdentityStatus,
		"business_state_surface":    path.BusinessStateSurface,
	}
}

func story24RequireMapItem(t *testing.T, value any, label string) map[string]any {
	t.Helper()
	record, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected %s object, got %T", label, value)
	}
	return record
}

func story24RequireMap(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()
	return story24RequireMapItem(t, payload[key], key)
}

func story24RequireSlice(t *testing.T, payload map[string]any, key string) []any {
	t.Helper()
	value, ok := payload[key].([]any)
	if !ok {
		t.Fatalf("expected %s array, got %T", key, payload[key])
	}
	return value
}

func story24OptionalSlice(payload map[string]any, key string) []any {
	value, ok := payload[key].([]any)
	if !ok {
		return nil
	}
	return value
}

func story24RequireString(t *testing.T, payload map[string]any, key string) string {
	t.Helper()
	value, ok := payload[key].(string)
	if !ok {
		t.Fatalf("expected %s string, got %T", key, payload[key])
	}
	return value
}

func story24RequireInt(t *testing.T, payload map[string]any, key string) int {
	t.Helper()
	switch value := payload[key].(type) {
	case float64:
		if value != math.Trunc(value) {
			t.Fatalf("expected %s integer value, got %v", key, value)
		}
		return int(value)
	case int:
		return value
	default:
		t.Fatalf("expected %s numeric value, got %T", key, payload[key])
		return 0
	}
}

func story24RequireBool(t *testing.T, payload map[string]any, key string) bool {
	t.Helper()
	value, ok := payload[key].(bool)
	if !ok {
		t.Fatalf("expected %s bool, got %T", key, payload[key])
	}
	return value
}
