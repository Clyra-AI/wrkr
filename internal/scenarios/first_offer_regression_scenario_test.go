//go:build scenario

package scenarios

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
)

func TestScenarioFirstOfferNoisePackAssessmentSharpening(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "first-offer-noise-pack", "repos")
	standard := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "standard-state.json"), "--profile", "standard", "--json"})
	assessment := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "assessment-state.json"), "--profile", "assessment", "--json"})

	standardGolden := mustLoadFirstOfferExpected(t, repoRoot, "scenarios/wrkr/first-offer-noise-pack/expected/standard-scan.json")
	assessmentGolden := mustLoadFirstOfferExpected(t, repoRoot, "scenarios/wrkr/first-offer-noise-pack/expected/assessment-scan.json")
	standardProjected := projectFirstOfferNoisePackScan(t, standard)
	assessmentProjected := projectFirstOfferNoisePackScan(t, assessment)
	if !reflect.DeepEqual(standardProjected, standardGolden) {
		t.Fatalf("standard first-offer noise-pack scan drifted\nprojected=%v\nexpected=%v", standardProjected, standardGolden)
	}
	if !reflect.DeepEqual(assessmentProjected, assessmentGolden) {
		t.Fatalf("assessment first-offer noise-pack scan drifted\nprojected=%v\nexpected=%v", assessmentProjected, assessmentGolden)
	}
}

func TestScenarioFirstOfferMixedGovernanceReportUsefulness(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "first-offer-mixed-governance", "repos")
	_ = runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--profile", "assessment", "--json"})
	reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--json"})

	expected := mustLoadFirstOfferExpected(t, repoRoot, "scenarios/wrkr/first-offer-mixed-governance/expected/assessment-report.json")
	projected := projectFirstOfferMixedGovernanceReport(t, reportPayload)
	if !reflect.DeepEqual(projected, expected) {
		t.Fatalf("first-offer mixed-governance report drifted\nprojected=%v\nexpected=%v", projected, expected)
	}
}

func TestScenarioFirstOfferDuplicatePathFixture(t *testing.T) {
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
	expected := mustLoadFirstOfferExpected(t, repoRoot, "scenarios/wrkr/first-offer-duplicate-paths/expected/action-paths.json")
	projected := projectFirstOfferDuplicateFixture(paths, choice)
	if !reflect.DeepEqual(projected, expected) {
		t.Fatalf("first-offer duplicate-path projection drifted\nprojected=%v\nexpected=%v", projected, expected)
	}
}

func mustLoadFirstOfferExpected(t *testing.T, repoRoot, rel string) map[string]any {
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

func projectFirstOfferNoisePackScan(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()

	return map[string]any{
		"status":            requireStringValue(t, payload, "status"),
		"findings_count":    float64(len(requireSliceValue(t, payload, "findings"))),
		"top_finding_types": projectTopFindingTypes(t, payload),
		"action_path_count": float64(len(optionalSliceValue(payload, "action_paths"))),
		"action_paths":      projectActionPaths(t, optionalSliceValue(payload, "action_paths")),
		"control_first":     projectOptionalControlFirst(t, payload["action_path_to_control_first"]),
		"activation": map[string]any{
			"eligible_count": float64(requireIntValue(t, requireMapValue(t, payload, "activation"), "eligible_count")),
			"message":        requireStringValue(t, requireMapValue(t, payload, "activation"), "message"),
			"item_classes":   projectActivationClasses(t, requireMapValue(t, payload, "activation")),
		},
	}
}

func projectFirstOfferMixedGovernanceReport(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()

	summary := requireMapValue(t, payload, "summary")
	assessmentSummary := requireMapValue(t, payload, "assessment_summary")
	return map[string]any{
		"status":         requireStringValue(t, payload, "status"),
		"top_risk_types": projectSummaryRiskTypes(t, summary),
		"action_paths":   projectActionPaths(t, requireSliceValue(t, payload, "action_paths")),
		"control_first":  projectRequiredControlFirst(t, requireMapValue(t, payload, "action_path_to_control_first")),
		"assessment_summary": map[string]any{
			"governable_path_count":               float64(requireIntValue(t, assessmentSummary, "governable_path_count")),
			"write_capable_path_count":            float64(requireIntValue(t, assessmentSummary, "write_capable_path_count")),
			"production_target_backed_path_count": float64(requireIntValue(t, assessmentSummary, "production_target_backed_path_count")),
			"ownerless_exposure":                  requireMapValue(t, assessmentSummary, "ownerless_exposure"),
			"identity_exposure_summary":           requireMapValue(t, assessmentSummary, "identity_exposure_summary"),
			"identity_to_review_first":            projectIdentityActionTarget(t, requireMapValue(t, assessmentSummary, "identity_to_review_first")),
			"identity_to_revoke_first":            projectIdentityActionTarget(t, requireMapValue(t, assessmentSummary, "identity_to_revoke_first")),
		},
		"exposure_groups": projectExposureGroups(t, requireSliceValue(t, payload, "exposure_groups")),
	}
}

func projectFirstOfferDuplicateFixture(paths []risk.ActionPath, choice *risk.ActionPathToControlFirst) map[string]any {
	out := map[string]any{
		"action_path_count": float64(len(paths)),
		"action_paths":      projectRiskActionPaths(paths),
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
		"path": projectRiskActionPath(choice.Path),
	}
	return out
}

func projectTopFindingTypes(t *testing.T, payload map[string]any) []any {
	t.Helper()

	topFindings := requireSliceValue(t, payload, "top_findings")
	out := make([]any, 0, len(topFindings))
	for _, item := range topFindings {
		record := requireMapItem(t, item, "top_finding")
		finding := requireMapValue(t, record, "finding")
		out = append(out, requireStringValue(t, finding, "finding_type"))
	}
	return out
}

func projectSummaryRiskTypes(t *testing.T, summary map[string]any) []any {
	t.Helper()

	topRisks := requireSliceValue(t, summary, "top_risks")
	out := make([]any, 0, len(topRisks))
	for _, item := range topRisks {
		record := requireMapItem(t, item, "top_risk")
		out = append(out, requireStringValue(t, record, "finding_type"))
	}
	return out
}

func projectActivationClasses(t *testing.T, activation map[string]any) []any {
	t.Helper()

	items := requireSliceValue(t, activation, "items")
	out := make([]any, 0, len(items))
	for _, item := range items {
		record := requireMapItem(t, item, "activation_item")
		out = append(out, requireStringValue(t, record, "item_class"))
	}
	return out
}

func projectActionPaths(t *testing.T, items []any) []any {
	t.Helper()

	out := make([]any, 0, len(items))
	for _, item := range items {
		record := requireMapItem(t, item, "action_path")
		projected := map[string]any{
			"path_id":                requireStringValue(t, record, "path_id"),
			"repo":                   requireStringValue(t, record, "repo"),
			"tool_type":              requireStringValue(t, record, "tool_type"),
			"recommended_action":     requireStringValue(t, record, "recommended_action"),
			"business_state_surface": requireStringValue(t, record, "business_state_surface"),
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

func projectOptionalControlFirst(t *testing.T, raw any) any {
	t.Helper()
	if raw == nil {
		return nil
	}
	return projectRequiredControlFirst(t, requireMapItem(t, raw, "action_path_to_control_first"))
}

func projectRequiredControlFirst(t *testing.T, controlFirst map[string]any) map[string]any {
	t.Helper()

	path := requireMapValue(t, controlFirst, "path")
	summary := requireMapValue(t, controlFirst, "summary")
	projected := map[string]any{
		"summary": map[string]any{
			"total_paths":                    float64(requireIntValue(t, summary, "total_paths")),
			"write_capable_paths":            float64(requireIntValue(t, summary, "write_capable_paths")),
			"production_target_backed_paths": float64(requireIntValue(t, summary, "production_target_backed_paths")),
			"govern_first_paths":             float64(requireIntValue(t, summary, "govern_first_paths")),
		},
		"path": map[string]any{
			"path_id":            requireStringValue(t, path, "path_id"),
			"repo":               requireStringValue(t, path, "repo"),
			"tool_type":          requireStringValue(t, path, "tool_type"),
			"recommended_action": requireStringValue(t, path, "recommended_action"),
		},
	}
	if surface, ok := path["business_state_surface"].(string); ok && surface != "" {
		projectedPath := projected["path"].(map[string]any)
		projectedPath["business_state_surface"] = surface
	}
	return projected
}

func projectIdentityActionTarget(t *testing.T, target map[string]any) map[string]any {
	t.Helper()

	return map[string]any{
		"execution_identity":        requireStringValue(t, target, "execution_identity"),
		"path_count":                float64(requireIntValue(t, target, "path_count")),
		"write_capable_path_count":  float64(requireIntValue(t, target, "write_capable_path_count")),
		"shared_execution_identity": requireBoolValue(t, target, "shared_execution_identity"),
		"standing_privilege":        requireBoolValue(t, target, "standing_privilege"),
	}
}

func projectExposureGroups(t *testing.T, groups []any) []any {
	t.Helper()

	out := make([]any, 0, len(groups))
	for _, item := range groups {
		group := requireMapItem(t, item, "exposure_group")
		out = append(out, map[string]any{
			"group_id":               requireStringValue(t, group, "group_id"),
			"tool_types":             requireSliceValue(t, group, "tool_types"),
			"delivery_chain_status":  requireStringValue(t, group, "delivery_chain_status"),
			"business_state_surface": requireStringValue(t, group, "business_state_surface"),
			"recommended_action":     requireStringValue(t, group, "recommended_action"),
			"path_count":             float64(requireIntValue(t, group, "path_count")),
			"path_ids":               requireSliceValue(t, group, "path_ids"),
		})
	}
	return out
}

func projectRiskActionPaths(paths []risk.ActionPath) []any {
	out := make([]any, 0, len(paths))
	for _, path := range paths {
		out = append(out, projectRiskActionPath(path))
	}
	return out
}

func projectRiskActionPath(path risk.ActionPath) map[string]any {
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

func requireMapItem(t *testing.T, value any, label string) map[string]any {
	t.Helper()
	record, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected %s object, got %T", label, value)
	}
	return record
}

func requireMapValue(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()
	return requireMapItem(t, payload[key], key)
}

func requireSliceValue(t *testing.T, payload map[string]any, key string) []any {
	t.Helper()
	value, ok := payload[key].([]any)
	if !ok {
		t.Fatalf("expected %s array, got %T", key, payload[key])
	}
	return value
}

func optionalSliceValue(payload map[string]any, key string) []any {
	value, ok := payload[key].([]any)
	if !ok {
		return nil
	}
	return value
}

func requireStringValue(t *testing.T, payload map[string]any, key string) string {
	t.Helper()
	value, ok := payload[key].(string)
	if !ok {
		t.Fatalf("expected %s string, got %T", key, payload[key])
	}
	return value
}

func requireIntValue(t *testing.T, payload map[string]any, key string) int {
	t.Helper()
	switch value := payload[key].(type) {
	case float64:
		return int(value)
	case int:
		return value
	default:
		t.Fatalf("expected %s numeric value, got %T", key, payload[key])
		return 0
	}
}

func requireBoolValue(t *testing.T, payload map[string]any, key string) bool {
	t.Helper()
	value, ok := payload[key].(bool)
	if !ok {
		t.Fatalf("expected %s bool, got %T", key, payload[key])
	}
	return value
}
