package contracts

import (
	"path/filepath"
	"testing"
)

func TestWave4DriftReviewSchemasDeclareCategoryContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)

	regressSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "regress", "regress-result.schema.json"))
	regressProps := regressSchema["properties"].(map[string]any)
	for _, field := range []string{"drift_category_count", "comparison_status", "comparison_issues", "drift_categories"} {
		if _, ok := regressProps[field].(map[string]any); !ok {
			t.Fatalf("regress result schema missing %s: %v", field, regressProps)
		}
	}

	reportSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"))
	reportRegress := schemaDefinition(t, reportSchema, "regress")
	reportRegressProps := reportRegress["properties"].(map[string]any)
	for _, field := range []string{"drift_category_count", "comparison_status", "comparison_issues", "drift_categories"} {
		if _, ok := reportRegressProps[field].(map[string]any); !ok {
			t.Fatalf("report regress schema missing %s: %v", field, reportRegressProps)
		}
	}
	reportDriftExample := schemaDefinition(t, reportSchema, "driftExample")
	reportDriftExampleProps := reportDriftExample["properties"].(map[string]any)
	for _, field := range []string{
		"composition_id",
		"baseline_composition_id",
		"current_composition_ref",
		"baseline_composition_ref",
		"current_outcome_key",
		"baseline_outcome_key",
		"current_recommended_control",
		"baseline_recommended_control",
	} {
		if _, ok := reportDriftExampleProps[field].(map[string]any); !ok {
			t.Fatalf("report drift example schema missing %s: %v", field, reportDriftExampleProps)
		}
	}

	bomSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"))
	bomSummary := schemaDefinition(t, bomSchema, "summary")
	if _, ok := bomSummary["properties"].(map[string]any)["drift_review"].(map[string]any); !ok {
		t.Fatalf("agent action bom summary schema missing drift_review: %v", bomSummary)
	}
	bomDriftExample := schemaDefinition(t, bomSchema, "driftExample")
	bomDriftExampleProps := bomDriftExample["properties"].(map[string]any)
	for _, field := range []string{
		"composition_id",
		"baseline_composition_id",
		"current_composition_ref",
		"baseline_composition_ref",
		"current_outcome_key",
		"baseline_outcome_key",
		"current_recommended_control",
		"baseline_recommended_control",
	} {
		if _, ok := bomDriftExampleProps[field].(map[string]any); !ok {
			t.Fatalf("agent action bom drift example schema missing %s: %v", field, bomDriftExampleProps)
		}
	}
}

func TestWave4DriftReviewBaselineAndAssessSchemasDeclareMetadata(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)

	baselineSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "regress", "regress-baseline.schema.json"))
	baselineProps := baselineSchema["properties"].(map[string]any)
	for _, field := range []string{"action_paths_captured", "action_paths", "compositions_captured", "compositions"} {
		if _, ok := baselineProps[field].(map[string]any); !ok {
			t.Fatalf("regress baseline schema missing %s: %v", field, baselineProps)
		}
	}

	assessSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "assess", "assessment-manifest.schema.json"))
	stageStatus := schemaDefinition(t, assessSchema, "stageStatus")
	stageProps := stageStatus["properties"].(map[string]any)
	for _, field := range []string{"comparison_status", "drift_category_count"} {
		if _, ok := stageProps[field].(map[string]any); !ok {
			t.Fatalf("assessment stage schema missing %s: %v", field, stageProps)
		}
	}
}
