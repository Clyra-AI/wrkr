package contracts

import (
	"path/filepath"
	"testing"
)

func TestWave6SchemasDeclareExecutiveRollupsAndGovernedUsageMetrics(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)

	reportSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"))
	reportProps := reportSchema["properties"].(map[string]any)
	for _, key := range []string{"executive_rollup", "governed_usage_metrics"} {
		if _, ok := reportProps[key].(map[string]any); !ok {
			t.Fatalf("report summary schema missing %s: %v", key, reportProps)
		}
	}

	bomSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"))
	bomSummaryProps := schemaDefinitionProperties(t, bomSchema, "summary")
	for _, key := range []string{"executive_rollup", "governed_usage_metrics"} {
		if _, ok := bomSummaryProps[key].(map[string]any); !ok {
			t.Fatalf("agent action bom summary schema missing %s: %v", key, bomSummaryProps)
		}
	}

	evidenceSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "evidence", "evidence-bundle.schema.json"))
	evidenceProps := evidenceSchema["properties"].(map[string]any)
	for _, key := range []string{"executive_rollup", "governed_usage_metrics"} {
		if _, ok := evidenceProps[key].(map[string]any); !ok {
			t.Fatalf("evidence bundle schema missing %s: %v", key, evidenceProps)
		}
	}
}

func TestWave6ExecutiveRollupAndMetricFixturesValidate(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	reportSchemaPath := filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json")
	bomSchemaPath := filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json")
	executiveFixturePath := filepath.Join(repoRoot, "testinfra", "contracts", "fixtures", "wave6", "executive-rollup.json")
	metricsFixturePath := filepath.Join(repoRoot, "testinfra", "contracts", "fixtures", "wave6", "governed-usage-metrics.json")

	validateFixtureAgainstDefinition(t, reportSchemaPath, "executiveRollup", executiveFixturePath)
	validateFixtureAgainstDefinition(t, reportSchemaPath, "governedUsageMetrics", metricsFixturePath)
	validateFixtureAgainstDefinition(t, bomSchemaPath, "executiveRollup", executiveFixturePath)
	validateFixtureAgainstDefinition(t, bomSchemaPath, "governedUsageMetrics", metricsFixturePath)
}
