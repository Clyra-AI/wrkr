package contracts

import (
	"path/filepath"
	"testing"
)

func TestWave31SchemasDeclareRepeatUsageSignals(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)

	reportSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"))
	reportProps := reportSchema["properties"].(map[string]any)
	if _, ok := reportProps["repeat_usage_signals"].(map[string]any); !ok {
		t.Fatalf("report summary schema missing repeat_usage_signals: %v", reportProps)
	}

	bomSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"))
	bomSummaryProps := schemaDefinitionProperties(t, bomSchema, "summary")
	if _, ok := bomSummaryProps["repeat_usage_signals"].(map[string]any); !ok {
		t.Fatalf("agent action bom summary schema missing repeat_usage_signals: %v", bomSummaryProps)
	}
}

func TestWave31RepeatUsageSignalsFixtureValidates(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	reportSchemaPath := filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json")
	bomSchemaPath := filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json")
	fixturePath := filepath.Join(repoRoot, "testinfra", "contracts", "fixtures", "wave31", "repeat-usage-signals.json")

	validateFixtureAgainstDefinition(t, reportSchemaPath, "repeatUsageSignals", fixturePath)
	validateFixtureAgainstDefinition(t, bomSchemaPath, "repeatUsageSignals", fixturePath)
}
