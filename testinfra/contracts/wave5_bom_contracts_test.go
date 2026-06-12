package contracts

import (
	"path/filepath"
	"testing"
)

func TestWave5AgentActionBOMSchemaDeclaresPrimaryViewContract(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	schema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"))
	summaryProps := schemaDefinitionProperties(t, schema, "summary")
	primaryView := schemaRef(t, schema, summaryProps["primary_view"])
	for _, field := range []string{
		"path_id",
		"selection_reason",
		"path_map",
		"autonomy_tier",
		"delegation_readiness_state",
		"recommended_control",
		"risk_tier",
		"evidence_completeness_label",
		"recommended_next_actions",
		"coverage_status",
		"appendix_refs",
	} {
		if _, ok := primaryView["properties"].(map[string]any)[field]; !ok {
			t.Fatalf("primary view schema missing %s: %v", field, primaryView)
		}
	}

	pathMap := schemaRef(t, schema, primaryView["properties"].(map[string]any)["path_map"])
	for _, field := range []string{"tool", "repo_pr", "workflow", "credential", "action", "target"} {
		if _, ok := pathMap["properties"].(map[string]any)[field]; !ok {
			t.Fatalf("primary path map schema missing %s: %v", field, pathMap)
		}
	}
}

func TestWave5PrimaryViewSummaryFixtureValidates(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	validateFixtureAgainstDefinition(
		t,
		filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"),
		"summary",
		filepath.Join(repoRoot, "testinfra", "contracts", "fixtures", "wave5", "agent-action-bom-summary-primary-view.json"),
	)
}
