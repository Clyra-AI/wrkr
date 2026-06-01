package contracts

import (
	"path/filepath"
	"testing"
)

func TestWave28ReportSchemaDeclaresPublicSurfaceAssessment(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)

	reportSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"))
	reportProps := reportSchema["properties"].(map[string]any)
	if _, ok := reportProps["public_surface_assessment"].(map[string]any); !ok {
		t.Fatalf("report summary schema missing public_surface_assessment: %v", reportProps)
	}

	validateFixtureAgainstDefinition(
		t,
		filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"),
		"publicSurfaceAssessment",
		filepath.Join(repoRoot, "testinfra", "contracts", "fixtures", "wave28", "public-surface-assessment.json"),
	)
}
