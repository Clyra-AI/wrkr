package contracts

import (
	"path/filepath"
	"testing"
)

func TestWave27SchemasDeclareDeploymentMode(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)

	reportSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"))
	reportProps := reportSchema["properties"].(map[string]any)
	if _, ok := reportProps["deployment_mode"].(map[string]any); !ok {
		t.Fatalf("report summary schema missing deployment_mode: %v", reportProps)
	}

	evidenceSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "evidence", "evidence-bundle.schema.json"))
	evidenceProps := evidenceSchema["properties"].(map[string]any)
	if _, ok := evidenceProps["deployment_mode"].(map[string]any); !ok {
		t.Fatalf("evidence bundle schema missing deployment_mode: %v", evidenceProps)
	}
}
