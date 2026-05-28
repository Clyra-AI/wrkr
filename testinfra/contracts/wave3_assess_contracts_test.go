package contracts

import (
	"path/filepath"
	"testing"
)

func TestWave3SchemasDeclareFocusViewsAndAssessmentManifest(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)

	reportSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"))
	reportProps := reportSchema["properties"].(map[string]any)
	for _, key := range []string{"workflow_highlights", "focus_view"} {
		if _, ok := reportProps[key].(map[string]any); !ok {
			t.Fatalf("report summary schema missing %s: %v", key, reportProps)
		}
	}

	assessSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "assess", "assessment-manifest.schema.json"))
	assessProps := assessSchema["properties"].(map[string]any)
	for _, key := range []string{"command_metadata", "stages", "artifacts"} {
		if _, ok := assessProps[key].(map[string]any); !ok {
			t.Fatalf("assessment manifest schema missing %s: %v", key, assessProps)
		}
	}
}
