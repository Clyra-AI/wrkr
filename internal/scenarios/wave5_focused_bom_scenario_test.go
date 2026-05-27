//go:build scenario

package scenarios

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScenarioWave5FocusedWorkflowBOMUsesPrimaryViewAndExplicitFocus(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "agent-action-bom-demo", "after", "repos")
	statePath := filepath.Join(t.TempDir(), "wave5-state.json")

	runScenarioCommandJSON(t, []string{"scan", "--path", scanRoot, "--state", statePath, "--json"})
	reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "agent-action-bom", "--json"})

	bom := requireScenarioObject(t, reportPayload, "agent_action_bom")
	summary := requireScenarioObject(t, bom, "summary")
	primaryView := requireScenarioObject(t, summary, "primary_view")
	items := requireScenarioArrayFromObject(t, bom, "items")
	firstItem := requireScenarioMap(t, items[0])

	if primaryView["path_id"] != firstItem["path_id"] || primaryView["selection_reason"] != "default_top_path" {
		t.Fatalf("expected default primary view to follow first item, got primary=%v item=%v", primaryView, firstItem)
	}

	mdPath := filepath.Join(t.TempDir(), "focused-bom.md")
	focusedPayload := runScenarioCommandJSON(t, []string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--focus-path", firstItem["path_id"].(string),
		"--md",
		"--md-path", mdPath,
		"--json",
	})
	focusedPrimaryView := requireScenarioObject(t, requireScenarioObject(t, requireScenarioObject(t, focusedPayload, "agent_action_bom"), "summary"), "primary_view")
	if focusedPrimaryView["selection_reason"] != "explicit_focus_path" {
		t.Fatalf("expected explicit focus selection, got %v", focusedPrimaryView)
	}

	payload, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read markdown: %v", err)
	}
	markdown := string(payload)
	if !strings.Contains(markdown, "## Primary Workflow BOM") || !strings.Contains(markdown, "## Workflow BOM Appendix") {
		t.Fatalf("expected focused markdown sections, got %q", markdown)
	}
	if strings.Index(markdown, "## Primary Workflow BOM") > strings.Index(markdown, "## Workflow BOM Appendix") {
		t.Fatalf("expected primary workflow section before appendix, got %q", markdown)
	}
}
