//go:build scenario

package scenarios

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	reportcore "github.com/Clyra-AI/wrkr/core/report"
)

func TestScenarioReportOverclaim(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)

	t.Run("external-control-and-static-runtime-language", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "control-evidence-state.json")
		mdPath := filepath.Join(t.TempDir(), "control-evidence.md")
		scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "control-evidence-state", "repos")

		scanPayload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
		reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "agent-action-bom", "--share-profile", "internal", "--md", "--md-path", mdPath, "--json"})

		markdown := mustReadScenarioFile(t, mdPath)
		if !strings.Contains(markdown, "approval evidence declared") {
			t.Fatalf("expected declared approval evidence wording, got %q", markdown)
		}
		assertScenarioArtifactsPassBuyerQA(t, scanPayload, reportPayload, map[string]string{
			"control_evidence_markdown": markdown,
		})
	})

	t.Run("non-agent-path-language", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "target-classification-state.json")
		mdPath := filepath.Join(t.TempDir(), "target-classification.md")
		scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "target-classification", "repos")

		scanPayload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
		reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "agent-action-bom", "--share-profile", "internal", "--md", "--md-path", mdPath, "--json"})

		markdown := mustReadScenarioFile(t, mdPath)
		if strings.Contains(markdown, "agent framework repo=") {
			t.Fatalf("did not expect plain-source scenario markdown to use agent-framework wording, got %q", markdown)
		}
		assertScenarioArtifactsPassBuyerQA(t, scanPayload, reportPayload, map[string]string{
			"target_classification_markdown": markdown,
		})
	})

	t.Run("static-runtime-absence-language", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "agent-action-bom-before.json")
		mdPath := filepath.Join(t.TempDir(), "agent-action-bom-before.md")
		scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "agent-action-bom-demo", "before", "repos")

		scanPayload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
		reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "agent-action-bom", "--share-profile", "internal", "--md", "--md-path", mdPath, "--json"})

		markdown := mustReadScenarioFile(t, mdPath)
		if !strings.Contains(markdown, "runtime evidence not collected") {
			t.Fatalf("expected static-only runtime wording, got %q", markdown)
		}
		assertScenarioArtifactsPassBuyerQA(t, scanPayload, reportPayload, map[string]string{
			"static_runtime_markdown": markdown,
		})
	})
}

func assertScenarioArtifactsPassBuyerQA(t *testing.T, scanPayload, reportPayload map[string]any, extraTexts map[string]string) {
	t.Helper()

	reportJSON, err := json.Marshal(reportPayload)
	if err != nil {
		t.Fatalf("marshal report payload: %v", err)
	}

	texts := map[string]string{
		"report_json": string(reportJSON),
	}
	for key, value := range extraTexts {
		texts[key] = value
	}

	if err := reportcore.ValidateBuyerArtifactTexts(reportcore.BuyerArtifactQAInput{
		ActionPathTypes: scenarioActionPathTypes(t, scanPayload),
		Texts:           texts,
	}); err != nil {
		t.Fatalf("expected generated artifacts to pass buyer QA: %v", err)
	}
}

func scenarioActionPathTypes(t *testing.T, scanPayload map[string]any) []string {
	t.Helper()

	actionPaths := requireArray(t, scanPayload, "action_paths")
	types := make([]string, 0, len(actionPaths))
	for _, item := range actionPaths {
		path := requireObjectItem(t, item)
		if actionPathType, ok := path["action_path_type"].(string); ok && strings.TrimSpace(actionPathType) != "" {
			types = append(types, actionPathType)
		}
	}
	return types
}

func mustReadScenarioFile(t *testing.T, path string) string {
	t.Helper()

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(payload)
}
