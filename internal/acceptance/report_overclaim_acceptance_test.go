package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	reportcore "github.com/Clyra-AI/wrkr/core/report"
)

func TestReportOverclaimAcceptance(t *testing.T) {
	paths := loadAcceptancePaths(t)

	t.Run("control-evidence-internal", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "control-evidence-state.json")
		mdPath := filepath.Join(t.TempDir(), "control-evidence.md")
		scanRoot := filepath.Join(paths.repoRoot, "scenarios", "wrkr", "control-evidence-state", "repos")

		runJSONOK(t, "scan", "--path", scanRoot, "--state", statePath, "--json")
		reportPayload := runJSONOK(t, "report", "--state", statePath, "--template", "agent-action-bom", "--share-profile", "internal", "--md", "--md-path", mdPath, "--json")

		markdown, err := os.ReadFile(mdPath)
		if err != nil {
			t.Fatalf("read control-evidence markdown: %v", err)
		}
		if !strings.Contains(string(markdown), "approval evidence declared") {
			t.Fatalf("expected declared approval evidence wording, got %q", string(markdown))
		}
		assertAcceptanceArtifactsPassBuyerQA(t, reportPayload, map[string]string{
			"control_evidence_markdown": string(markdown),
		})
	})

	t.Run("static-runtime-internal", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "agent-action-bom-before.json")
		mdPath := filepath.Join(t.TempDir(), "agent-action-bom-before.md")
		scanRoot := filepath.Join(paths.repoRoot, "scenarios", "wrkr", "agent-action-bom-demo", "before", "repos")

		runJSONOK(t, "scan", "--path", scanRoot, "--state", statePath, "--json")
		reportPayload := runJSONOK(t, "report", "--state", statePath, "--template", "agent-action-bom", "--share-profile", "internal", "--md", "--md-path", mdPath, "--json")

		markdown, err := os.ReadFile(mdPath)
		if err != nil {
			t.Fatalf("read static-runtime markdown: %v", err)
		}
		if !strings.Contains(string(markdown), "runtime evidence not collected") {
			t.Fatalf("expected static-only runtime wording, got %q", string(markdown))
		}
		assertAcceptanceArtifactsPassBuyerQA(t, reportPayload, map[string]string{
			"static_runtime_markdown": string(markdown),
		})
	})

	t.Run("customer-redacted", func(t *testing.T) {
		statePath := filepath.Join(t.TempDir(), "customer-redacted-state.json")
		mdPath := filepath.Join(t.TempDir(), "customer-redacted.md")
		scanRoot := filepath.Join(paths.repoRoot, "scenarios", "wrkr", "buyer-action-registry-hardening", "repos")

		runJSONOK(t, "scan", "--path", scanRoot, "--state", statePath, "--json")
		reportPayload := runJSONOK(t, "report", "--state", statePath, "--template", "agent-action-bom", "--share-profile", "customer-redacted", "--md", "--md-path", mdPath, "--json")

		markdown, err := os.ReadFile(mdPath)
		if err != nil {
			t.Fatalf("read customer-redacted markdown: %v", err)
		}
		if !strings.Contains(string(markdown), "Share profile: customer-redacted") {
			t.Fatalf("expected customer-redacted share profile marker, got %q", string(markdown))
		}
		assertAcceptanceArtifactsPassBuyerQA(t, reportPayload, map[string]string{
			"customer_redacted_markdown": string(markdown),
		})
	})
}

func assertAcceptanceArtifactsPassBuyerQA(t *testing.T, reportPayload map[string]any, extraTexts map[string]string) {
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
		ActionPathTypes: acceptanceActionPathTypes(t, reportPayload),
		PathEvidence:    acceptancePathEvidence(t, reportPayload),
		Texts:           texts,
	}); err != nil {
		t.Fatalf("expected generated artifacts to pass buyer QA: %v", err)
	}
}

func acceptanceActionPathTypes(t *testing.T, reportPayload map[string]any) []string {
	t.Helper()

	actionPaths := requireArray(t, reportPayload, "action_paths")
	types := make([]string, 0, len(actionPaths))
	for _, item := range actionPaths {
		path := requireObjectItem(t, item)
		if actionPathType, ok := path["action_path_type"].(string); ok && strings.TrimSpace(actionPathType) != "" {
			types = append(types, actionPathType)
		}
	}
	return types
}

func acceptancePathEvidence(t *testing.T, reportPayload map[string]any) []reportcore.BuyerArtifactPathEvidence {
	t.Helper()

	actionPaths := requireArray(t, reportPayload, "action_paths")
	evidence := make([]reportcore.BuyerArtifactPathEvidence, 0, len(actionPaths))
	for _, item := range actionPaths {
		path := requireObjectItem(t, item)
		evidence = append(evidence, reportcore.BuyerArtifactPathEvidence{
			ActionPathType: acceptanceStringValue(path["action_path_type"]),
			Repo:           acceptanceStringValue(path["repo"]),
			Location:       acceptanceStringValue(path["location"]),
		})
	}
	return evidence
}

func acceptanceStringValue(value any) string {
	text, _ := value.(string)
	return text
}
