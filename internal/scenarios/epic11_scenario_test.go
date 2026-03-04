//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestScenarioExtensionDetectorExecution(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "extension-detectors", "repos")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--json"})

	if errorsValue, present := payload["detector_errors"]; present {
		if list, ok := errorsValue.([]any); ok && len(list) > 0 {
			t.Fatalf("expected no detector errors for valid extension scenario, got %v", errorsValue)
		}
	}

	findings, ok := payload["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings from extension scenario, got %v", payload["findings"])
	}

	foundCustom := false
	for _, item := range findings {
		finding, castOK := item.(map[string]any)
		if !castOK {
			continue
		}
		if finding["finding_type"] != "custom_extension_finding" {
			continue
		}
		if finding["detector"] != "extension" {
			t.Fatalf("expected detector=extension for custom finding, got %v", finding["detector"])
		}
		foundCustom = true
		break
	}
	if !foundCustom {
		t.Fatalf("expected custom_extension_finding in scenario output, got %v", findings)
	}
}
