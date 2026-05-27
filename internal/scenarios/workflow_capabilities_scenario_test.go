//go:build scenario

package scenarios

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkflowCapabilitiesScenario(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "workflow-capabilities", "repos")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})

	findings, ok := payload["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}

	platformFindings := map[string]map[string]any{}
	for _, item := range findings {
		typed, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if typed["finding_type"] == "ci_autonomy" {
			if platform := scenarioEvidenceValue(typed, "ci_platform"); platform != "" {
				platformFindings[platform] = typed
			}
		}
	}
	for _, platform := range []string{"github_actions", "gitlab_ci", "azure_devops"} {
		if platformFindings[platform] == nil {
			t.Fatalf("expected ci_autonomy finding for %s, got %v", platform, findings)
		}
	}
	permissions := toStringSlice(platformFindings["github_actions"]["permissions"])
	for _, required := range []string{"repo.write", "pull_request.write", "merge.execute", "deploy.write", "db.write", "iac.write"} {
		if !containsString(permissions, required) {
			t.Fatalf("expected permission %q in %v", required, permissions)
		}
	}
	for _, platform := range []string{"gitlab_ci", "azure_devops"} {
		if !containsString(toStringSlice(platformFindings[platform]["permissions"]), "deploy.write") {
			t.Fatalf("expected deploy.write permission for %s, got %v", platform, platformFindings[platform]["permissions"])
		}
	}

	actionPaths, ok := payload["action_paths"].([]any)
	if !ok || len(actionPaths) == 0 {
		t.Fatalf("expected action_paths payload, got %v", payload["action_paths"])
	}
	pathsByLocation := map[string]map[string]any{}
	for _, item := range actionPaths {
		path, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if location, _ := path["location"].(string); location != "" {
			pathsByLocation[location] = path
		}
	}
	if path := pathsByLocation[".github/workflows/release.yml"]; path == nil || path["business_state_surface"] != "db" {
		t.Fatalf("expected github workflow db surface, got %v", path)
	}
	for _, location := range []string{".gitlab-ci.yml", "azure-pipelines.yml"} {
		path := pathsByLocation[location]
		if path == nil {
			t.Fatalf("expected action path for %s, got %v", location, pathsByLocation)
		}
		if surface, _ := path["business_state_surface"].(string); strings.TrimSpace(surface) == "" {
			t.Fatalf("expected non-empty business_state_surface for %s, got %v", location, path)
		}
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func scenarioEvidenceValue(finding map[string]any, key string) string {
	evidence, _ := finding["evidence"].([]any)
	for _, item := range evidence {
		record, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if recordKey, _ := record["key"].(string); recordKey == key {
			if value, _ := record["value"].(string); value != "" {
				return value
			}
		}
	}
	return ""
}
