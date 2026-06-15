//go:build scenario

package scenarios

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWave3ActionPathSemanticScenario(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeWave3ScenarioFile(t, root, "openapi/payments-openapi.yaml", `openapi: 3.0.0
paths:
  /v1/payments:
    post:
      summary: Create payment
      operationId: createPayment
`)

	statePath := filepath.Join(t.TempDir(), "state.json")
	scanPayload := runScenarioCommandJSON(t, []string{"scan", "--path", root, "--state", statePath, "--json"})
	actionPaths := requireArray(t, scanPayload, "action_paths")
	openAPIPath := findActionPathByLocation(t, actionPaths, "payments-openapi.yaml")
	if value, ok := openAPIPath["action_path_eligible"]; ok && value != false {
		t.Fatalf("expected unbound openapi path to stay in target-surface context, got %v", openAPIPath)
	}
	if openAPIPath["action_binding_state"] != "unbound_context" {
		t.Fatalf("expected unbound openapi binding_state=unbound_context, got %v", openAPIPath)
	}

	reportPayload := runScenarioCommandJSON(t, []string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--share-profile", "internal",
		"--json",
	})
	bom := requireObject(t, reportPayload, "agent_action_bom")
	summary := requireObject(t, bom, "summary")
	if objectInt(summary["target_surface_context_items"]) < 1 {
		t.Fatalf("expected target_surface_context_items in BOM summary, got %v", summary)
	}
	if value, ok := summary["primary_view"]; ok && value != nil {
		t.Fatalf("expected unbound target surface to avoid primary_view promotion, got %v", summary["primary_view"])
	}
}

func writeWave3ScenarioFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}
