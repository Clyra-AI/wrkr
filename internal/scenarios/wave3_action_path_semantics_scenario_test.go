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

func TestSwaggerWithUnrelatedWorkflowCredentialStaysTargetContext(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeWave3ScenarioFile(t, root, ".github/workflows/release.yml", `name: release
on: workflow_dispatch
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: ./release.sh
        env:
          PROD_DEPLOY_PAT: ${{ secrets.PROD_DEPLOY_PAT }}
`)
	writeWave3ScenarioFile(t, root, "openapi/swagger.yaml", `openapi: 3.0.0
paths:
  /v1/payments:
    post:
      summary: Create payment
      operationId: createPayment
`)

	statePath := filepath.Join(t.TempDir(), "state.json")
	scanPayload := runScenarioCommandJSON(t, []string{"scan", "--path", root, "--state", statePath, "--json"})
	actionPaths := requireArray(t, scanPayload, "action_paths")
	swaggerPath := findActionPathByLocation(t, actionPaths, "openapi/swagger.yaml")
	if value, ok := swaggerPath["action_path_eligible"]; ok && value != false {
		t.Fatalf("expected swagger target context to stay ineligible when only an unrelated workflow secret exists, got %v", swaggerPath)
	}
	if swaggerPath["action_binding_state"] != "unbound_context" {
		t.Fatalf("expected swagger binding_state=unbound_context, got %v", swaggerPath)
	}
	if credentialAccess, ok := swaggerPath["credential_access"].(bool); ok && credentialAccess {
		t.Fatalf("expected swagger target context to drop unrelated credential_access, got %v", swaggerPath)
	}
	if _, ok := swaggerPath["credential_authority_ref"]; ok {
		t.Fatalf("expected swagger target context to omit credential_authority_ref, got %v", swaggerPath)
	}
	if _, ok := swaggerPath["credential_authority"]; ok {
		t.Fatalf("expected swagger target context to omit embedded credential_authority, got %v", swaggerPath)
	}
	if refs, ok := swaggerPath["authority_binding_refs"].([]any); ok && len(refs) > 0 {
		t.Fatalf("expected swagger target context to omit authority_binding_refs, got %v", swaggerPath)
	}
	if bindings, ok := swaggerPath["authority_bindings"].([]any); ok && len(bindings) > 0 {
		t.Fatalf("expected swagger target context to omit embedded authority_bindings, got %v", swaggerPath)
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
