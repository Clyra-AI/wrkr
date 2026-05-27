//go:build scenario

package scenarios

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWave4HighStakesAuthorityScenario(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeScenarioFile(t, root, ".github/workflows/release.yml", `name: release
on: workflow_dispatch
jobs:
  deploy:
    environment: production
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/release
      - run: terraform apply -auto-approve
      - run: kubectl apply -f k8s/
        env:
          SLACK_BOT_TOKEN: ${{ secrets.SLACK_BOT_TOKEN }}
`)
	writeScenarioFile(t, root, "openapi/payments-openapi.yaml", `openapi: 3.0.0
paths:
  /v1/payments:
    post:
      summary: Create payment
      operationId: createPayment
`)

	statePath := filepath.Join(t.TempDir(), "state.json")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", root, "--state", statePath, "--json"})
	actionPaths := requireArray(t, payload, "action_paths")

	workflowPath := findActionPathByLocation(t, actionPaths, ".github/workflows/release.yml")
	if len(requireArrayFromObject(t, workflowPath, "high_stakes_presets")) == 0 {
		t.Fatalf("expected high_stakes_presets on workflow path, got %v", workflowPath)
	}
	if len(requireArrayFromObject(t, workflowPath, "authority_bindings")) == 0 {
		t.Fatalf("expected authority_bindings on workflow path, got %v", workflowPath)
	}

	openAPIPath := findActionPathByLocation(t, actionPaths, "openapi/payments-openapi.yaml")
	context := requireObject(t, openAPIPath, "production_context")
	if context["status"] != "correlated" {
		t.Fatalf("expected correlated production context for repo-correlated openapi surface, got %v", context)
	}
}

func writeScenarioFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}
