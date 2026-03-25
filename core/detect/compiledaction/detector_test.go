package compiledaction

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestDetectCompiledActionDerivesWorkflowCapabilities(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workflowDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "release.yml"), []byte(`name: release
on:
  pull_request:
    branches: [main]
permissions:
  contents: write
  pull-requests: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto "$PR_URL"
      - run: terraform apply -auto-approve
      - run: kubectl apply -f k8s/
`), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "payments", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect compiled action: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %+v", findings)
	}
	for _, permission := range []string{"repo.write", "pull_request.write", "merge.execute", "deploy.write", "iac.write"} {
		if !containsPermission(findings[0].Permissions, permission) {
			t.Fatalf("expected permission %q in %+v", permission, findings[0].Permissions)
		}
	}
	if evidenceValue(findings[0], "workflow_capability.iac.write") == "" {
		t.Fatalf("expected iac capability evidence, got %+v", findings[0].Evidence)
	}
}

func TestDetectCompiledActionWorkflowParseErrorIsExplicit(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workflowDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "bad.yml"), []byte("jobs:\n  release:\n    steps: ["), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "payments", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect compiled action: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one parse_error finding, got %+v", findings)
	}
	if findings[0].FindingType != "parse_error" {
		t.Fatalf("expected parse_error finding, got %+v", findings[0])
	}
}

func containsPermission(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func evidenceValue(finding model.Finding, key string) string {
	for _, evidence := range finding.Evidence {
		if evidence.Key == key {
			return evidence.Value
		}
	}
	return ""
}
