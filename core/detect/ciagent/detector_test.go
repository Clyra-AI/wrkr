package ciagent

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestDetectCIAutonomyCriticalFinding(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scope := detect.Scope{Org: "local", Repo: "infra", Root: filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos", "infra")}
	findings, err := New().Detect(context.Background(), scope, detect.Options{})
	if err != nil {
		t.Fatalf("detect ciagent: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected ciagent findings")
	}
	if findings[0].Severity != "critical" {
		t.Fatalf("expected critical severity finding first, got %s", findings[0].Severity)
	}
	if findings[0].Autonomy != "headless_auto" {
		t.Fatalf("expected headless_auto autonomy, got %s", findings[0].Autonomy)
	}
}

func TestDetectCIAutonomyDerivesWorkflowCapabilities(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workflowPath := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowPath, 0o755); err != nil {
		t.Fatalf("mkdir workflow path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowPath, "release.yml"), []byte(`name: release
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
      - run: codex --full-auto --approval never
      - run: gh pr merge --auto "$PR_URL"
      - run: kubectl apply -f k8s/
      - run: alembic upgrade head
`), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "payments", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect ciagent: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one ciagent finding, got %+v", findings)
	}
	for _, permission := range []string{"repo.write", "pull_request.write", "merge.execute", "deploy.write", "db.write"} {
		if !hasPermission(findings[0].Permissions, permission) {
			t.Fatalf("expected permission %q in %+v", permission, findings[0].Permissions)
		}
	}
	if value := evidenceValue(findings[0], "workflow_capability.merge.execute"); value != "step.run:gh_pr_merge" {
		t.Fatalf("expected merge execute evidence, got %q", value)
	}
}

func TestDetectCIAutonomyDoesNotOverclaimMergeWhenWorkflowIsReadOnly(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workflowPath := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowPath, 0o755); err != nil {
		t.Fatalf("mkdir workflow path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowPath, "dry-run.yml"), []byte(`name: dry-run
on: workflow_dispatch
permissions: read-all
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: codex --full-auto --approval never
      - run: gh pr merge --auto "$PR_URL"
`), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "payments", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect ciagent: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one ciagent finding, got %+v", findings)
	}
	if hasPermission(findings[0].Permissions, "merge.execute") {
		t.Fatalf("did not expect merge.execute permission in %+v", findings[0].Permissions)
	}
}

func TestDetectCIAutonomyCarriesApprovalAndProofEvidence(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workflowPath := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowPath, 0o755); err != nil {
		t.Fatalf("mkdir workflow path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowPath, "release.yml"), []byte(`name: release
on:
  workflow_dispatch:
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: trstringer/manual-approval@v1
      - run: codex --full-auto --approval never
      - run: wrkr evidence --state .wrkr/last-scan.json
`), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "payments", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect ciagent: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one ciagent finding, got %+v", findings)
	}
	if value := evidenceValue(findings[0], "approval_source"); value != "manual_approval_step" {
		t.Fatalf("expected approval_source=manual_approval_step, got %q", value)
	}
	if value := evidenceValue(findings[0], "proof_requirement"); value != "evidence" {
		t.Fatalf("expected proof_requirement=evidence, got %q", value)
	}
}

func mustFindRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(wd, "go.mod")); statErr == nil {
			return wd
		}
		next := filepath.Dir(wd)
		if next == wd {
			t.Fatal("could not find repo root")
		}
		wd = next
	}
}

func hasPermission(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func evidenceValue(finding model.Finding, key string) string {
	for _, item := range finding.Evidence {
		if item.Key == key {
			return item.Value
		}
	}
	return ""
}
