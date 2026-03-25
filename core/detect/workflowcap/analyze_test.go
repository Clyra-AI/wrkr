package workflowcap

import (
	"strings"
	"testing"
)

func TestAnalyzeDerivesStructuredWorkflowCapabilities(t *testing.T) {
	t.Parallel()

	payload := []byte(`name: release
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
      - run: terraform apply -auto-approve
      - run: kubectl apply -f k8s/
      - run: alembic upgrade head
      - run: wrkr evidence --state .wrkr/last-scan.json
`)

	result, parseErr := Analyze(".github/workflows/release.yml", payload)
	if parseErr != nil {
		t.Fatalf("analyze workflow: %v", parseErr)
	}
	for _, capability := range []string{"repo.write", "pull_request.write", "merge.execute", "deploy.write", "db.write", "iac.write"} {
		if !contains(result.Capabilities, capability) {
			t.Fatalf("expected capability %q in %v", capability, result.Capabilities)
		}
	}
	if result.Tool != "codex" {
		t.Fatalf("expected tool codex, got %q", result.Tool)
	}
	if !result.Headless {
		t.Fatal("expected headless detection")
	}
	if !result.DangerousFlags {
		t.Fatal("expected dangerous flag detection")
	}
	if result.ProofRequirement != "evidence" {
		t.Fatalf("expected proof requirement evidence, got %q", result.ProofRequirement)
	}
	if evidenceValue(result, "workflow_capability.merge.execute") != "step.run:gh_pr_merge" {
		t.Fatalf("expected merge execute evidence, got %q", evidenceValue(result, "workflow_capability.merge.execute"))
	}
	if !strings.Contains(evidenceValue(result, "workflow_capability.deploy.write"), "kubectl_apply") {
		t.Fatalf("expected deploy evidence to mention kubectl apply, got %q", evidenceValue(result, "workflow_capability.deploy.write"))
	}
}

func TestAnalyzeRequiresStructuredEvidenceBeforeClaimingMergeCapability(t *testing.T) {
	t.Parallel()

	payload := []byte(`name: read-only
on: workflow_dispatch
permissions: read-all
jobs:
  dry-run:
    runs-on: ubuntu-latest
    steps:
      - run: gh pr merge --auto "$PR_URL"
`)

	result, parseErr := Analyze(".github/workflows/dry-run.yml", payload)
	if parseErr != nil {
		t.Fatalf("analyze workflow: %v", parseErr)
	}
	if contains(result.Capabilities, "merge.execute") {
		t.Fatalf("did not expect merge.execute from read-only permissions: %v", result.Capabilities)
	}
}

func TestAnalyzeMalformedWorkflowReturnsParseError(t *testing.T) {
	t.Parallel()

	_, parseErr := Analyze(".github/workflows/bad.yml", []byte("jobs:\n  build:\n    steps: ["))
	if parseErr == nil {
		t.Fatal("expected parse error")
	}
	if parseErr.Kind != "parse_error" {
		t.Fatalf("expected parse_error kind, got %+v", parseErr)
	}
}

func evidenceValue(result Result, key string) string {
	for _, evidence := range result.Evidence {
		if evidence.Key == key {
			return evidence.Value
		}
	}
	return ""
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
