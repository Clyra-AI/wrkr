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

func TestAnalyzeClassifiesReleaseAndPackagePublishCapabilities(t *testing.T) {
	t.Parallel()

	payload := []byte(`name: publish
on: workflow_dispatch
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - run: goreleaser release --clean
      - run: npm publish
      - uses: docker/build-push-action@v6
`)

	result, parseErr := Analyze(".github/workflows/publish.yml", payload)
	if parseErr != nil {
		t.Fatalf("analyze workflow: %v", parseErr)
	}
	for _, capability := range []string{"release.write", "package.write"} {
		if !contains(result.Capabilities, capability) {
			t.Fatalf("expected capability %q in %v", capability, result.Capabilities)
		}
	}
	if evidenceValue(result, "workflow_capability.release.write") != "step.run:goreleaser_release" {
		t.Fatalf("expected release evidence, got %q", evidenceValue(result, "workflow_capability.release.write"))
	}
	if !strings.Contains(evidenceValue(result, "workflow_capability.package.write"), "npm_publish") {
		t.Fatalf("expected package publish evidence, got %q", evidenceValue(result, "workflow_capability.package.write"))
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

func TestAnalyzeTreatsMixedDeliveryGovernanceAsAmbiguous(t *testing.T) {
	t.Parallel()

	payload := []byte(`name: release
on:
  push:
    branches: [main]
jobs:
  approved:
    runs-on: ubuntu-latest
    steps:
      - uses: trstringer/manual-approval@v1
      - run: kubectl apply -f k8s/
      - run: wrkr evidence --state .wrkr/approved.json
  ungated:
    runs-on: ubuntu-latest
    steps:
      - run: kubectl apply -f k8s/
      - run: wrkr evidence --state .wrkr/ungated.json
`)

	result, parseErr := Analyze(".github/workflows/release.yml", payload)
	if parseErr != nil {
		t.Fatalf("analyze workflow: %v", parseErr)
	}
	if result.DeploymentGate != "ambiguous" {
		t.Fatalf("expected ambiguous deployment gate, got %q", result.DeploymentGate)
	}
	if result.ApprovalSource != "ambiguous" {
		t.Fatalf("expected ambiguous approval source, got %q", result.ApprovalSource)
	}
}

func TestAnalyzeMarksMissingProofWhenDeliveryPathLacksEvidence(t *testing.T) {
	t.Parallel()

	payload := []byte(`name: release
on:
  push:
    branches: [main]
jobs:
  covered:
    runs-on: ubuntu-latest
    steps:
      - run: kubectl apply -f k8s/
      - run: wrkr evidence --state .wrkr/covered.json
  uncovered:
    runs-on: ubuntu-latest
    steps:
      - run: kubectl apply -f k8s/
`)

	result, parseErr := Analyze(".github/workflows/release.yml", payload)
	if parseErr != nil {
		t.Fatalf("analyze workflow: %v", parseErr)
	}
	if result.ProofRequirement != "missing" {
		t.Fatalf("expected missing proof requirement, got %q", result.ProofRequirement)
	}
}

func TestAnalyzeIgnoresNonDeliveryJobsWhenAggregatingGovernance(t *testing.T) {
	t.Parallel()

	payload := []byte(`name: release
on:
  push:
    branches: [main]
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: trstringer/manual-approval@v1
      - run: kubectl apply -f k8s/
      - run: wrkr evidence --state .wrkr/release.json
  lint:
    runs-on: ubuntu-latest
    steps:
      - run: go test ./...
`)

	result, parseErr := Analyze(".github/workflows/release.yml", payload)
	if parseErr != nil {
		t.Fatalf("analyze workflow: %v", parseErr)
	}
	if result.DeploymentGate != "approved" {
		t.Fatalf("expected approved deployment gate, got %q", result.DeploymentGate)
	}
	if result.ApprovalSource != "manual_approval_step" {
		t.Fatalf("expected manual approval source, got %q", result.ApprovalSource)
	}
	if result.ProofRequirement != "evidence" {
		t.Fatalf("expected evidence proof requirement, got %q", result.ProofRequirement)
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
