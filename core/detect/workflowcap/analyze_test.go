package workflowcap

import (
	"os"
	"path/filepath"
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

func TestAnalyzeCapturesBuiltInWorkflowTokenAndSecretRefs(t *testing.T) {
	t.Parallel()

	payload := []byte(`name: release
on: workflow_dispatch
permissions:
  contents: write
  pull-requests: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: codex --full-auto --approval never
        env:
          GITHUB_TOKEN: ${{ github.token }}
          PROD_DEPLOY_PAT: ${{ secrets.PROD_DEPLOY_PAT }}
`)

	result, parseErr := Analyze(".github/workflows/release.yml", payload)
	if parseErr != nil {
		t.Fatalf("analyze workflow: %v", parseErr)
	}
	if evidenceValue(result, "workflow_builtin_token") != "github_token" {
		t.Fatalf("expected built-in workflow token evidence, got %q", evidenceValue(result, "workflow_builtin_token"))
	}
	if !strings.Contains(evidenceValue(result, "workflow_token_permission"), "contents=write") && evidenceValue(result, "workflow_token_permission") != "write-all" {
		t.Fatalf("expected workflow token permission evidence, got %q", evidenceValue(result, "workflow_token_permission"))
	}
	if evidenceValue(result, "workflow_secret_refs") != "PROD_DEPLOY_PAT" {
		t.Fatalf("expected secret ref evidence, got %q", evidenceValue(result, "workflow_secret_refs"))
	}
}

func TestAnalyzeEmitsAuthorityBindingsForStructuredCloudAndDeploySignals(t *testing.T) {
	t.Parallel()

	payload := []byte(`name: prod-release
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
`)

	result, parseErr := Analyze(".github/workflows/release.yml", payload)
	if parseErr != nil {
		t.Fatalf("analyze workflow: %v", parseErr)
	}
	if !strings.Contains(evidenceValue(result, "auth_surfaces"), "aws_oidc") {
		t.Fatalf("expected aws_oidc auth surface, got %v", evidenceValues(result, "auth_surfaces"))
	}
	bindings := evidenceValues(result, "authority_binding")
	if !containsPrefix(bindings, "workload_identity|aws|workflow_aws_oidc|aws|aws_role|cloud_or_infra_access|write|production|true|high") {
		t.Fatalf("expected aws authority binding, got %v", bindings)
	}
	if !containsPrefix(bindings, "deployment_path|terraform|workflow_terraform_apply|terraform|terraform_apply|infrastructure_apply|write|production|true|high") {
		t.Fatalf("expected terraform authority binding, got %v", bindings)
	}
	if !containsPrefix(bindings, "deployment_path|kubernetes|workflow_kubernetes_deploy|kubernetes|cluster_apply|deploy_write|write|production|true|high") {
		t.Fatalf("expected kubernetes authority binding, got %v", bindings)
	}
}

func TestAnalyzeDoesNotTreatTemplatedGithubTokenNameAsBuiltinWhenValueIsExternal(t *testing.T) {
	t.Parallel()

	payload := []byte(`name: release
on: workflow_dispatch
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: codex --full-auto --approval never
        env:
          GITHUB_TOKEN: ${{ vars.CI_TOKEN }}
          GH_TOKEN: ${{ secrets.PROD_DEPLOY_PAT }}
`)

	result, parseErr := Analyze(".github/workflows/release.yml", payload)
	if parseErr != nil {
		t.Fatalf("analyze workflow: %v", parseErr)
	}
	if evidenceValue(result, "workflow_builtin_token") != "" {
		t.Fatalf("did not expect built-in workflow token evidence, got %q", evidenceValue(result, "workflow_builtin_token"))
	}
	refs := evidenceValues(result, "workflow_secret_refs")
	if !contains(refs, "PROD_DEPLOY_PAT") {
		t.Fatalf("expected external secret ref evidence, got %v", refs)
	}
}

func TestAnalyzeMalformedWorkflowReturnsParseError(t *testing.T) {
	t.Parallel()

	_, parseErr := Analyze(".github/workflows/bad.yml", []byte("jobs:\n  build:\n    steps: ["))
	if parseErr == nil {
		t.Fatal("expected parse error")
		return
	}
	got := *parseErr
	if got.Kind != "parse_error" {
		t.Fatalf("expected parse_error kind, got %+v", got)
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

func TestAnalyzeCapturesWorkflowEnvironmentForTargetClassification(t *testing.T) {
	t.Parallel()

	payload := []byte(`name: release
on:
  workflow_dispatch:
jobs:
  release:
    runs-on: ubuntu-latest
    environment:
      name: production
    steps:
      - run: kubectl apply -f k8s/
`)

	result, parseErr := Analyze(".github/workflows/release.yml", payload)
	if parseErr != nil {
		t.Fatalf("analyze workflow: %v", parseErr)
	}
	if evidenceValue(result, "workflow_environment") != "production" {
		t.Fatalf("expected workflow environment evidence, got %q", evidenceValue(result, "workflow_environment"))
	}
	if evidenceValue(result, "target_class_hint") != "production_impacting" {
		t.Fatalf("expected target class hint, got %q", evidenceValue(result, "target_class_hint"))
	}
}

func TestAnalyzeDoesNotTreatNonProdEnvironmentAsProductionHint(t *testing.T) {
	t.Parallel()

	payload := []byte(`name: release
on:
  workflow_dispatch:
jobs:
  release:
    runs-on: ubuntu-latest
    environment:
      name: nonprod-validation
    steps:
      - run: kubectl apply -f k8s/
`)

	result, parseErr := Analyze(".github/workflows/release.yml", payload)
	if parseErr != nil {
		t.Fatalf("analyze workflow: %v", parseErr)
	}
	if evidenceValue(result, "target_class_hint") != "release_adjacent" {
		t.Fatalf("expected release-adjacent hint, got %q", evidenceValue(result, "target_class_hint"))
	}
}

func TestAnalyzeGitLabPipelineResolvesLocalIncludesAndManualGate(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".gitlab", "ci"), 0o755); err != nil {
		t.Fatalf("mkdir gitlab include path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".gitlab", "ci", "deploy.yml"), []byte(`deploy:
  stage: deploy
  when: manual
  environment:
    name: production
  script:
    - codex --full-auto --approval never
    - kubectl apply -f k8s/
    - wrkr evidence --state .wrkr/last-scan.json
  variables:
    PROD_DEPLOY_PAT: "$PROD_DEPLOY_PAT"
`), 0o600); err != nil {
		t.Fatalf("write gitlab include: %v", err)
	}

	result, parseErr := AnalyzeInRoot(root, ".gitlab-ci.yml", []byte(`stages:
  - build
  - deploy
include:
  - local: .gitlab/ci/deploy.yml
build:
  stage: build
  script:
    - go test ./...
`))
	if parseErr != nil {
		t.Fatalf("analyze gitlab workflow: %v", parseErr)
	}
	for _, capability := range []string{"deploy.write"} {
		if !contains(result.Capabilities, capability) {
			t.Fatalf("expected capability %q in %v", capability, result.Capabilities)
		}
	}
	if result.Tool != "codex" {
		t.Fatalf("expected tool codex, got %q", result.Tool)
	}
	if !result.Headless {
		t.Fatal("expected headless detection from gitlab script")
	}
	if result.ApprovalSource != "manual_job" {
		t.Fatalf("expected manual_job approval source, got %q", result.ApprovalSource)
	}
	if result.DeploymentGate != "approved" {
		t.Fatalf("expected approved deployment gate, got %q", result.DeploymentGate)
	}
	if evidenceValue(result, "ci_platform") != "gitlab_ci" {
		t.Fatalf("expected ci_platform=gitlab_ci, got %q", evidenceValue(result, "ci_platform"))
	}
	if evidenceValue(result, "include_resolution_status") != "resolved" {
		t.Fatalf("expected include resolution evidence, got %q", evidenceValue(result, "include_resolution_status"))
	}
	if evidenceValue(result, "workflow_environment") != "production" {
		t.Fatalf("expected production environment evidence, got %q", evidenceValue(result, "workflow_environment"))
	}
	if evidenceValue(result, "workflow_secret_refs") != "PROD_DEPLOY_PAT" {
		t.Fatalf("expected secret ref evidence, got %q", evidenceValue(result, "workflow_secret_refs"))
	}
}

func TestAnalyzeAzurePipelineResolvesLocalTemplateAndKeepsApprovalClaimScoped(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".azure", "pipelines"), 0o755); err != nil {
		t.Fatalf("mkdir azure template path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".azure", "pipelines", "deploy.yml"), []byte(`jobs:
- deployment: deploy_prod
  environment: production
  strategy:
    runOnce:
      deploy:
        steps:
        - script: codex --full-auto --approval never
        - script: az webapp deploy --resource-group prod-rg --name api
        - script: wrkr verify --chain --json
          env:
            PROD_DEPLOY_TOKEN: $(PROD_DEPLOY_TOKEN)
        - task: AzureCLI@2
          inputs:
            azureSubscription: prod-service-conn
            scriptType: bash
            scriptLocation: inlineScript
            inlineScript: |
              az aks get-credentials --name prod-aks --resource-group prod-rg
`), 0o600); err != nil {
		t.Fatalf("write azure template: %v", err)
	}

	result, parseErr := AnalyzeInRoot(root, "azure-pipelines.yml", []byte(`trigger:
- main
extends:
  template: .azure/pipelines/deploy.yml
variables:
- group: ProdSecrets
`))
	if parseErr != nil {
		t.Fatalf("analyze azure pipeline: %v", parseErr)
	}
	for _, capability := range []string{"deploy.write"} {
		if !contains(result.Capabilities, capability) {
			t.Fatalf("expected capability %q in %v", capability, result.Capabilities)
		}
	}
	if result.Tool != "codex" {
		t.Fatalf("expected tool codex, got %q", result.Tool)
	}
	if result.DeploymentGate != "ambiguous" {
		t.Fatalf("expected ambiguous deployment gate, got %q", result.DeploymentGate)
	}
	if evidenceValue(result, "ci_platform") != "azure_devops" {
		t.Fatalf("expected ci_platform=azure_devops, got %q", evidenceValue(result, "ci_platform"))
	}
	if evidenceValue(result, "template_resolution_status") != "resolved" {
		t.Fatalf("expected template resolution evidence, got %q", evidenceValue(result, "template_resolution_status"))
	}
	if evidenceValue(result, "workflow_environment") != "production" {
		t.Fatalf("expected production environment evidence, got %q", evidenceValue(result, "workflow_environment"))
	}
	if !strings.Contains(evidenceValue(result, "auth_surfaces"), "prod-service-conn") {
		t.Fatalf("expected service connection auth surface, got %q", evidenceValue(result, "auth_surfaces"))
	}
	if evidenceValue(result, "workflow_secret_refs") != "PROD_DEPLOY_TOKEN" {
		t.Fatalf("expected secret ref evidence, got %q", evidenceValue(result, "workflow_secret_refs"))
	}
}

func TestAnalyzeAzurePipelineDoesNotTreatOrdinaryRuntimeVariablesAsSecrets(t *testing.T) {
	t.Parallel()

	result, parseErr := AnalyzeInRoot("", "azure-pipelines.yml", []byte(`trigger:
- main
jobs:
- job: info
  steps:
  - script: |
      codex --full-auto --approval never
      echo $(Build.BuildNumber)
      echo $(System.DefaultWorkingDirectory)
`))
	if parseErr != nil {
		t.Fatalf("analyze azure pipeline: %v", parseErr)
	}
	if result.HasSecretAccess {
		t.Fatalf("did not expect ordinary Azure runtime variables to imply secret access: %+v", result)
	}
	if evidenceValue(result, "workflow_secret_refs") != "" {
		t.Fatalf("did not expect secret ref evidence, got %q", evidenceValue(result, "workflow_secret_refs"))
	}
}

func TestAnalyzeGitLabSkipsHiddenTemplateJobsUntilExtended(t *testing.T) {
	t.Parallel()

	result, parseErr := AnalyzeInRoot("", ".gitlab-ci.yml", []byte(`.deploy_template:
  stage: deploy
  script:
    - kubectl apply -f k8s/

lint:
  stage: test
  script:
    - go test ./...
`))
	if parseErr != nil {
		t.Fatalf("analyze gitlab workflow: %v", parseErr)
	}
	if contains(result.Capabilities, "deploy.write") {
		t.Fatalf("did not expect hidden template job to create deploy authority: %v", result.Capabilities)
	}
}

func TestAnalyzeGitLabExtendsHiddenTemplatesAndDefaultScripts(t *testing.T) {
	t.Parallel()

	result, parseErr := AnalyzeInRoot("", ".gitlab-ci.yml", []byte(`default:
  before_script:
    - codex --full-auto --approval never

.deploy_template:
  stage: deploy
  script:
    - kubectl apply -f k8s/

deploy:
  extends: .deploy_template
  environment:
    name: production
`))
	if parseErr != nil {
		t.Fatalf("analyze gitlab workflow: %v", parseErr)
	}
	if !result.Headless {
		t.Fatalf("expected inherited default.before_script to mark headless execution: %+v", result)
	}
	if !contains(result.Capabilities, "deploy.write") {
		t.Fatalf("expected inherited hidden template to project deploy.write, got %v", result.Capabilities)
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

func evidenceValues(result Result, key string) []string {
	out := []string{}
	for _, evidence := range result.Evidence {
		if evidence.Key == key {
			out = append(out, evidence.Value)
		}
	}
	return out
}

func containsPrefix(values []string, prefix string) bool {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
