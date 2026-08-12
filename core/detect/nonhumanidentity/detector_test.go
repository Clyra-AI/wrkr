package nonhumanidentity

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestDetectNonHumanIdentitiesFromWorkflowSignals(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workflowPath := filepath.Join(root, ".github", "workflows", "release.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o755); err != nil {
		t.Fatalf("mkdir workflow: %v", err)
	}
	payload := []byte(`
name: release
on: push
jobs:
  release:
    steps:
      - uses: actions/create-github-app-token@v1
        with:
          app-id: ${{ secrets.RELEASE_APP_ID }}
          private-key: ${{ secrets.RELEASE_APP_PRIVATE_KEY }}
      - run: echo "dependabot[bot]"
      - run: echo "release-bot@project.iam.gserviceaccount.com"
`)
	if err := os.WriteFile(workflowPath, payload, 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	detector := New()
	findings, err := detector.Detect(context.Background(), detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect non-human identities: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected three identity findings, got %+v", findings)
	}
	foundWorkflowReference := false
	for _, finding := range findings {
		if evidenceValue(finding, "surface_role") == "workflow_reference" {
			foundWorkflowReference = true
		}
		if evidenceValue(finding, "credential_provenance_type") != "" {
			t.Fatalf("workflow references must not become instantiated credential provenance: %+v", finding)
		}
	}
	if !foundWorkflowReference {
		t.Fatalf("expected workflow-reference role, got %+v", findings)
	}
}

func TestOpenAPISchemaCredentialFieldsDoNotCreateIdentity(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNonHumanFile(t, root, "api/openapi.json", `{"openapi":"3.1.0","components":{"schemas":{"Auth":{"properties":{"app_id":{"type":"string"},"private_key":{"type":"string"},"token":{"type":"string"}}}}}}`)
	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect non-human identities: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("schema declarations must not create identities or authority: %+v", findings)
	}
}

func TestJSONSchemaIdentityVocabularyDoesNotCreateIdentity(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNonHumanFile(t, root, "schema.json", `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object","properties":{"account_type":{"enum":["service_account"]},"client_email":{"type":"string"}}}`)
	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("schema identity vocabulary must not create an identity instance: %+v", findings)
	}
}

func TestGenericCloudIdentityTemplatesRemainConfigurationInstances(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNonHumanFile(t, root, "template.yaml", `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  DeployRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Principal:
              Federated: token.actions.githubusercontent.com
            Action: sts:AssumeRoleWithWebIdentity
`)
	writeNonHumanFile(t, root, "azure-template.json", `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "resources": [{"type": "Microsoft.ManagedIdentity/userAssignedIdentities", "name": "release-agent"}]
}`)
	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	locations := map[string]bool{}
	for _, finding := range findings {
		if evidenceValue(finding, "surface_role") == "config_instance" {
			locations[finding.Location] = true
		}
	}
	if !locations["template.yaml"] || !locations["azure-template.json"] {
		t.Fatalf("cloud identity deployment templates must remain configuration evidence: findings=%+v", findings)
	}
}

func TestDetectRejectsExternalSymlinkedWorkflowIdentitySource(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	writeNonHumanFile(t, outside, "release.yml", strings.Join([]string{
		"name: release",
		"jobs:",
		"  release:",
		"    steps:",
		"      - uses: actions/create-github-app-token@v1",
		"      - run: echo \"dependabot[bot]\"",
	}, "\n"))
	mustSymlinkOrSkipNonHuman(t, filepath.Join(outside, "release.yml"), filepath.Join(root, ".github", "workflows", "release.yml"))

	detector := New()
	findings, err := detector.Detect(context.Background(), detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect non-human identities: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one parse error finding, got %+v", findings)
	}
	if findings[0].FindingType != "parse_error" || findings[0].ParseError == nil || findings[0].ParseError.Kind != "unsafe_path" {
		t.Fatalf("expected unsafe_path parse error, got %+v", findings)
	}
	receipts := detector.SurfaceCoverage(detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if len(receipts) != 1 || receipts[0].Selected != 1 || receipts[0].Attempted != 1 || receipts[0].Partial != 1 {
		t.Fatalf("blocked candidate must preserve selected/attempted reconciliation: %+v", receipts)
	}
}

func TestDetectStructuredAuthorityBindingsFromTerraformAndRBACSignals(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNonHumanFile(t, root, "infra/main.tf", strings.Join([]string{
		`resource "aws_iam_role" "release" {`,
		`  name = "release-role"`,
		`  assume_role_policy = jsonencode({`,
		`    Statement = [{`,
		`      Principal = { Federated = "token.actions.githubusercontent.com" }`,
		`      Action = "sts:AssumeRoleWithWebIdentity"`,
		`    }]`,
		`  })`,
		`}`,
	}, "\n"))
	writeNonHumanFile(t, root, "k8s/rbac.yaml", strings.Join([]string{
		`kind: ClusterRole`,
		`metadata:`,
		`  name: cluster-admin`,
		`rules:`,
		`  - verbs: ["*"]`,
		`    resources: ["*"]`,
	}, "\n"))

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect non-human identities: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected structured authority findings")
	}
	joined := strings.Join(flattenEvidence(findings, "authority_binding"), "\n")
	if !strings.Contains(joined, "workload_identity|aws|github_actions_oidc") {
		t.Fatalf("expected aws oidc binding, got %s", joined)
	}
	if !strings.Contains(joined, "kubernetes_rbac|kubernetes|kubernetes_rbac") {
		t.Fatalf("expected kubernetes rbac binding, got %s", joined)
	}
}

func TestDetectWildcardKubernetesRBACAsAdminAuthority(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNonHumanFile(t, root, "k8s/rbac.yaml", strings.Join([]string{
		`kind: ClusterRole`,
		`metadata:`,
		`  name: release-manager`,
		`rules:`,
		`  - verbs: ["*"]`,
		`    resources: ["deployments"]`,
	}, "\n"))

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect non-human identities: %v", err)
	}
	joined := strings.Join(flattenEvidence(findings, "authority_binding"), "\n")
	if !strings.Contains(joined, "kubernetes_rbac|kubernetes|kubernetes_rbac|kubernetes|cluster_role|cluster_access|admin") {
		t.Fatalf("expected wildcard kubernetes RBAC to classify as admin, got %s", joined)
	}
}

func TestStructuredIdentityHelperTruthTable(t *testing.T) {
	items := []identityCandidate{{identityType: "service_account"}}
	if !hasIdentityType(items, "service_account") || hasIdentityType(items, "github_app") {
		t.Fatal("unexpected identity type membership")
	}
	for identityType, want := range map[string]string{
		"github_app":      "workload_identity",
		"service_account": "workload_identity",
		"bot_user":        "inherited_human",
		"other":           "unknown",
	} {
		if got := credentialProvenanceType(identityType); got != want {
			t.Fatalf("credentialProvenanceType(%q)=%q want %q", identityType, got, want)
		}
	}
	for _, tc := range []struct {
		identityType string
		confidence   string
		want         string
	}{
		{identityType: "github_app", confidence: "low", want: "high"},
		{identityType: "bot_user", confidence: "high", want: "medium"},
		{identityType: "bot_user", confidence: "low", want: "low"},
		{identityType: "other", confidence: "high", want: "medium"},
		{identityType: "other", confidence: "low", want: "low"},
	} {
		if got := credentialProvenanceConfidence(tc.identityType, tc.confidence); got != tc.want {
			t.Fatalf("credentialProvenanceConfidence(%q,%q)=%q want %q", tc.identityType, tc.confidence, got, tc.want)
		}
	}
	if toString("name") != "name" || toString(42) != "" {
		t.Fatal("unexpected structured key conversion")
	}
	if got := normalizedRootKeys(map[string]any{"Kind": "Role", "Nested": map[string]any{"Token": true}}); !got["kind"] || !got["nested"] {
		t.Fatalf("unexpected normalized root keys: %+v", got)
	}
}

func TestSurfaceCoverageIncludesStructuredAndParseOutcomes(t *testing.T) {
	root := t.TempDir()
	writeNonHumanFile(t, root, "infra/main.tf", `resource "aws_iam_role" "release" { name = "release-role" }`)
	writeNonHumanFile(t, root, ".github/workflows/bad.yml", "jobs:\n  release:\n    steps: [")
	detector := New()
	if _, err := detector.Detect(context.Background(), detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{}); err != nil {
		t.Fatalf("detect coverage surfaces: %v", err)
	}
	receipts := detector.SurfaceCoverage(detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if len(receipts) == 0 {
		t.Fatal("expected surface coverage receipts")
	}
	if receipts := detector.SurfaceCoverage(detect.Scope{Root: filepath.Join(root, "missing")}, detect.Options{}); receipts != nil {
		t.Fatalf("expected absent coverage receipt, got %+v", receipts)
	}
}

func TestMalformedHighSignalIdentityIsPartial(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNonHumanFile(t, root, "config/identity.json", `{"client_email":`)
	detector := New()
	findings, err := detector.Detect(context.Background(), detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].FindingType != "parse_error" || findings[0].ParseError == nil || findings[0].ParseError.Kind != "malformed" {
		t.Fatalf("malformed high-signal identity must emit a parse finding: %+v", findings)
	}
	receipts := detector.SurfaceCoverage(detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if len(receipts) != 1 || receipts[0].Discovered != 1 || receipts[0].Selected != 1 || receipts[0].Attempted != 1 || receipts[0].Parsed != 0 || receipts[0].Partial != 1 {
		t.Fatalf("malformed high-signal identity must reduce coverage: %+v", receipts)
	}
}

func TestMalformedOrdinaryStructuredFileIsSuppressed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeNonHumanFile(t, root, "package.json", `{"name":`)
	detector := New()
	findings, err := detector.Detect(context.Background(), detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("ordinary malformed structured files must not create identity findings: %+v", findings)
	}
	receipts := detector.SurfaceCoverage(detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if len(receipts) != 1 || receipts[0].Discovered != 1 || receipts[0].Suppressed != 1 || receipts[0].Partial != 0 {
		t.Fatalf("ordinary malformed structured files must be accounted as suppressed: %+v", receipts)
	}
}

func evidenceValue(finding model.Finding, key string) string {
	for _, item := range finding.Evidence {
		if item.Key == key {
			return item.Value
		}
	}
	return ""
}

func flattenEvidence(findings []model.Finding, key string) []string {
	values := []string{}
	for _, finding := range findings {
		for _, item := range finding.Evidence {
			if item.Key == key {
				values = append(values, item.Value)
			}
		}
	}
	return values
}

func writeNonHumanFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func mustSymlinkOrSkipNonHuman(t *testing.T, target, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir symlink parent: %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("symlinks unsupported in this environment: %v", err)
	}
}
