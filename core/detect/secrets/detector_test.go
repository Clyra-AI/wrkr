package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestSecretsDetectorRejectsExternalSymlinkedEnv(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, ".env")
	if err := os.WriteFile(target, []byte("OPENAI_API_KEY=redacted\n"), 0o600); err != nil {
		t.Fatalf("write outside env: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(root, ".env")); err != nil {
		t.Skipf("symlinks unsupported in this environment: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Root: root, Repo: "repo", Org: "local"}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 || findings[0].FindingType != "parse_error" {
		t.Fatalf("expected one parse_error finding, got %+v", findings)
	}
	if findings[0].ParseError == nil || findings[0].ParseError.Kind != "unsafe_path" {
		t.Fatalf("expected unsafe_path parse error, got %+v", findings[0].ParseError)
	}
}

func TestSecretsDetectorCarriesStaticSecretCredentialProvenance(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("OPENAI_API_KEY=redacted\n"), 0o600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Root: root, Repo: "repo", Org: "local"}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one secret finding, got %+v", findings)
	}
	if got := evidenceValue(findings[0], "credential_provenance_type"); got != "static_secret" {
		t.Fatalf("expected static_secret provenance, got %q", got)
	}
}

func TestSecretsDetectorUsesStructuredWorkflowCredentialSemantics(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	workflowDir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("mkdir workflow directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "e2e-aws.yml"), []byte(`name: e2e
on: workflow_dispatch
permissions:
  id-token: write
jobs:
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_E2E_ROLE_ARN }}
      - run: ./notify
        env:
          SECURITY_EMAIL_TO: ${{ secrets.SECURITY_EMAIL_TO }}
          SLACK_SECURITY_WEBHOOK: ${{ secrets.SLACK_SECURITY_WEBHOOK }}
`), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Root: root, Repo: "repo", Org: "local"}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one secret finding, got %+v", findings)
	}
	for _, ref := range []string{"AWS_E2E_ROLE_ARN", "SECURITY_EMAIL_TO"} {
		if !containsEvidenceValue(findings[0], "workflow_noncredential_secret_refs", ref) {
			t.Fatalf("expected non-authority ref %q in %+v", ref, findings[0].Evidence)
		}
	}
	if !containsEvidenceValue(findings[0], "workflow_credential_kind", "SLACK_SECURITY_WEBHOOK|static_secret") {
		t.Fatalf("expected webhook credential kind in %+v", findings[0].Evidence)
	}
	if got := evidenceValue(findings[0], "credential_provenance_type"); got != "" {
		t.Fatalf("workflow ref finding must not emit conflicting direct provenance, got %q", got)
	}
	if got := evidenceValue(findings[0], "credential_subject"); got != "" {
		t.Fatalf("workflow ref finding must not emit comma-joined credential subject, got %q", got)
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

func containsEvidenceValue(finding model.Finding, key, value string) bool {
	for _, item := range finding.Evidence {
		if item.Key == key && item.Value == value {
			return true
		}
	}
	return false
}
