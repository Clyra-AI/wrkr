package nonhumanidentity

import (
	"context"
	"os"
	"path/filepath"
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

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect non-human identities: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected three identity findings, got %+v", findings)
	}
	foundWorkload := false
	foundInherited := false
	for _, finding := range findings {
		switch evidenceValue(finding, "credential_provenance_type") {
		case "workload_identity":
			foundWorkload = true
		case "inherited_human":
			foundInherited = true
		}
	}
	if !foundWorkload || !foundInherited {
		t.Fatalf("expected workload and inherited credential provenance evidence, got %+v", findings)
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
