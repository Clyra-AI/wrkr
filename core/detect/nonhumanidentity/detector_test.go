package nonhumanidentity

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
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
}
