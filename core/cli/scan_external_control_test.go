package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/source"
)

func TestValidateRepoExternalControlEvidenceFailsClosed(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join(t.TempDir(), "demo")
	if err := os.MkdirAll(filepath.Join(repoRoot, ".wrkr", "provenance"), 0o755); err != nil {
		t.Fatalf("mkdir provenance dir: %v", err)
	}
	payload := `{
  "schema_version": "v1",
  "generated_at": "2026-06-25T12:00:00Z",
  "records": [
    {
      "record_kind": "external_control",
      "source": "missing-source-type",
      "repo": "local/demo",
      "observed_at": "2026-06-25T11:00:00Z",
      "evidence_class": "branch_protection"
    }
  ]
}`
	if err := os.WriteFile(filepath.Join(repoRoot, ".wrkr", "provenance", "external-control-evidence.json"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write external control evidence: %v", err)
	}

	err := validateRepoExternalControlEvidence(source.Manifest{
		Repos: []source.RepoManifest{{
			Repo:     "local/demo",
			ScanRoot: repoRoot,
		}},
	})
	if err == nil {
		t.Fatal("expected invalid external control evidence to fail validation")
	}
	if !strings.Contains(err.Error(), "external-control-evidence.json") {
		t.Fatalf("expected path in validation error, got %v", err)
	}
}
