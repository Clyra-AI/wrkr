package contracts

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/ingest"
)

func TestExternalControlEvidenceSchemaEmbeddedContractMatchesCanonical(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	canonicalPath := filepath.Join(repoRoot, "schemas", "v1", "evidence", "external-control-evidence.schema.json")
	embeddedPath := filepath.Join(repoRoot, "core", "ingest", "schema", "external-control-evidence.schema.json")

	canonical, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatalf("read canonical schema: %v", err)
	}
	embedded, err := os.ReadFile(embeddedPath)
	if err != nil {
		t.Fatalf("read embedded schema: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(canonical), bytes.TrimSpace(embedded)) {
		t.Fatal("embedded external control evidence schema drifted from canonical schema contract")
	}
}

func TestExternalControlEvidenceFixturesValidateAgainstSchema(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	for _, rel := range []string{
		"testinfra/contracts/fixtures/external-control-evidence/provider-export.json",
		"testinfra/contracts/fixtures/external-control-evidence/customer-owner-map.json",
	} {
		payload, err := os.ReadFile(filepath.Join(repoRoot, rel))
		if err != nil {
			t.Fatalf("read fixture %s: %v", rel, err)
		}
		if err := ingest.ValidateExternalControlEvidenceJSON(payload); err != nil {
			t.Fatalf("fixture %s must validate: %v", rel, err)
		}
	}
}
