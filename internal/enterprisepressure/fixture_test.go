package enterprisepressure

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestMaterializeCurrentPreservesCombinedExternalControlEvidence(t *testing.T) {
	root := t.TempDir()
	if err := MaterializeCount(root, VariantCurrent, 4); err != nil {
		t.Fatalf("materialize current fixture: %v", err)
	}

	assertEvidenceClasses(t, filepath.Join(root, RepoName(4), ".wrkr", "provenance", "external-control-evidence.json"),
		[]string{"deployment_approval", "branch_protection"})
}

func TestMaterializeBaselinePreservesCombinedExternalControlEvidence(t *testing.T) {
	root := t.TempDir()
	if err := MaterializeCount(root, VariantBaseline, 60); err != nil {
		t.Fatalf("materialize baseline fixture: %v", err)
	}

	assertEvidenceClasses(t, filepath.Join(root, RepoName(60), ".wrkr", "provenance", "external-control-evidence.json"),
		[]string{"deployment_approval", "branch_protection"})
}

func assertEvidenceClasses(t *testing.T, path string, want []string) {
	t.Helper()

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read evidence sidecar %s: %v", path, err)
	}

	var doc externalControlEvidenceDocument
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatalf("parse evidence sidecar %s: %v", path, err)
	}
	if len(doc.Records) != len(want) {
		t.Fatalf("expected %d evidence records, got %d (%v)", len(want), len(doc.Records), doc.Records)
	}
	for idx, wantClass := range want {
		if got := doc.Records[idx].EvidenceClass; got != wantClass {
			t.Fatalf("expected evidence class %q at index %d, got %q", wantClass, idx, got)
		}
	}
}
