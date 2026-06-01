package source

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadPublicSurfaceManifestSortsEvidenceDeterministically(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	manifestPath := filepath.Join(tmp, "public-surface.yaml")
	if err := os.WriteFile(manifestPath, []byte(`schema_version: v1
name: acme-public
sources:
  - id: b
    source_class: public_workflow
    public_ref: https://github.com/acme/platform/actions/workflows/release.yml
    evidence_label: public_inferred
    confidence: medium
    inference_rationale: Workflow name implies release automation, but no private deployment proof is attached.
    claims:
      - Release workflow likely exists
  - id: a
    source_class: public_repo
    public_ref: https://github.com/acme/platform
    evidence_label: public_observed
    confidence: high
    claims:
      - Public repo is visible
`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	loaded, err := LoadPublicSurfaceManifest(manifestPath)
	if err != nil {
		t.Fatalf("load public-surface manifest: %v", err)
	}
	if len(loaded.Sources) != 2 {
		t.Fatalf("expected two sources, got %+v", loaded.Sources)
	}
	if loaded.Sources[0].EvidenceLabel != PublicEvidenceLabelInferred {
		t.Fatalf("expected deterministic sort by label, got %+v", loaded.Sources)
	}
	if loaded.Sources[1].EvidenceLabel != PublicEvidenceLabelObserved {
		t.Fatalf("expected second public evidence row to be observed, got %+v", loaded.Sources)
	}
}

func TestLoadPublicSurfaceManifestRejectsUnsafeCapturePath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	manifestPath := filepath.Join(tmp, "public-surface.yaml")
	if err := os.WriteFile(manifestPath, []byte(`schema_version: v1
name: acme-public
sources:
  - id: a
    source_class: public_docs
    public_ref: https://docs.acme.example/security
    evidence_label: public_observed
    confidence: high
    capture_path: ../private-export.json
    claims:
      - Public docs are visible
`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	if _, err := LoadPublicSurfaceManifest(manifestPath); err == nil {
		t.Fatal("expected unsafe public-surface capture path to be rejected")
	} else if !IsPublicSurfaceSafetyError(err) {
		t.Fatalf("expected public-surface safety error, got %v", err)
	}
}
