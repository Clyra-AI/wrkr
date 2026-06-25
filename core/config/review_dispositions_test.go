package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewDispositionDeclarationValidates(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	payload := []byte(`schema_version: v1
review_dispositions:
  - state: accepted_risk
    source: governance-ticket
    issuer: release-cab
    rationale: Reviewed release workflow and accepted temporary residual risk.
    observed_at: 2026-06-25T10:00:00Z
    scope: repo
    resolution_key: rk-release
`)
	if err := os.WriteFile(filepath.Join(root, "wrkr-control-declarations.yaml"), payload, 0o600); err != nil {
		t.Fatalf("write declarations: %v", err)
	}

	loaded, _, err := LoadControlDeclarations(root)
	if err != nil {
		t.Fatalf("load declarations: %v", err)
	}
	if len(loaded.ReviewDispositions) != 1 {
		t.Fatalf("expected one review disposition, got %+v", loaded)
	}
	if loaded.ReviewDispositions[0].State != "accepted_risk" {
		t.Fatalf("expected accepted_risk state, got %+v", loaded.ReviewDispositions[0])
	}
}

func TestInvalidReviewDispositionFailsClosed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	payload := []byte(`schema_version: v1
review_dispositions:
  - state: unsupported_state
    source: governance-ticket
    issuer: release-cab
    rationale: Unsupported declarations must fail closed.
    observed_at: 2026-06-25T10:00:00Z
    scope: repo
    resolution_key: rk-release
`)
	if err := os.WriteFile(filepath.Join(root, "wrkr-control-declarations.yaml"), payload, 0o600); err != nil {
		t.Fatalf("write declarations: %v", err)
	}

	if _, _, err := LoadControlDeclarations(root); err == nil {
		t.Fatal("expected invalid review disposition to fail closed")
	}
}

func TestReviewDispositionWithoutObservedAtFailsClosed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	payload := []byte(`schema_version: v1
review_dispositions:
  - state: accepted_risk
    source: governance-ticket
    issuer: release-cab
    rationale: Missing observed_at must fail closed.
    scope: repo
    resolution_key: rk-release
`)
	if err := os.WriteFile(filepath.Join(root, "wrkr-control-declarations.yaml"), payload, 0o600); err != nil {
		t.Fatalf("write declarations: %v", err)
	}

	if _, _, err := LoadControlDeclarations(root); err == nil {
		t.Fatal("expected missing observed_at to fail closed")
	}
}
