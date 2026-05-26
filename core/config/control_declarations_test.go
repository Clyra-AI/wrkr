package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestControlDeclarationsLoadFromRoot(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	payload := []byte(`schema_version: v1
issuer: security-platform
owners:
  - repo: acme/payments
    path: .github/workflows/release.yml
    owner: "@acme/platform"
    evidence_refs:
      - evidence://customer/owners.yaml#payments
targets:
  - repo: acme/payments
    path: .github/workflows/release.yml
    target_class: test_demo_sandbox
    non_production: true
    evidence_refs:
      - evidence://customer/targets.yaml#payments
`)
	if err := os.WriteFile(filepath.Join(root, "wrkr-control-declarations.yaml"), payload, 0o600); err != nil {
		t.Fatalf("write declarations: %v", err)
	}

	loaded, paths, err := LoadControlDeclarations(root)
	if err != nil {
		t.Fatalf("load declarations: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("expected one declaration path, got %v", paths)
	}
	if len(loaded.Owners) != 1 || loaded.Owners[0].Owner != "@acme/platform" {
		t.Fatalf("expected owner declaration, got %+v", loaded)
	}
	if len(loaded.Targets) != 1 || !loaded.Targets[0].NonProduction {
		t.Fatalf("expected non-production target declaration, got %+v", loaded)
	}
}

func TestInvalidControlDeclarationFailsClosed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	payload := []byte(`schema_version: v1
owners:
  - repo: acme/payments
    path: ../outside.yml
    owner: "@acme/platform"
`)
	if err := os.WriteFile(filepath.Join(root, "wrkr-control-declarations.yaml"), payload, 0o600); err != nil {
		t.Fatalf("write declarations: %v", err)
	}

	if _, _, err := LoadControlDeclarations(root); err == nil {
		t.Fatal("expected invalid declaration to fail closed")
	}
}

func TestDuplicateControlDeclarationAcrossFilesFailsClosed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".wrkr"), 0o750); err != nil {
		t.Fatalf("mkdir .wrkr: %v", err)
	}
	first := []byte(`schema_version: v1
owners:
  - repo: acme/payments
    path: .github/workflows/release.yml
    owner: "@acme/platform"
`)
	second := []byte(`schema_version: v1
owners:
  - repo: acme/payments
    path: .github/workflows/release.yml
    owner: "@acme/security"
`)
	if err := os.WriteFile(filepath.Join(root, "wrkr-control-declarations.yaml"), first, 0o600); err != nil {
		t.Fatalf("write root declarations: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".wrkr", "control-declarations.yaml"), second, 0o600); err != nil {
		t.Fatalf("write nested declarations: %v", err)
	}

	if _, _, err := LoadControlDeclarations(root); err == nil {
		t.Fatal("expected duplicate cross-file scope to fail closed")
	}
}
