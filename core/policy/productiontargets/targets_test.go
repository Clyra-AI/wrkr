package productiontargets

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadNormalizesAndDefaultsWritePermissions(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "targets.yaml")
	payload := []byte(`
schema_version: v1
targets:
  repos:
    exact: ["Acme/Payments", "acme/payments"]
  mcp_servers:
    prefix: ["postgres-"]
`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write targets file: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load targets: %v", err)
	}
	if got := len(cfg.WritePermissions); got == 0 {
		t.Fatal("expected default write permissions to be populated")
	}
	if !cfg.Targets.Repos.Match("acme/payments") {
		t.Fatal("expected normalized repo exact match")
	}
	if !cfg.Targets.MCPServers.Match("postgres-prod") {
		t.Fatal("expected prefix match for mcp server")
	}
}

func TestLoadRejectsUnsupportedSchemaVersion(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "targets.yaml")
	if err := os.WriteFile(path, []byte("schema_version: v2\n"), 0o600); err != nil {
		t.Fatalf("write targets file: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected invalid schema version error")
	}
}
