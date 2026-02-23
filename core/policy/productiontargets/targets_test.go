package productiontargets

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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

func TestLoadRejectsUnknownSchemaFields(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "targets.yaml")
	payload := []byte(`
schema_version: v1
targets:
  workflow_env_keys:
    exact: ["DEPLOY_ENV"]
    prod_values_exact: ["production"]
`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write targets file: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected schema validation error for unknown field")
	}
}

func TestLoadRejectsInvalidWritePermissionsType(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "targets.yaml")
	payload := []byte(`
schema_version: v1
targets: {}
write_permissions: db.write
`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write targets file: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("expected schema validation error for invalid write_permissions type")
	}
}

func TestEmbeddedSchemaMatchesCanonicalContract(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve current file path")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", "..", ".."))
	canonicalPath := filepath.Join(repoRoot, "schemas", "v1", "policy", "production-targets.schema.json")

	canonicalBytes, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatalf("read canonical schema: %v", err)
	}
	var canonical map[string]any
	if err := json.Unmarshal(canonicalBytes, &canonical); err != nil {
		t.Fatalf("parse canonical schema: %v", err)
	}
	var embedded map[string]any
	if err := json.Unmarshal(productionTargetsSchemaJSON, &embedded); err != nil {
		t.Fatalf("parse embedded schema: %v", err)
	}
	if !reflect.DeepEqual(canonical, embedded) {
		t.Fatal("embedded production target schema drifted from canonical schema contract")
	}
}
