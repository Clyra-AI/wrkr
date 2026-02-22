package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStory10DiscoveryMethodSchemaContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	findingSchemaPath := filepath.Join(repoRoot, "schemas", "v1", "findings", "finding.schema.json")
	inventorySchemaPath := filepath.Join(repoRoot, "schemas", "v1", "inventory", "inventory.schema.json")
	for _, path := range []string{findingSchemaPath, inventorySchemaPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected schema path %s: %v", path, err)
		}
	}

	findingSchema := mustReadJSON(t, findingSchemaPath)
	props, ok := findingSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("finding schema missing properties: %v", findingSchema)
	}
	discoveryMethod, ok := props["discovery_method"].(map[string]any)
	if !ok {
		t.Fatalf("finding schema missing discovery_method: %v", props)
	}
	enumValues, ok := discoveryMethod["enum"].([]any)
	if !ok || len(enumValues) != 1 || enumValues[0] != "static" {
		t.Fatalf("expected discovery_method enum [static], got %v", discoveryMethod)
	}
}

func TestStory10A2ASchemaPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	schemaPath := filepath.Join(repoRoot, "schemas", "v1", "a2a", "agent-card.schema.json")
	if _, err := os.Stat(schemaPath); err != nil {
		t.Fatalf("expected a2a schema path %s: %v", schemaPath, err)
	}
	schema := mustReadJSON(t, schemaPath)
	if schema["type"] != "object" {
		t.Fatalf("expected object schema, got %v", schema["type"])
	}
}

func mustReadJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	parsed := map[string]any{}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return parsed
}
