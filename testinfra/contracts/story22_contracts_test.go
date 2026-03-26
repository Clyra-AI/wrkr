package contracts

import (
	"path/filepath"
	"testing"
)

func TestStory22InventorySchemaIncludesLocalGovernanceAndNonHumanIdentities(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	schemaPath := filepath.Join(repoRoot, "schemas", "v1", "inventory", "inventory.schema.json")
	schema := mustReadJSON(t, schemaPath)
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("inventory schema missing properties: %v", schema)
	}
	if _, ok := props["local_governance"].(map[string]any); !ok {
		t.Fatalf("expected local_governance property in inventory schema: %v", props)
	}
	if _, ok := props["non_human_identities"].(map[string]any); !ok {
		t.Fatalf("expected non_human_identities property in inventory schema: %v", props)
	}
}
