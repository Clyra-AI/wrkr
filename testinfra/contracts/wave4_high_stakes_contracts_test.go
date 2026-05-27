package contracts

import (
	"path/filepath"
	"testing"
)

func TestWave4SchemasDeclareHighStakesAndProductionContextContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	cases := []struct {
		name       string
		path       string
		definition string
	}{
		{
			name:       "agent action bom item",
			path:       filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"),
			definition: "item",
		},
		{
			name:       "risk report action path",
			path:       filepath.Join(repoRoot, "schemas", "v1", "risk", "risk-report.schema.json"),
			definition: "actionPath",
		},
		{
			name:       "report summary action path",
			path:       filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"),
			definition: "actionPath",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			schema := mustReadJSON(t, tc.path)
			props := schemaDefinitionProperties(t, schema, tc.definition)
			for _, field := range []string{"authority_bindings", "high_stakes_presets", "production_context"} {
				if _, ok := props[field].(map[string]any); !ok {
					t.Fatalf("%s schema missing %s: %v", tc.name, field, props)
				}
			}

			presetProps := schemaDefinitionProperties(t, schema, "highStakesPreset")
			assertSchemaEnum(t, presetProps["preset"].(map[string]any), []string{
				"release_automation",
				"production_path",
				"credential_bearing_automation",
				"infrastructure_as_code",
				"identity_auth_code",
				"package_publishing",
				"payment_flow",
				"regulated_customer_workflow",
				"external_egress",
				"mcp_tool_config",
				"mutable_endpoint",
			})
		})
	}
}

func TestWave4AuthorityContractsExtendInventoryAndGraphSchemas(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	inventorySchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "inventory", "inventory.schema.json"))
	graphSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "control-path-graph.schema.json"))

	privilegeMap := requireSchemaProperty(t, inventorySchema["properties"].(map[string]any), "agent_privilege_map")
	requireSchemaProperty(t, privilegeMap["items"].(map[string]any)["properties"].(map[string]any), "authority_bindings")

	for _, schema := range []map[string]any{
		schemaDefinition(t, inventorySchema, "credentialProvenance"),
		schemaDefinition(t, inventorySchema, "credentialAuthority"),
		schemaDefinition(t, graphSchema, "credentialAuthority"),
	} {
		props := schema["properties"].(map[string]any)
		for _, field := range []string{"target_system", "likely_scope", "scope_confidence"} {
			if _, ok := props[field]; !ok {
				t.Fatalf("schema missing %s: %v", field, props)
			}
		}
	}

	nodeProps := schemaDefinitionProperties(t, graphSchema, "node")
	if _, ok := nodeProps["authority_bindings"].(map[string]any); !ok {
		t.Fatalf("graph node schema missing authority_bindings: %v", nodeProps)
	}
}

func requireSchemaProperty(t *testing.T, props map[string]any, field string) map[string]any {
	t.Helper()
	raw, ok := props[field].(map[string]any)
	if !ok {
		t.Fatalf("schema missing %s: %v", field, props)
	}
	return raw
}
