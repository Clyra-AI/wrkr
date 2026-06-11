package contracts

import (
	"path/filepath"
	"testing"
)

func TestWave40SchemasDeclareEnterpriseContextFields(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	cases := []struct {
		name       string
		path       string
		definition string
		required   []string
	}{
		{
			name:       "agent action bom item",
			path:       filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"),
			definition: "item",
			required: []string{
				"runtime_provider",
				"runtime_host",
				"runtime_kind",
				"model_provider",
				"model_version",
				"execution_environment",
				"state_retention_status",
				"agent_identity",
				"decision_precedent",
				"delivery_control_context",
			},
		},
		{
			name:       "risk report action path",
			path:       filepath.Join(repoRoot, "schemas", "v1", "risk", "risk-report.schema.json"),
			definition: "actionPath",
			required: []string{
				"runtime_provider",
				"runtime_host",
				"runtime_kind",
				"model_provider",
				"model_version",
				"execution_environment",
				"state_retention_status",
				"agent_identity",
				"decision_precedent",
				"delivery_control_context",
			},
		},
		{
			name:       "report summary action path",
			path:       filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"),
			definition: "actionPath",
			required: []string{
				"runtime_provider",
				"runtime_host",
				"runtime_kind",
				"model_provider",
				"model_version",
				"execution_environment",
				"state_retention_status",
				"agent_identity",
				"decision_precedent",
				"delivery_control_context",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			schema := mustReadJSON(t, tc.path)
			props := schemaDefinitionProperties(t, schema, tc.definition)
			for _, key := range tc.required {
				if _, ok := props[key].(map[string]any); !ok {
					t.Fatalf("%s schema missing %s: %v", tc.name, key, props)
				}
			}
		})
	}
}
