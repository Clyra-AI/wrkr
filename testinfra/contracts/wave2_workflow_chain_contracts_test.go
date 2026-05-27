package contracts

import (
	"path/filepath"
	"testing"
)

func TestWave2SchemasDeclareWorkflowChainRefsAndArtifacts(t *testing.T) {
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
			if _, ok := props["workflow_chain_refs"].(map[string]any); !ok {
				t.Fatalf("%s schema missing workflow_chain_refs: %v", tc.name, props)
			}
		})
	}

	riskSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "risk", "risk-report.schema.json"))
	if _, ok := riskSchema["properties"].(map[string]any)["workflow_chains"].(map[string]any); !ok {
		t.Fatalf("risk report schema missing workflow_chains: %v", riskSchema["properties"])
	}

	reportSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"))
	if _, ok := reportSchema["properties"].(map[string]any)["workflow_chains"].(map[string]any); !ok {
		t.Fatalf("report summary schema missing workflow_chains: %v", reportSchema["properties"])
	}
}

func TestWave2SchemasDeclareGraphV2AndExtendedLineageKinds(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	graphSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "control-path-graph.schema.json"))
	nodeProps := schemaDefinitionProperties(t, graphSchema, "node")
	assertSchemaEnum(t, map[string]any{
		"enum": nodeProps["kind"].(map[string]any)["enum"],
	}, []string{
		"control_path",
		"agent",
		"execution_identity",
		"credential",
		"tool",
		"workflow",
		"repo",
		"governance_control",
		"target",
		"action_capability",
		"intent",
		"task",
		"human_identity",
		"agent_team",
		"pull_request",
		"approval_identity",
		"policy_identity",
		"asset_identity",
		"evidence_identity",
		"deployment_path",
		"ci_cd_run",
		"workflow_run",
		"outcome",
	})

	summaryProps, ok := graphSchema["properties"].(map[string]any)["summary"].(map[string]any)["properties"].(map[string]any)
	if !ok {
		t.Fatalf("control path graph schema missing summary properties: %v", graphSchema["properties"])
	}
	for _, field := range []string{"autonomy_tiers", "delegation_readiness_states", "evidence_states"} {
		if _, ok := summaryProps[field].(map[string]any); !ok {
			t.Fatalf("control path graph summary missing %s: %v", field, summaryProps)
		}
	}

	for _, path := range []string{
		filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"),
		filepath.Join(repoRoot, "schemas", "v1", "risk", "risk-report.schema.json"),
		filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"),
	} {
		schema := mustReadJSON(t, path)
		segmentProps := schemaDefinitionProperties(t, schema, "actionLineageSegment")
		assertSchemaEnum(t, map[string]any{
			"enum": segmentProps["kind"].(map[string]any)["enum"],
		}, []string{
			"repo",
			"workflow",
			"agent",
			"action",
			"credential",
			"target",
			"owner",
			"approval",
			"proof",
			"intent",
			"task",
			"human",
			"pr",
			"workflow_run",
			"control",
			"deployment",
			"outcome",
			"evidence",
		})
	}
}
