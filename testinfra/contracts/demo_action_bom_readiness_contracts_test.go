package contracts

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestDemoActionBOMReadinessSchemasDeclareBuyerFacingPathFields(t *testing.T) {
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
			for _, field := range []string{
				"control_state",
				"control_state_reasons",
				"risk_zone",
				"risk_zone_reasons",
				"review_burden",
				"review_burden_reasons",
				"gait_coverage",
				"closure_requirements",
				"evidence_completeness",
			} {
				if _, ok := props[field].(map[string]any); !ok {
					t.Fatalf("%s schema missing %s contract field: %v", tc.name, field, props)
				}
			}

			assertSchemaEnum(t, schemaRef(t, schema, props["control_state"]), []string{
				"safe_by_default",
				"approval_required",
				"block_recommended",
				"evidence_required",
				"inventory_only",
			})
			assertSchemaEnum(t, schemaRef(t, schema, props["risk_zone"]), []string{
				"coding_help",
				"repo_write",
				"credential_bearing",
				"ci_cd",
				"iac",
				"release",
				"production_data",
				"external_egress",
			})
			assertSchemaEnum(t, schemaRef(t, schema, props["review_burden"]), []string{
				"low",
				"medium",
				"high",
				"critical",
			})
			assertGaitCoverageContract(t, schemaRef(t, schema, props["gait_coverage"]))
		})
	}
}

func TestDemoActionBOMReadinessSchemasDeclareClosureAndCompletenessSummaryContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	bomSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"))
	reportSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"))

	bomSummaryProps := schemaDefinitionProperties(t, bomSchema, "summary")
	if _, ok := bomSummaryProps["evidence_completeness"].(map[string]any); !ok {
		t.Fatalf("agent action bom summary missing evidence_completeness: %v", bomSummaryProps)
	}
	reportProps, ok := reportSchema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("report summary schema missing properties: %v", reportSchema)
	}
	if _, ok := reportProps["evidence_completeness"].(map[string]any); !ok {
		t.Fatalf("report summary schema missing evidence_completeness: %v", reportProps)
	}

	closureRequirement := schemaDefinition(t, bomSchema, "closureRequirement")
	for _, field := range []string{"id", "severity", "requirement_type", "required_evidence", "guidance"} {
		if _, ok := closureRequirement["properties"].(map[string]any)[field]; !ok {
			t.Fatalf("closure requirement schema missing %s: %v", field, closureRequirement)
		}
	}
	completeness := schemaDefinition(t, bomSchema, "evidenceCompleteness")
	for _, field := range []string{"total_score", "label", "axis_scores"} {
		if _, ok := completeness["properties"].(map[string]any)[field]; !ok {
			t.Fatalf("evidence completeness schema missing %s: %v", field, completeness)
		}
	}
}

func schemaDefinitionProperties(t *testing.T, schema map[string]any, definition string) map[string]any {
	t.Helper()

	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("schema missing $defs: %v", schema)
	}
	def, ok := defs[definition].(map[string]any)
	if !ok {
		t.Fatalf("schema missing $defs.%s: %v", definition, defs)
	}
	props, ok := def["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema definition %s missing properties: %v", definition, def)
	}
	return props
}

func schemaRef(t *testing.T, schema map[string]any, node any) map[string]any {
	t.Helper()

	refNode, ok := node.(map[string]any)
	if !ok {
		t.Fatalf("schema node is not an object: %v", node)
	}
	ref, ok := refNode["$ref"].(string)
	if !ok {
		return refNode
	}
	if len(ref) <= len("#/$defs/") || ref[:len("#/$defs/")] != "#/$defs/" {
		t.Fatalf("unsupported local schema ref %q", ref)
	}
	return schemaDefinition(t, schema, ref[len("#/$defs/"):])
}

func schemaDefinition(t *testing.T, schema map[string]any, definition string) map[string]any {
	t.Helper()

	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("schema missing $defs: %v", schema)
	}
	def, ok := defs[definition].(map[string]any)
	if !ok {
		t.Fatalf("schema missing $defs.%s: %v", definition, defs)
	}
	return def
}

func assertSchemaEnum(t *testing.T, node map[string]any, want []string) {
	t.Helper()

	raw, ok := node["enum"].([]any)
	if !ok {
		t.Fatalf("schema node missing enum: %v", node)
	}
	got := make([]string, 0, len(raw))
	for _, item := range raw {
		value, ok := item.(string)
		if !ok {
			t.Fatalf("schema enum contains non-string value: %v", raw)
		}
		got = append(got, value)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected enum values\ngot:  %v\nwant: %v", got, want)
	}
}

func assertGaitCoverageContract(t *testing.T, node map[string]any) {
	t.Helper()

	requiredRaw, ok := node["required"].([]any)
	if !ok {
		t.Fatalf("gait coverage schema missing required controls: %v", node)
	}
	gotRequired := make([]string, 0, len(requiredRaw))
	for _, item := range requiredRaw {
		value, ok := item.(string)
		if !ok {
			t.Fatalf("gait coverage required contains non-string value: %v", requiredRaw)
		}
		gotRequired = append(gotRequired, value)
	}
	wantRequired := []string{
		"policy_decision",
		"approval",
		"jit_credential",
		"freeze_window",
		"kill_switch",
		"action_outcome",
		"proof_verification",
	}
	if !reflect.DeepEqual(gotRequired, wantRequired) {
		t.Fatalf("unexpected gait coverage required controls\ngot:  %v\nwant: %v", gotRequired, wantRequired)
	}

	props, ok := node["properties"].(map[string]any)
	if !ok {
		t.Fatalf("gait coverage schema missing properties: %v", node)
	}
	for _, field := range wantRequired {
		if _, ok := props[field].(map[string]any); !ok {
			t.Fatalf("gait coverage schema missing %s detail property: %v", field, props)
		}
	}
}
