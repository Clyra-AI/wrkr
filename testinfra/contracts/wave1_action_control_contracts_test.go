package contracts

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestWave1SchemasDeclareAutonomyReadinessAndGovernedPathContracts(t *testing.T) {
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
				"autonomy_tier",
				"autonomy_tier_reasons",
				"delegation_readiness_state",
				"recommended_control",
				"risk_classification_validation_reasons",
				"recommended_action_contract",
				"today_path",
				"recommended_governed_path",
			} {
				if _, ok := props[field].(map[string]any); !ok {
					t.Fatalf("%s schema missing %s field: %v", tc.name, field, props)
				}
			}

			assertSchemaEnum(t, schemaRef(t, schema, props["autonomy_tier"]), []string{
				"tier_0_safe_metadata",
				"tier_1_low_risk_internal",
				"tier_2_app_code_owner_review",
				"tier_3_sensitive_code_or_infra",
				"tier_4_prod_privileged_or_customer_impacting",
			})
			assertSchemaEnum(t, schemaRef(t, schema, props["delegation_readiness_state"]), []string{
				"safe_to_delegate",
				"review_required",
				"approval_required",
				"proof_required",
				"ready_for_control",
				"blocked",
				"blocked_by_contradiction",
			})
			assertSchemaEnum(t, schemaRef(t, schema, props["recommended_control"]), []string{
				"allow",
				"owner_review",
				"security_review",
				"approval_required",
				"jit_credential_required",
				"proof_required",
				"block_standing_credential",
				"block",
			})
		})
	}
}

func TestWave1AgentActionBOMSummaryDeclaresNewCountBuckets(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	schema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"))
	props := schemaDefinitionProperties(t, schema, "summary")

	for _, field := range []string{"autonomy_tiers", "delegation_readiness", "recommended_controls"} {
		if _, ok := props[field].(map[string]any); !ok {
			t.Fatalf("agent action bom summary missing %s: %v", field, props)
		}
	}

	counts := schemaRef(t, schema, props["autonomy_tiers"])
	want := []string{
		"tier_0_safe_metadata",
		"tier_1_low_risk_internal",
		"tier_2_app_code_owner_review",
		"tier_3_sensitive_code_or_infra",
		"tier_4_prod_privileged_or_customer_impacting",
	}
	got := make([]string, 0, len(want))
	for key := range counts["properties"].(map[string]any) {
		got = append(got, key)
	}
	sortStrings(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected autonomy tier count fields\ngot:  %v\nwant: %v", got, want)
	}
}

func sortStrings(values []string) {
	for i := 0; i < len(values); i++ {
		for j := i + 1; j < len(values); j++ {
			if values[j] < values[i] {
				values[i], values[j] = values[j], values[i]
			}
		}
	}
}
