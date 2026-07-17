package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestComposedActionPathSchemasValidateMinimalFixture(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	composedPath := filepath.Join(repoRoot, "schemas", "v1", "composed-action-path.schema.json")
	proposedPath := filepath.Join(repoRoot, "schemas", "v1", "proposed-action-contract.schema.json")

	compiler := jsonschema.NewCompiler()
	mustAddCompositionSchemaResource(t, compiler, composedPath)
	mustAddCompositionSchemaResourceAs(t, compiler, "https://wrkr.dev/schemas/v1/proposed-action-contract.schema.json", proposedPath)

	compiled, err := compiler.Compile(composedPath)
	if err != nil {
		t.Fatalf("compile composed action path schema: %v", err)
	}

	fixture := map[string]any{
		"composition_id": "cap-1234",
		"pattern_id":     "secret_to_network",
		"pattern": map[string]any{
			"pattern_id":    "secret_to_network",
			"stage_roles":   []any{"source", "external_sink"},
			"outcome_class": "external_egress",
		},
		"stages": []any{
			map[string]any{
				"stage_id":               "stage-source",
				"role":                   "source",
				"evidence_state":         "inferred",
				"freshness_state":        "unknown",
				"policy_coverage_status": "none",
			},
			map[string]any{
				"stage_id":               "stage-sink",
				"role":                   "external_sink",
				"evidence_state":         "declared",
				"freshness_state":        "fresh",
				"policy_coverage_status": "declared",
			},
		},
		"transitions": []any{
			map[string]any{
				"transition_id":          "transition-1",
				"from_stage_id":          "stage-source",
				"to_stage_id":            "stage-sink",
				"claim_state":            "declared_policy_only",
				"evidence_state":         "declared",
				"policy_coverage_status": "declared",
			},
		},
		"claim_state": "declared_policy_only",
		"proposed_action_contract": map[string]any{
			"contract_id":              "pac-1234",
			"contract_family_id":       "pac-family-1234",
			"contract_content_digest":  "sha256:abc123",
			"contract_version":         "2",
			"contract_kind":            "proposed_action_contract",
			"composition_ref":          "cap-1234",
			"maximum_delegation_depth": 1,
			"report_only":              true,
			"readiness_state":          "needs_evidence",
			"reason_codes":             []any{"report_only:true"},
		},
		"proposed_action_contract_refs": []any{"pac-1234"},
	}
	if err := compiled.Validate(fixture); err != nil {
		t.Fatalf("minimal composed action path fixture must validate: %v", err)
	}
}

func TestCompositionSchemaExamplesValidate(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	composedPath := filepath.Join(repoRoot, "schemas", "v1", "composed-action-path.schema.json")
	proposedPath := filepath.Join(repoRoot, "schemas", "v1", "proposed-action-contract.schema.json")
	testdataRoot := filepath.Join(repoRoot, "schemas", "v1", "testdata")

	compiler := jsonschema.NewCompiler()
	mustAddCompositionSchemaResource(t, compiler, composedPath)
	mustAddCompositionSchemaResourceAs(t, compiler, "https://wrkr.dev/schemas/v1/proposed-action-contract.schema.json", proposedPath)
	composedSchema, err := compiler.Compile(composedPath)
	if err != nil {
		t.Fatalf("compile composed action path schema: %v", err)
	}
	validateCompositionFixtureFile(t, composedSchema, filepath.Join(testdataRoot, "composed-action-path.valid.json"), true)
	validateCompositionFixtureFile(t, composedSchema, filepath.Join(testdataRoot, "composed-action-path.invalid.json"), false)

	proposedCompiler := jsonschema.NewCompiler()
	mustAddCompositionSchemaResource(t, proposedCompiler, proposedPath)
	proposedSchema, err := proposedCompiler.Compile(proposedPath)
	if err != nil {
		t.Fatalf("compile proposed action contract schema: %v", err)
	}
	validateCompositionFixtureFile(t, proposedSchema, filepath.Join(testdataRoot, "proposed-action-contract.valid.json"), true)
	validateCompositionFixtureFile(t, proposedSchema, filepath.Join(testdataRoot, "proposed-action-contract.invalid.json"), false)
}

func TestCompositionSchemasExposeContractSpine(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	composed := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "composed-action-path.schema.json"))
	proposed := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "proposed-action-contract.schema.json"))

	composedProps := compositionSchemaProperties(t, composed)
	for _, field := range []string{
		"composition_id",
		"pattern_id",
		"stages",
		"transitions",
		"claim_state",
		"proposed_action_contract",
		"proposed_action_contract_refs",
	} {
		compositionRequireProperty(t, composedProps, field)
	}

	stageRoleEnum := compositionDefinitionEnum(t, composed, "stageRole")
	for _, role := range []string{"source", "transform", "sink", "internal_sink", "external_sink", "privileged_sink", "destructive_sink"} {
		if !compositionContains(stageRoleEnum, role) {
			t.Fatalf("stageRole enum missing %q: %v", role, stageRoleEnum)
		}
	}
	claimEnum := compositionDefinitionEnum(t, composed, "claimState")
	for _, state := range []string{"static_only", "partially_evidenced", "declared_policy_only", "runtime_controlled", "observed_execution", "contradictory", "unknown"} {
		if !compositionContains(claimEnum, state) {
			t.Fatalf("claimState enum missing %q: %v", state, claimEnum)
		}
	}

	proposedProps := compositionSchemaProperties(t, proposed)
	for _, field := range []string{
		"contract_id",
		"contract_family_id",
		"contract_content_digest",
		"contract_version",
		"contract_kind",
		"composition_ref",
		"allowed_transitions",
		"prohibited_transitions",
		"approval_required_transitions",
		"report_only",
		"readiness_state",
	} {
		compositionRequireProperty(t, proposedProps, field)
	}
	reportOnly := compositionRequireProperty(t, proposedProps, "report_only")
	if reportOnly["const"] != true {
		t.Fatalf("proposed Action Contract schema must keep report_only const true, got %+v", reportOnly)
	}
}

func validateCompositionFixtureFile(t *testing.T, schema *jsonschema.Schema, path string, wantValid bool) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	err = schema.Validate(value)
	if wantValid && err != nil {
		t.Fatalf("expected fixture %s to validate: %v", path, err)
	}
	if !wantValid && err == nil {
		t.Fatalf("expected fixture %s to fail schema validation", path)
	}
}

func TestCompositionFieldsReachAggregateSchemas(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	riskSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "risk", "risk-report.schema.json"))
	reportSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"))
	bomSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"))
	decisionTraceSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "proof-outputs", "decision-trace-record.schema.json"))
	evidenceBundleSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "evidence", "evidence-bundle.schema.json"))

	riskProps := compositionSchemaProperties(t, riskSchema)
	compositionRequireProperty(t, riskProps, "composed_action_paths")
	compositionRequireProperty(t, riskProps, "composed_action_path_to_control_first")
	compositionRequireProperty(t, compositionDefinitionProperties(t, riskSchema, "actionPath"), "composition_ids")
	compositionRequireProperty(t, compositionDefinitionProperties(t, riskSchema, "actionPath"), "proposed_action_contract_refs")

	reportProps := compositionSchemaProperties(t, reportSchema)
	compositionRequireProperty(t, reportProps, "composed_action_paths")
	compositionRequireProperty(t, reportProps, "composed_action_path_to_control_first")
	if got := compositionRequireProperty(t, reportProps, "composed_action_paths")["items"].(map[string]any)["$ref"]; got != "https://wrkr.dev/schemas/v1/composed-action-path.schema.json" {
		t.Fatalf("expected canonical composed-action schema ref in report summary, got %+v", got)
	}
	compositionRequireProperty(t, compositionDefinitionProperties(t, reportSchema, "actionPath"), "composition_ids")
	compositionRequireProperty(t, compositionDefinitionProperties(t, reportSchema, "actionPath"), "proposed_action_contract_refs")
	compositionRequireProperty(t, compositionDefinitionProperties(t, reportSchema, "artifactBudget"), "max_composed_action_paths")
	compositionRequireProperty(t, compositionDefinitionProperties(t, reportSchema, "suppressedCounts"), "composed_action_paths")

	bomProps := compositionSchemaProperties(t, bomSchema)
	compositionRequireProperty(t, bomProps, "composed_action_paths")
	compositionRequireProperty(t, compositionDefinitionProperties(t, bomSchema, "item"), "composition_ids")
	compositionRequireProperty(t, compositionDefinitionProperties(t, bomSchema, "item"), "proposed_action_contract_refs")
	primaryViewProps := compositionDefinitionProperties(t, bomSchema, "primaryView")
	for _, field := range []string{
		"composition_id",
		"composition_stage_map",
		"credential_summary",
		"delegation_summary",
		"target_summary",
		"current_coverage",
		"proposed_control",
		"expected_outcome",
		"proposed_action_contract",
		"closure_requirements",
		"composition_ids",
		"proposed_action_contract_refs",
	} {
		compositionRequireProperty(t, primaryViewProps, field)
	}

	decisionEventProps := compositionSchemaProperties(t, compositionRequireProperty(t, compositionSchemaProperties(t, decisionTraceSchema), "event"))
	for _, field := range []string{
		"resolution_key",
		"composition_ids",
		"proposed_action_contract_refs",
		"workflow_chain_refs",
		"autonomy_tier",
		"recommended_control",
		"evidence_states",
		"gait_coverage",
	} {
		compositionRequireProperty(t, decisionEventProps, field)
	}

	evidenceProps := compositionSchemaProperties(t, evidenceBundleSchema)
	compositionRequireProperty(t, evidenceProps, "composition_refs")
	compositionDefinitionPropertiesDraft7(t, evidenceBundleSchema, "compositionRef")
}

func mustAddCompositionSchemaResource(t *testing.T, compiler *jsonschema.Compiler, path string) {
	t.Helper()
	mustAddCompositionSchemaResourceAs(t, compiler, path, path)
}

func mustAddCompositionSchemaResourceAs(t *testing.T, compiler *jsonschema.Compiler, id string, path string) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read schema %s: %v", path, err)
	}
	if err := compiler.AddResource(id, strings.NewReader(string(payload))); err != nil {
		t.Fatalf("add schema resource %s: %v", id, err)
	}
}

func compositionSchemaProperties(t *testing.T, schema map[string]any) map[string]any {
	t.Helper()
	props, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatalf("schema missing properties")
	}
	return props
}

func compositionDefinitionProperties(t *testing.T, schema map[string]any, definition string) map[string]any {
	t.Helper()
	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("schema missing $defs")
	}
	def, ok := defs[definition].(map[string]any)
	if !ok {
		t.Fatalf("schema missing $defs.%s", definition)
	}
	return compositionSchemaProperties(t, def)
}

func compositionDefinitionPropertiesDraft7(t *testing.T, schema map[string]any, definition string) map[string]any {
	t.Helper()
	defs, ok := schema["definitions"].(map[string]any)
	if !ok {
		t.Fatalf("schema missing definitions")
	}
	def, ok := defs[definition].(map[string]any)
	if !ok {
		t.Fatalf("schema missing definitions.%s", definition)
	}
	return compositionSchemaProperties(t, def)
}

func compositionDefinitionEnum(t *testing.T, schema map[string]any, definition string) []any {
	t.Helper()
	defs, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatalf("schema missing $defs")
	}
	def, ok := defs[definition].(map[string]any)
	if !ok {
		t.Fatalf("schema missing $defs.%s", definition)
	}
	values, ok := def["enum"].([]any)
	if !ok {
		encoded, _ := json.Marshal(def)
		t.Fatalf("schema $defs.%s missing enum: %s", definition, encoded)
	}
	return values
}

func compositionRequireProperty(t *testing.T, props map[string]any, field string) map[string]any {
	t.Helper()
	prop, ok := props[field].(map[string]any)
	if !ok {
		t.Fatalf("schema properties missing %q", field)
	}
	return prop
}

func compositionContains(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
