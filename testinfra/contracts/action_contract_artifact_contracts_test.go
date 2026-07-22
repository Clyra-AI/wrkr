package contracts

import (
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestActionContractArtifactSchemaValidatesPortableV3Envelope(t *testing.T) {
	t.Parallel()
	repoRoot := mustFindRepoRoot(t)
	artifactPath := filepath.Join(repoRoot, "schemas", "v1", "proposed-action-contract-artifact.schema.json")
	v3Path := filepath.Join(repoRoot, "schemas", "v1", "proposed-action-contract-v3.schema.json")
	compiler := jsonschema.NewCompiler()
	mustAddCompositionSchemaResourceAs(t, compiler, "https://wrkr.dev/schemas/v1/proposed-action-contract-v3.schema.json", v3Path)
	mustAddCompositionSchemaResource(t, compiler, artifactPath)
	compiled, err := compiler.Compile(artifactPath)
	if err != nil {
		t.Fatalf("compile artifact schema: %v", err)
	}
	contract := map[string]any{
		"contract_id": "pac-0123456789abcdef", "contract_family_id": "pacf-0123", "contract_content_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"contract_version": "3", "contract_kind": "proposed_action_contract", "composition_ref": "cap-1", "revision": 1,
		"authority_requirements": []any{map[string]any{"requirement_id": "pacr-owner", "kind": "business_owner", "required_constraint": "business_owner:required", "evidence_state": "unknown", "freshness_state": "unknown"}}, "authority_readiness_state": "needs_evidence",
		"preconditions":            []any{map[string]any{"requirement_id": "pacp-target", "kind": "target", "required_constraint": "target:bounded", "evidence_state": "unknown", "freshness_state": "unknown"}},
		"confirmation_requirement": map[string]any{"mode": "not_required", "required": false, "evidence_state": "verified", "freshness_state": "unknown"},
		"approval_requirement":     map[string]any{"required": false, "minimum_approvals": 0, "scope_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "evidence_state": "verified", "freshness_state": "unknown"},
		"compensation_requirement": map[string]any{"required": false, "kind": "not_required", "verification_required": false, "evidence_state": "verified", "freshness_state": "unknown"}, "maximum_delegation_depth": 1, "report_only": true,
	}
	fixture := map[string]any{
		"schema_id": "https://wrkr.dev/schemas/v1/proposed-action-contract-artifact.schema.json", "schema_version": "1", "artifact_id": "paca-0123456789abcdef", "contract_id": "pac-0123456789abcdef", "contract_family_id": "pacf-0123", "revision": 1,
		"producer": map[string]any{"name": "wrkr", "artifact_schema_version": "1", "contract_schema_version": "3"}, "source_scan_refs": []any{"saved_scan:v1"}, "composition_refs": []any{"cap-1"}, "creation_evidence": []any{"risk_assessment:pac-0123456789abcdef"}, "canonical_content_digest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", "variant": map[string]any{"share_profile": "internal", "redacted": false}, "report_only": true, "contract": contract,
	}
	if err := compiled.Validate(fixture); err != nil {
		t.Fatalf("portable artifact fixture must validate: %v", err)
	}
	for _, kind := range []string{"documented_recovery", "rollback", "restore", "irreversible_escalation", "not_required"} {
		required := kind != "not_required"
		evidenceState := "verified"
		if kind == "irreversible_escalation" {
			evidenceState = "contradictory"
		}
		contract["compensation_requirement"] = map[string]any{
			"required": required, "kind": kind, "verification_required": required,
			"evidence_state": evidenceState, "freshness_state": "unknown",
		}
		if err := compiled.Validate(fixture); err != nil {
			t.Fatalf("compensation kind %q must remain schema-compatible: %v", kind, err)
		}
	}
	contract["compensation_requirement"] = map[string]any{"required": false, "kind": "custom_script", "verification_required": false, "evidence_state": "verified", "freshness_state": "unknown"}
	if err := compiled.Validate(fixture); err == nil {
		t.Fatal("artifact must reject unsupported compensation kind")
	}
	contract["compensation_requirement"] = map[string]any{"required": false, "kind": "not_required", "verification_required": false, "evidence_state": "verified", "freshness_state": "unknown"}
	contract["contract_version"] = "2"
	if err := compiled.Validate(fixture); err == nil {
		t.Fatal("artifact must reject embedded v2 contract")
	}
}
