//go:build scenario

package scenarios

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScenarioAgentActionBOMDemoContract(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	expectedRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "agent-action-bom-demo", "expected")

	beforeOutput := filepath.Join(t.TempDir(), "before")
	runDemoScript(t, repoRoot, "before", beforeOutput)
	beforeScan := extractDemoTopActionPath(t, filepath.Join(beforeOutput, "scan.json"))
	beforeReport := extractDemoTopBOM(t, filepath.Join(beforeOutput, "report.json"))

	afterOutput := filepath.Join(t.TempDir(), "after")
	runDemoScript(t, repoRoot, "after", afterOutput)
	afterScan := extractDemoTopActionPath(t, filepath.Join(afterOutput, "scan.json"))
	afterReport := extractDemoTopBOM(t, filepath.Join(afterOutput, "report.json"))
	afterIngest := extractDemoJSONFile(t, filepath.Join(afterOutput, "ingest.json"), "runtime_evidence", "correlations")
	afterEvidenceReport := extractDemoEvidenceReport(t, filepath.Join(afterOutput, "evidence-bundle", "reports", "agent-action-bom.json"))

	assertDemoScenarioEqual(t, beforeScan, mustLoadDemoScenarioValue(t, filepath.Join(expectedRoot, "before-scan.json")))
	assertDemoScenarioEqual(t, beforeReport, mustLoadDemoScenarioValue(t, filepath.Join(expectedRoot, "before-report.json")))
	assertDemoScenarioEqual(t, afterScan, mustLoadDemoScenarioValue(t, filepath.Join(expectedRoot, "after-scan.json")))
	assertDemoScenarioEqual(t, afterReport, mustLoadDemoScenarioValue(t, filepath.Join(expectedRoot, "after-report.json")))
	assertDemoScenarioEqual(t, afterIngest, mustLoadDemoScenarioValue(t, filepath.Join(expectedRoot, "after-ingest.json")))
	assertDemoScenarioEqual(t, afterEvidenceReport, mustLoadDemoScenarioValue(t, filepath.Join(expectedRoot, "after-evidence-report.json")))
}

func runDemoScript(t *testing.T, repoRoot, mode, outputRoot string) {
	t.Helper()

	cmd := exec.Command("bash", filepath.Join(repoRoot, "scripts", "run_agent_action_bom_demo.sh"), mode, outputRoot) // #nosec G204 -- deterministic local demo fixture runner.
	cmd.Dir = repoRoot
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("demo script failed mode=%s err=%v stderr=%s", mode, err, errOut.String())
	}
}

func extractDemoTopActionPath(t *testing.T, path string) map[string]any {
	t.Helper()
	payload := mustLoadDemoScenarioJSON(t, path)
	paths := requireDemoScenarioArray(t, payload, "action_paths")
	first := requireDemoScenarioObjectItem(t, paths[0])
	return map[string]any{
		"top_action_path": map[string]any{
			"path_id":                    first["path_id"],
			"tool_type":                  first["tool_type"],
			"repo":                       first["repo"],
			"location":                   first["location"],
			"action_classes":             first["action_classes"],
			"credential_kind":            requireDemoScenarioObject(t, first, "credential_provenance")["credential_kind"],
			"control_state":              first["control_state"],
			"risk_zone":                  first["risk_zone"],
			"review_burden":              first["review_burden"],
			"introduced_by":              first["introduced_by"],
			"matched_production_targets": first["matched_production_targets"],
			"policy_coverage_status":     first["policy_coverage_status"],
		},
	}
}

func extractDemoTopBOM(t *testing.T, path string) map[string]any {
	t.Helper()
	payload := mustLoadDemoScenarioJSON(t, path)
	bom := requireDemoScenarioObject(t, payload, "agent_action_bom")
	items := requireDemoScenarioArray(t, bom, "items")
	first := requireDemoScenarioObjectItem(t, items[0])
	topItem := map[string]any{
		"path_id":                 first["path_id"],
		"tool_type":               first["tool_type"],
		"control_state":           first["control_state"],
		"risk_zone":               first["risk_zone"],
		"review_burden":           first["review_burden"],
		"proof_coverage":          first["proof_coverage"],
		"policy_status":           first["policy_status"],
		"runtime_evidence_status": demoScenarioString(first["runtime_evidence_status"]),
		"introduced_by":           first["introduced_by"],
		"gait_coverage":           first["gait_coverage"],
	}
	if classes, ok := first["runtime_evidence_classes"]; ok && classes != nil {
		topItem["runtime_evidence_classes"] = classes
	}
	return map[string]any{
		"runtime_evidence": demoScenarioRuntimeEvidenceSummary(payload["runtime_evidence"]),
		"summary":          extractDemoBOMSummary(t, requireDemoScenarioObject(t, bom, "summary")),
		"top_item":         topItem,
	}
}

func extractDemoEvidenceReport(t *testing.T, path string) map[string]any {
	t.Helper()
	payload := mustLoadDemoScenarioJSON(t, path)
	items := requireDemoScenarioArray(t, payload, "items")
	first := requireDemoScenarioObjectItem(t, items[0])
	topItem := map[string]any{
		"path_id":                 first["path_id"],
		"tool_type":               first["tool_type"],
		"control_state":           first["control_state"],
		"risk_zone":               first["risk_zone"],
		"review_burden":           first["review_burden"],
		"proof_coverage":          first["proof_coverage"],
		"policy_status":           first["policy_status"],
		"runtime_evidence_status": demoScenarioString(first["runtime_evidence_status"]),
		"introduced_by":           first["introduced_by"],
		"gait_coverage":           first["gait_coverage"],
	}
	if classes, ok := first["runtime_evidence_classes"]; ok && classes != nil {
		topItem["runtime_evidence_classes"] = classes
	}
	return map[string]any{
		"top_item": topItem,
		"summary":  extractDemoBOMSummary(t, requireDemoScenarioObject(t, payload, "summary")),
	}
}

func extractDemoBOMSummary(t *testing.T, summary map[string]any) map[string]any {
	t.Helper()

	out := map[string]any{
		"total_items":                     summary["total_items"],
		"control_first_items":             summary["control_first_items"],
		"standing_privilege_items":        summary["standing_privilege_items"],
		"static_credential_items":         summary["static_credential_items"],
		"production_target_items":         summary["production_target_items"],
		"missing_approval_items":          summary["missing_approval_items"],
		"missing_policy_items":            summary["missing_policy_items"],
		"missing_proof_items":             summary["missing_proof_items"],
		"runtime_proven_items":            summary["runtime_proven_items"],
		"confirmed_action_path_items":     summary["confirmed_action_path_items"],
		"likely_action_path_items":        summary["likely_action_path_items"],
		"semantic_review_candidate_items": summary["semantic_review_candidate_items"],
		"context_only_items":              summary["context_only_items"],
		"autonomy_tiers":                  summary["autonomy_tiers"],
		"delegation_readiness":            summary["delegation_readiness"],
		"recommended_controls":            summary["recommended_controls"],
		"coverage_confidence":             summary["coverage_confidence"],
		"empty_state_status":              summary["empty_state_status"],
		"empty_state_reasons":             summary["empty_state_reasons"],
		"scan_scope":                      summary["scan_scope"],
		"operational_exposure":            summary["operational_exposure"],
		"governance_readiness":            summary["governance_readiness"],
		"governed_usage_metrics":          summary["governed_usage_metrics"],
		"repeat_usage_signals":            summary["repeat_usage_signals"],
	}

	if evidence, ok := summary["evidence_completeness"].(map[string]any); ok {
		out["evidence_completeness"] = map[string]any{
			"average_total_score": evidence["average_total_score"],
			"label":               evidence["label"],
			"path_count":          evidence["path_count"],
			"axis_scores":         evidence["axis_scores"],
			"reasons":             evidence["reasons"],
		}
	}
	if rollup, ok := summary["executive_rollup"].(map[string]any); ok {
		out["executive_rollup"] = map[string]any{
			"total_groups": rollup["total_groups"],
			"total_paths":  rollup["total_paths"],
			"groups":       rollup["groups"],
		}
	}
	if primary, ok := summary["primary_view"].(map[string]any); ok {
		out["primary_view"] = map[string]any{
			"path_id":                     primary["path_id"],
			"selection_reason":            primary["selection_reason"],
			"boundary_label":              primary["boundary_label"],
			"approval_evidence_state":     primary["approval_evidence_state"],
			"credential_evidence_state":   primary["credential_evidence_state"],
			"proof_evidence_state":        primary["proof_evidence_state"],
			"runtime_evidence_state":      primary["runtime_evidence_state"],
			"target_evidence_state":       primary["target_evidence_state"],
			"autonomy_tier":               primary["autonomy_tier"],
			"delegation_readiness_state":  primary["delegation_readiness_state"],
			"recommended_control":         primary["recommended_control"],
			"risk_tier":                   primary["risk_tier"],
			"evidence_completeness_label": primary["evidence_completeness_label"],
			"evidence_completeness_score": primary["evidence_completeness_score"],
			"unresolved_evidence":         primary["unresolved_evidence"],
			"recommended_next_actions":    primary["recommended_next_actions"],
			"coverage_status":             primary["coverage_status"],
			"coverage_impact":             primary["coverage_impact"],
			"path_map":                    primary["path_map"],
			"today_path":                  primary["today_path"],
			"recommended_governed_path":   primary["recommended_governed_path"],
			"recommended_action_contract": primary["recommended_action_contract"],
			"decision_trace_refs":         primary["decision_trace_refs"],
			"appendix_refs":               primary["appendix_refs"],
		}
	}
	return out
}

func extractDemoJSONFile(t *testing.T, path string, keys ...string) any {
	t.Helper()
	payload := mustLoadDemoScenarioJSON(t, path)
	value := any(payload)
	for _, key := range keys {
		obj, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("expected object while walking %s at key %s", path, key)
		}
		value = obj[key]
	}
	return value
}

func mustLoadDemoScenarioJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return decoded
}

func mustLoadDemoScenarioValue(t *testing.T, path string) any {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return decoded
}

func assertDemoScenarioEqual(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scenario mismatch\nwant=%#v\ngot=%#v", want, got)
	}
}

func requireDemoScenarioObject(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := payload[key].(map[string]any)
	if !ok {
		t.Fatalf("expected object %s, got %T (%v)", key, payload[key], payload[key])
	}
	return value
}

func requireDemoScenarioArray(t *testing.T, payload map[string]any, key string) []any {
	t.Helper()
	value, ok := payload[key].([]any)
	if !ok {
		t.Fatalf("expected array %s, got %T (%v)", key, payload[key], payload[key])
	}
	return value
}

func requireDemoScenarioObjectItem(t *testing.T, value any) map[string]any {
	t.Helper()
	record, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected object item, got %T (%v)", value, value)
	}
	return record
}

func demoScenarioString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

func demoScenarioRuntimeEvidenceSummary(value any) any {
	if value == nil {
		return nil
	}
	record, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	correlations, _ := record["correlations"].([]any)
	return map[string]any{
		"matched_records":   record["matched_records"],
		"unmatched_records": record["unmatched_records"],
		"correlation_count": float64(len(correlations)),
	}
}
