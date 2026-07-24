package acceptance

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAgentActionBOMAcceptanceStaticToRuntimeEvidence(t *testing.T) {
	t.Parallel()

	paths := loadAcceptancePaths(t)

	beforeState := filepath.Join(t.TempDir(), "before-state.json")
	beforeScanRoot := filepath.Join(paths.repoRoot, "scenarios", "wrkr", "agent-action-bom-demo", "before", "repos")
	beforeScan := runJSONOK(t, "scan", "--path", beforeScanRoot, "--state", beforeState, "--json")
	beforeReport := runJSONOK(t, "report", "--state", beforeState, "--template", "agent-action-bom", "--share-profile", "internal", "--json")

	beforeActionPaths := requireArray(t, beforeScan, "action_paths")
	beforeTopPath := requireObjectItem(t, beforeActionPaths[0])
	beforeBOM := requireObject(t, beforeReport, "agent_action_bom")
	beforeBOMSummary := requireObject(t, beforeBOM, "summary")
	beforeItems := requireArrayFromObject(t, beforeBOM, "items")
	beforeTopItem := requireObjectItem(t, beforeItems[0])
	beforePrimaryView := requireObject(t, beforeBOMSummary, "primary_view")
	if beforeTopItem["policy_status"] != "none" {
		t.Fatalf("expected pre-ingest policy gap, got %v", beforeTopItem["policy_status"])
	}
	if beforePrimaryView["path_id"] != beforeTopItem["path_id"] || beforePrimaryView["selection_reason"] != "default_top_path" {
		t.Fatalf("expected default primary view to follow top BOM item, got summary=%v item=%v", beforePrimaryView, beforeTopItem)
	}
	if beforeTopPath["control_state"] != "block_recommended" || beforeTopPath["risk_zone"] == nil || beforeTopPath["review_burden"] == nil {
		t.Fatalf("expected buyer-facing action-path projections before ingest, got %v", beforeTopPath)
	}
	introducedBy := requireObject(t, beforeTopPath, "introduced_by")
	if introducedBy["pr_number"] != float64(108) {
		t.Fatalf("expected deterministic PR provenance before ingest, got %v", introducedBy)
	}
	beforeCoverage := requireObject(t, beforeTopItem, "gait_coverage")
	if requireObject(t, beforeCoverage, "policy_decision")["status"] != "missing" {
		t.Fatalf("expected missing pre-ingest Gait coverage, got %v", beforeCoverage)
	}
	if _, ok := beforeReport["runtime_evidence"]; ok {
		t.Fatalf("expected pre-ingest report runtime_evidence to be omitted, got %v", beforeReport["runtime_evidence"])
	}

	afterState := filepath.Join(t.TempDir(), "after-state.json")
	afterRoot := filepath.Join(paths.repoRoot, "scenarios", "wrkr", "agent-action-bom-demo", "after")
	afterScanRoot := filepath.Join(afterRoot, "repos")
	runtimeEvidencePath := filepath.Join(afterRoot, "runtime-evidence.json")
	afterScan := runJSONOK(t, "scan", "--path", afterScanRoot, "--state", afterState, "--json")
	runJSONOK(t, "ingest", "--state", afterState, "--input", runtimeEvidencePath, "--json")
	afterReport := runJSONOK(t, "report", "--state", afterState, "--template", "agent-action-bom", "--share-profile", "internal", "--json", "--evidence-json", "--evidence-json-path", filepath.Join(t.TempDir(), "agent-action-bom-evidence.json"))

	afterActionPaths := requireArray(t, afterScan, "action_paths")
	afterTopPath := requireObjectItem(t, afterActionPaths[0])
	if beforeTopPath["path_id"] != afterTopPath["path_id"] {
		t.Fatalf("expected stable top path id across before/after fixtures, before=%v after=%v", beforeTopPath["path_id"], afterTopPath["path_id"])
	}
	if afterTopPath["policy_coverage_status"] != "matched" {
		t.Fatalf("expected after scan to show static policy match, got %v", afterTopPath["policy_coverage_status"])
	}
	if afterTopPath["control_state"] != "block_recommended" {
		t.Fatalf("expected stable buyer-facing state after scan, got %v", afterTopPath["control_state"])
	}

	afterBOM := requireObject(t, afterReport, "agent_action_bom")
	afterBOMSummary := requireObject(t, afterBOM, "summary")
	afterItems := requireArrayFromObject(t, afterBOM, "items")
	afterTopItem := requireObjectItem(t, afterItems[0])
	afterPrimaryView := requireObject(t, afterBOMSummary, "primary_view")
	reportRuntimeEvidence := requireObject(t, afterReport, "runtime_evidence")
	reportSummary := requireObject(t, afterReport, "summary")
	if !reflect.DeepEqual(reportRuntimeEvidence, requireObject(t, reportSummary, "runtime_evidence")) {
		t.Fatalf("expected top-level and summary runtime_evidence to match\nreport=%v\nsummary=%v", reportRuntimeEvidence, reportSummary["runtime_evidence"])
	}
	if afterTopItem["path_id"] != beforeTopItem["path_id"] {
		t.Fatalf("expected same BOM item path id across before/after, before=%v after=%v", beforeTopItem["path_id"], afterTopItem["path_id"])
	}
	if afterPrimaryView["path_id"] != afterTopItem["path_id"] || afterPrimaryView["selection_reason"] != "default_top_path" {
		t.Fatalf("expected default primary view after ingest, got summary=%v item=%v", afterPrimaryView, afterTopItem)
	}
	if afterTopItem["policy_status"] != "runtime_proven" {
		t.Fatalf("expected runtime-proven policy coverage after ingest, got %v", afterTopItem["policy_status"])
	}
	if afterTopItem["runtime_evidence_status"] != "matched" {
		t.Fatalf("expected runtime evidence to correlate after ingest, got %v", afterTopItem["runtime_evidence_status"])
	}
	afterCoverage := requireObject(t, afterTopItem, "gait_coverage")
	for _, key := range []string{"policy_decision", "approval", "freeze_window", "kill_switch", "action_outcome", "proof_verification"} {
		if requireObject(t, afterCoverage, key)["status"] != "present" {
			t.Fatalf("expected present Gait coverage for %s after ingest, got %v", key, afterCoverage)
		}
	}
	classes := requireArrayFromObject(t, afterTopItem, "runtime_evidence_classes")
	for _, required := range []string{"approval", "policy_decision", "proof_verification"} {
		if !containsArrayValue(classes, required) {
			t.Fatalf("expected runtime evidence class %s, got %v", required, classes)
		}
	}

	outputDir := filepath.Join(t.TempDir(), "evidence-bundle")
	evidencePayload := runJSONOK(t, "evidence", "--frameworks", "soc2", "--state", afterState, "--output", outputDir, "--json")
	evidenceRuntimeEvidence := requireObject(t, evidencePayload, "runtime_evidence")
	if reportRuntimeEvidence["matched_records"] != evidenceRuntimeEvidence["matched_records"] || reportRuntimeEvidence["unmatched_records"] != evidenceRuntimeEvidence["unmatched_records"] {
		t.Fatalf("expected report/evidence runtime_evidence counts to agree, report=%v evidence=%v", reportRuntimeEvidence, evidenceRuntimeEvidence)
	}
	evidenceBOM := requireObject(t, evidencePayload, "agent_action_bom")
	if evidenceBOM["share_profile"] != "customer-redacted" {
		t.Fatalf("expected evidence BOM share profile to be customer-redacted, got %v", evidenceBOM["share_profile"])
	}
	bundleRedactedBOM := loadAcceptanceJSONFile(t, filepath.Join(outputDir, "reports", "agent-action-bom-customer-redacted.json"))
	bundleItems := requireArrayFromObject(t, bundleRedactedBOM, "items")
	evidenceItems := requireArrayFromObject(t, evidenceBOM, "items")
	if len(bundleItems) <= len(evidenceItems) {
		t.Fatalf("expected evidence command response to preview the fuller canonical BOM: artifact_items=%d preview_items=%d", len(bundleItems), len(evidenceItems))
	}
	for _, previewItem := range evidenceItems {
		found := false
		for _, artifactItem := range bundleItems {
			if reflect.DeepEqual(previewItem, artifactItem) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected every evidence BOM preview item to come from the canonical artifact: %v", previewItem)
		}
	}
	suppressedCounts := requireObject(t, evidencePayload, "suppressed_counts")
	if suppressedCounts["agent_action_bom"] != float64(len(bundleItems)-len(evidenceItems)) {
		t.Fatalf("expected exact BOM suppression receipt, artifact_items=%d preview_items=%d suppressed=%v", len(bundleItems), len(evidenceItems), suppressedCounts)
	}
	artifactPaths := requireObject(t, evidencePayload, "artifact_paths")
	if artifactPaths["agent_action_bom_json"] != filepath.Join(outputDir, "reports", "agent-action-bom-customer-redacted.json") {
		t.Fatalf("expected preview to point to canonical customer-redacted BOM, got %v", artifactPaths)
	}
	evidenceTopItem := requireObjectItem(t, requireArrayFromObject(t, evidenceBOM, "items")[0])
	if afterTopItem["proof_coverage"] != evidenceTopItem["proof_coverage"] {
		t.Fatalf("expected report/evidence top BOM proof_coverage to agree, report=%v evidence=%v", afterTopItem["proof_coverage"], evidenceTopItem["proof_coverage"])
	}
	if _, err := os.Stat(filepath.Join(outputDir, "reports", "agent-action-bom.json")); err != nil {
		t.Fatalf("expected BOM report artifact in evidence bundle: %v", err)
	}

	focusedReport := runJSONOK(t, "report", "--state", afterState, "--template", "agent-action-bom", "--share-profile", "internal", "--focus-path", afterTopItem["path_id"].(string), "--json")
	focusedBOM := requireObject(t, focusedReport, "agent_action_bom")
	focusedPrimaryView := requireObject(t, requireObject(t, focusedBOM, "summary"), "primary_view")
	if focusedPrimaryView["path_id"] != afterTopItem["path_id"] || focusedPrimaryView["selection_reason"] != "explicit_focus_path" {
		t.Fatalf("expected explicit focus primary view, got %v", focusedPrimaryView)
	}
	focusedEvidencePath := filepath.Join(t.TempDir(), "focused-agent-action-bom-evidence.json")
	runJSONOK(
		t,
		"report",
		"--state", afterState,
		"--template", "agent-action-bom",
		"--share-profile", "internal",
		"--focus-path", afterTopItem["path_id"].(string),
		"--evidence-json",
		"--evidence-json-path", focusedEvidencePath,
		"--json",
	)
	focusedEvidenceBundle := loadAcceptanceJSONFile(t, focusedEvidencePath)
	focusedEvidenceBOM := requireObject(t, focusedEvidenceBundle, "agent_action_bom")
	focusedEvidenceItems := requireArrayFromObject(t, focusedEvidenceBOM, "items")
	if len(focusedEvidenceItems) != 1 {
		t.Fatalf("expected focused evidence bundle to keep one BOM item, got %v", focusedEvidenceItems)
	}
	if requireObjectItem(t, focusedEvidenceItems[0])["path_id"] != afterTopItem["path_id"] {
		t.Fatalf("expected focused evidence bundle to keep the selected path, got %v", focusedEvidenceItems)
	}
	if _, ok := focusedEvidenceBundle["control_path_graph"]; ok {
		t.Fatalf("expected focused evidence bundle to omit full control graph export, got %v", focusedEvidenceBundle["control_path_graph"])
	}
}

func containsArrayValue(values []any, want string) bool {
	for _, value := range values {
		if text, ok := value.(string); ok && text == want {
			return true
		}
	}
	return false
}
