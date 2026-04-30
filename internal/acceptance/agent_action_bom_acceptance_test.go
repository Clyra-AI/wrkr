package acceptance

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestAgentActionBOMAcceptanceStaticToRuntimeEvidence(t *testing.T) {
	paths := loadAcceptancePaths(t)

	beforeState := filepath.Join(t.TempDir(), "before-state.json")
	beforeScanRoot := filepath.Join(paths.repoRoot, "scenarios", "wrkr", "agent-action-bom-demo", "before", "repos")
	beforeScan := runJSONOK(t, "scan", "--path", beforeScanRoot, "--state", beforeState, "--json")
	beforeReport := runJSONOK(t, "report", "--state", beforeState, "--template", "agent-action-bom", "--json")

	beforeActionPaths := requireArray(t, beforeScan, "action_paths")
	beforeTopPath := requireObjectItem(t, beforeActionPaths[0])
	beforeBOM := requireObject(t, beforeReport, "agent_action_bom")
	beforeItems := requireArrayFromObject(t, beforeBOM, "items")
	beforeTopItem := requireObjectItem(t, beforeItems[0])
	if beforeTopItem["policy_status"] != "none" {
		t.Fatalf("expected pre-ingest policy gap, got %v", beforeTopItem["policy_status"])
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
	afterReport := runJSONOK(t, "report", "--state", afterState, "--template", "agent-action-bom", "--json", "--evidence-json", "--evidence-json-path", filepath.Join(t.TempDir(), "agent-action-bom-evidence.json"))

	afterActionPaths := requireArray(t, afterScan, "action_paths")
	afterTopPath := requireObjectItem(t, afterActionPaths[0])
	if beforeTopPath["path_id"] != afterTopPath["path_id"] {
		t.Fatalf("expected stable top path id across before/after fixtures, before=%v after=%v", beforeTopPath["path_id"], afterTopPath["path_id"])
	}
	if afterTopPath["policy_coverage_status"] != "matched" {
		t.Fatalf("expected after scan to show static policy match, got %v", afterTopPath["policy_coverage_status"])
	}

	afterBOM := requireObject(t, afterReport, "agent_action_bom")
	afterItems := requireArrayFromObject(t, afterBOM, "items")
	afterTopItem := requireObjectItem(t, afterItems[0])
	reportRuntimeEvidence := requireObject(t, afterReport, "runtime_evidence")
	reportSummary := requireObject(t, afterReport, "summary")
	if !reflect.DeepEqual(reportRuntimeEvidence, requireObject(t, reportSummary, "runtime_evidence")) {
		t.Fatalf("expected top-level and summary runtime_evidence to match\nreport=%v\nsummary=%v", reportRuntimeEvidence, reportSummary["runtime_evidence"])
	}
	if afterTopItem["path_id"] != beforeTopItem["path_id"] {
		t.Fatalf("expected same BOM item path id across before/after, before=%v after=%v", beforeTopItem["path_id"], afterTopItem["path_id"])
	}
	if afterTopItem["policy_status"] != "runtime_proven" {
		t.Fatalf("expected runtime-proven policy coverage after ingest, got %v", afterTopItem["policy_status"])
	}
	if afterTopItem["runtime_evidence_status"] != "matched" {
		t.Fatalf("expected runtime evidence to correlate after ingest, got %v", afterTopItem["runtime_evidence_status"])
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
	if !reflect.DeepEqual(requireObject(t, afterBOM, "summary"), requireObject(t, evidenceBOM, "summary")) {
		t.Fatalf("expected report/evidence BOM summaries to agree\nreport=%v\nevidence=%v", afterBOM["summary"], evidenceBOM["summary"])
	}
	if afterTopItem["proof_coverage"] != requireObjectItem(t, requireArrayFromObject(t, evidenceBOM, "items")[0])["proof_coverage"] {
		t.Fatalf("expected report/evidence top BOM proof_coverage to agree, report=%v evidence=%v", afterTopItem["proof_coverage"], requireObjectItem(t, requireArrayFromObject(t, evidenceBOM, "items")[0])["proof_coverage"])
	}
	if _, err := os.Stat(filepath.Join(outputDir, "reports", "agent-action-bom.json")); err != nil {
		t.Fatalf("expected BOM report artifact in evidence bundle: %v", err)
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
