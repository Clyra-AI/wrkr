package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestScanJSONEmitsComplianceSummaryAdditively(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("scan failed: %d %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	summary, ok := payload["compliance_summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected compliance_summary object, got %T", payload["compliance_summary"])
	}
	frameworks, ok := summary["frameworks"].([]any)
	if !ok || len(frameworks) == 0 {
		t.Fatalf("expected non-empty compliance_summary.frameworks, got %v", summary["frameworks"])
	}
	first, ok := frameworks[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected first framework type %T", frameworks[0])
	}
	for _, key := range []string{"framework_id", "control_count", "covered_count", "coverage_percent", "mapped_finding_count", "controls"} {
		if _, present := first[key]; !present {
			t.Fatalf("framework rollup missing %s: %v", key, first)
		}
	}
}

func TestReportJSONEmitsDeterministicControlRollups(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	runReport := func() map[string]any {
		t.Helper()
		var out bytes.Buffer
		var errOut bytes.Buffer
		if code := Run([]string{"report", "--state", statePath, "--json"}, &out, &errOut); code != 0 {
			t.Fatalf("report failed: %d %s", code, errOut.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
			t.Fatalf("parse report payload: %v", err)
		}
		return payload
	}

	first := runReport()
	second := runReport()
	if !reflect.DeepEqual(first["compliance_summary"], second["compliance_summary"]) {
		t.Fatalf("report compliance_summary drifted\nfirst=%v\nsecond=%v", first["compliance_summary"], second["compliance_summary"])
	}
}

func TestScanAndReportExplainIncludeComplianceRollupLines(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	var scanExplain bytes.Buffer
	var scanExplainErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--explain"}, &scanExplain, &scanExplainErr); code != 0 {
		t.Fatalf("scan --explain failed: %d %s", code, scanExplainErr.String())
	}
	if !strings.Contains(scanExplain.String(), "compliance: ") {
		t.Fatalf("expected scan explain output to include compliance lines, got %q", scanExplain.String())
	}
	if !strings.Contains(scanExplain.String(), "bundled framework mappings are available; current findings do not map to bundled compliance controls yet") {
		t.Fatalf("expected scan explain output to clarify sparse evidence state, got %q", scanExplain.String())
	}
	if strings.Contains(scanExplain.String(), "no findings currently map to bundled compliance controls") {
		t.Fatalf("expected scan explain output to stop implying missing framework support, got %q", scanExplain.String())
	}

	var reportExplain bytes.Buffer
	var reportExplainErr bytes.Buffer
	if code := Run([]string{"report", "--state", statePath, "--explain"}, &reportExplain, &reportExplainErr); code != 0 {
		t.Fatalf("report --explain failed: %d %s", code, reportExplainErr.String())
	}
	if !strings.Contains(reportExplain.String(), "compliance: ") {
		t.Fatalf("expected report explain output to include compliance lines, got %q", reportExplain.String())
	}
	if !strings.Contains(reportExplain.String(), "coverage still reflects only controls evidenced in the current scan state; remediate gaps, rescan, and regenerate report/evidence artifacts") {
		t.Fatalf("expected report explain output to include next-action guidance, got %q", reportExplain.String())
	}
}
