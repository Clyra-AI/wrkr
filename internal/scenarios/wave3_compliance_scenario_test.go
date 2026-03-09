//go:build scenario

package scenarios

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestScenarioComplianceSummaryStableAcrossScanAndReport(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	scanPayload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
	reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--json"})

	if !reflect.DeepEqual(scanPayload["compliance_summary"], reportPayload["compliance_summary"]) {
		t.Fatalf("expected scan/report compliance summaries to match\nscan=%v\nreport=%v", scanPayload["compliance_summary"], reportPayload["compliance_summary"])
	}
}
