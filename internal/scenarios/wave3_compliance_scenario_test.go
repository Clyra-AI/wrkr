//go:build scenario

package scenarios

import (
	"bytes"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
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

func TestScenarioComplianceExplainClarifiesEvidenceState(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	scanExplain := runScenarioCommandText(t, []string{"scan", "--path", scanPath, "--state", statePath, "--explain"})
	reportExplain := runScenarioCommandText(t, []string{"report", "--state", statePath, "--explain"})

	for _, output := range []string{scanExplain, reportExplain} {
		if !strings.Contains(output, "bundled framework mappings are available; current findings do not map to bundled compliance controls yet") {
			t.Fatalf("expected evidence-state clarification in explain output, got %q", output)
		}
		if !strings.Contains(output, "coverage still reflects only controls evidenced in the current scan state; remediate gaps, rescan, and regenerate report/evidence artifacts") {
			t.Fatalf("expected deterministic next-action guidance in explain output, got %q", output)
		}
	}
}

func runScenarioCommandText(t *testing.T, args []string) string {
	t.Helper()

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run(args, &out, &errOut); code != 0 {
		t.Fatalf("command failed: %v code=%d stderr=%s", args, code, errOut.String())
	}
	return out.String()
}
