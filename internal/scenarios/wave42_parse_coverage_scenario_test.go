//go:build scenario

package scenarios

import (
	"path/filepath"
	"testing"
)

func TestScenarioWave42WebMCPReducedCoverageStaysQualified(t *testing.T) {
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "webmcp-declarations", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
	scanQuality := requireScenarioObject(t, payload, "scan_quality")
	compact := requireScenarioObject(t, scanQuality, "compact_summary")
	if compact["coverage_confidence"] != "reduced" {
		t.Fatalf("expected reduced coverage confidence for parse-limited WebMCP scenario, got %v", compact)
	}

	claims := requireScenarioArrayFromObject(t, scanQuality, "absence_claims")
	foundQualifiedClaim := false
	for _, raw := range claims {
		claim := requireScenarioMap(t, raw)
		if claim["repo"] == "parse-error-repo" && claim["status"] == "candidate_parse_failed" {
			foundQualifiedClaim = true
			break
		}
	}
	if !foundQualifiedClaim {
		t.Fatalf("expected candidate_parse_failed absence claim for parse-error-repo, got %v", claims)
	}

	topFindings := requireScenarioArrayFromObject(t, payload, "top_findings")
	for _, raw := range topFindings {
		finding := requireScenarioMap(t, raw)
		if finding["finding_type"] == "parse_error" {
			t.Fatalf("expected parse diagnostics to stay out of ranked top findings, got %v", topFindings)
		}
	}
}
