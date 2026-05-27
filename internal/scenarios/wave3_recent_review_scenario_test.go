//go:build scenario

package scenarios

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScenarioWave3RecentReviewUsesLocalSidecars(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "agent-action-bom-demo", "after", "repos")
	statePath := filepath.Join(t.TempDir(), "wave3-state.json")

	scanPayload := runScenarioCommandJSON(t, []string{"scan", "--path", scanRoot, "--state", statePath, "--json"})
	actionPaths := requireScenarioArrayFromObject(t, scanPayload, "action_paths")
	firstPath := requireScenarioMap(t, actionPaths[0])
	pathID := firstPath["path_id"].(string)

	packetPath := filepath.Join(t.TempDir(), "packets.json")
	packetPayload := `{
  "schema_version": "v1",
  "generated_at": "2026-05-26T15:00:00Z",
  "packets": [
    {
      "packet_id": "pkt-108",
      "source": "review_export",
      "repo": "acme/demo-app",
      "workflow": ".github/workflows/release.yml",
      "path_id": "` + pathID + `",
      "pull_request_ref": "pr/108",
      "observed_at": "2026-05-26T14:59:00Z",
      "result": "partial",
      "missing_evidence_state": "partial",
      "missing_evidence": ["branch_protection_missing"],
      "proof_refs": ["proof://release"]
    }
  ]
}`
	if err := os.WriteFile(packetPath, []byte(packetPayload), 0o600); err != nil {
		t.Fatalf("write packet input: %v", err)
	}
	runScenarioCommandJSON(t, []string{"ingest", "--state", statePath, "--input", packetPath, "--json"})
	reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "agent-action-bom", "--recent-pr-review", "--review-ids", "pr/108", "--json"})

	evidencePackets := requireScenarioObject(t, reportPayload, "evidence_packets")
	if evidencePackets["matched_packets"] != float64(1) {
		t.Fatalf("expected matched evidence packet, got %v", evidencePackets)
	}
	recentReview := requireScenarioObject(t, reportPayload, "recent_pr_review")
	ranked := requireScenarioArrayFromObject(t, recentReview, "ranked")
	if len(ranked) == 0 {
		t.Fatalf("expected ranked recent review items, got %v", recentReview)
	}
}
