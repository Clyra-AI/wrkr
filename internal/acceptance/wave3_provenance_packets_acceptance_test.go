package acceptance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWave3AcceptanceEvidencePacketsAndRecentReview(t *testing.T) {
	paths := loadAcceptancePaths(t)

	statePath := filepath.Join(t.TempDir(), "wave3-state.json")
	scanRoot := filepath.Join(paths.repoRoot, "scenarios", "wrkr", "agent-action-bom-demo", "after", "repos")
	scanPayload := runJSONOK(t, "scan", "--path", scanRoot, "--state", statePath, "--json")
	actionPaths := requireArray(t, scanPayload, "action_paths")
	firstPath := requireObjectItem(t, actionPaths[0])
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
      "proof_refs": ["proof://release"],
      "evidence_refs": ["evidence://fake/provider/pr-108.json"]
    }
  ]
}`
	if err := os.WriteFile(packetPath, []byte(packetPayload), 0o600); err != nil {
		t.Fatalf("write packet input: %v", err)
	}
	runJSONOK(t, "ingest", "--state", statePath, "--input", packetPath, "--json")

	reportPayload := runJSONOK(t, "report", "--state", statePath, "--template", "agent-action-bom", "--recent-pr-review", "--review-ids", "pr/108", "--json")
	evidencePackets := requireObject(t, reportPayload, "evidence_packets")
	if evidencePackets["matched_packets"] != float64(1) {
		t.Fatalf("expected matched evidence packet, got %v", evidencePackets)
	}
	reportSummary := requireObject(t, reportPayload, "summary")
	if _, ok := requireObject(t, reportSummary, "evidence_packets")["matched_packets"]; !ok {
		t.Fatalf("expected nested summary evidence_packets, got %v", reportSummary)
	}
	recentReview := requireObject(t, reportPayload, "recent_pr_review")
	ranked := requireArrayFromObject(t, recentReview, "ranked")
	foundFocusedPath := false
	for _, item := range ranked {
		rankedItem := requireObjectItem(t, item)
		if rankedItem["reference"] == "pr/108" && rankedItem["focus_bom_path_id"] == pathID {
			foundFocusedPath = true
			break
		}
	}
	if !foundFocusedPath {
		t.Fatalf("expected recent review to include correlated path %s for pr/108, got %v", pathID, ranked)
	}
	bom := requireObject(t, reportPayload, "agent_action_bom")
	items := requireArrayFromObject(t, bom, "items")
	firstItem := requireObjectItem(t, items[0])
	if firstItem["evidence_packet_status"] != "matched" || firstItem["evidence_packet_result"] != "partial" {
		t.Fatalf("expected evidence packet projection on BOM item, got %v", firstItem)
	}
}
