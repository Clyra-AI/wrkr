package ingest

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestEvidencePacketNormalizeStableOrder(t *testing.T) {
	t.Parallel()

	bundle := EvidencePacketBundle{
		SchemaVersion: EvidencePacketSchemaVersion,
		GeneratedAt:   "2026-05-26T15:00:00Z",
		Packets: []EvidencePacket{
			{
				Source:          "review_export",
				Repo:            "acme/payments",
				Workflow:        ".github/workflows/release.yml",
				PullRequestRef:  "pr/42",
				ObservedAt:      "2026-05-26T14:59:00Z",
				FilesTouched:    []string{"AGENTS.md", ".github/workflows/release.yml"},
				Reviewers:       []string{"platform-bot"},
				Approvals:       []string{"sre-owner"},
				Result:          "complete",
				MissingEvidence: []string{},
				ProofRefs:       []string{"proof://release"},
				GraphNodeRefs:   []string{"node-2", "node-1"},
			},
			{
				Source:          "review_export",
				Repo:            "acme/payments",
				Workflow:        ".github/workflows/build.yml",
				PullRequestRef:  "pr/41",
				ObservedAt:      "2026-05-26T14:00:00Z",
				MissingEvidence: []string{"deployment_missing"},
			},
		},
	}

	first, err := NormalizeEvidencePacketBundle(bundle)
	if err != nil {
		t.Fatalf("normalize first bundle: %v", err)
	}
	second, err := NormalizeEvidencePacketBundle(bundle)
	if err != nil {
		t.Fatalf("normalize second bundle: %v", err)
	}

	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatalf("marshal first bundle: %v", err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil {
		t.Fatalf("marshal second bundle: %v", err)
	}
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("expected stable normalization\nfirst=%s\nsecond=%s", firstJSON, secondJSON)
	}
	if len(first.Packets) != 2 || first.Packets[0].PacketID == "" || first.Packets[1].PacketID == "" {
		t.Fatalf("expected generated packet ids, got %+v", first.Packets)
	}
}

func TestEvidencePacketsCorrelateByPullRequestRefAndWorkflow(t *testing.T) {
	t.Parallel()

	summary := CorrelateEvidencePackets(state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:   "apc-release-1",
				AgentID:  "wrkr:workflow-release:acme",
				Repo:     "acme/payments",
				Location: ".github/workflows/release.yml",
				IntroducedBy: &attribution.Result{
					Reference: "pr/42",
					PRNumber:  42,
					Provenance: &attribution.Provenance{
						Reference:    "pr/42",
						ChangedFiles: []string{".github/workflows/release.yml"},
					},
				},
				PolicyEvidenceRefs: []string{"proof://release"},
			}},
		},
	}, "agentic-evidence-packets.json", EvidencePacketBundle{
		SchemaVersion: EvidencePacketSchemaVersion,
		GeneratedAt:   time.Date(2026, 5, 26, 15, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Packets: []EvidencePacket{{
			Source:          "review_export",
			Repo:            "acme/payments",
			Workflow:        ".github/workflows/release.yml",
			PullRequestRef:  "pr/42",
			ProofRefs:       []string{"proof://release"},
			ObservedAt:      time.Date(2026, 5, 26, 14, 59, 0, 0, time.UTC).Format(time.RFC3339),
			Result:          "complete",
			MissingEvidence: []string{},
		}},
	})
	if summary.MatchedPackets != 1 || len(summary.Correlations) != 1 {
		t.Fatalf("expected one matched packet, got %+v", summary)
	}
	if summary.Correlations[0].PathID != "apc-release-1" || summary.Correlations[0].Status != CorrelationStatusMatched {
		t.Fatalf("expected packet correlation by path, got %+v", summary.Correlations[0])
	}
}

func TestEvidencePacketsRejectSecretLikeValues(t *testing.T) {
	t.Parallel()

	_, err := NormalizeEvidencePacketBundle(EvidencePacketBundle{
		SchemaVersion: EvidencePacketSchemaVersion,
		GeneratedAt:   "2026-05-26T15:00:00Z",
		Packets: []EvidencePacket{{
			Source:       "review_export",
			Repo:         "acme/payments",
			Workflow:     ".github/workflows/release.yml",
			ObservedAt:   "2026-05-26T14:59:00Z",
			EvidenceRefs: []string{"ghp_super_secret_token_value"},
		}},
	})
	if err == nil {
		t.Fatal("expected secret-like value rejection")
	}
	if !strings.Contains(err.Error(), "secret-like") {
		t.Fatalf("expected secret-like rejection error, got %v", err)
	}
}
