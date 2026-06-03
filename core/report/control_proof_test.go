package report

import (
	"testing"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestBuildControlProofStatusTreatsAcceptedRiskAsApprovalProof(t *testing.T) {
	t.Parallel()

	for _, eventType := range []string{"risk_accepted", "accepted_risk"} {
		t.Run(eventType, func(t *testing.T) {
			t.Parallel()

			snapshot := state.Snapshot{
				RiskReport: &risk.Report{
					ActionPaths: []risk.ActionPath{{
						PathID:   "apc-risk-accepted",
						AgentID:  "wrkr:ci:acme",
						Org:      "acme",
						Repo:     "demo-app",
						ToolType: "ci_agent",
						Location: ".github/workflows/release.yml",
					}},
				},
				ControlBacklog: &controlbacklog.Backlog{Items: []controlbacklog.Item{{
					ID:                 "cb-risk-accepted",
					Repo:               "demo-app",
					Path:               ".github/workflows/release.yml",
					RecommendedAction:  controlbacklog.ActionApprove,
					ClosureCriteria:    "Record owner-approved, time-bounded approval evidence and rescan.",
					LinkedActionPathID: "apc-risk-accepted",
					GovernanceControls: []agginventory.GovernanceControlMapping{
						{Control: agginventory.GovernanceControlApproval, Status: agginventory.ControlStatusGap},
					},
				}}},
			}
			chain := proof.NewChain("wrkr-proof")
			chain.Records = append(chain.Records, proof.Record{
				RecordID:   "rec-risk-accepted",
				RecordType: "approval",
				AgentID:    "wrkr:ci:acme",
				Event: map[string]any{
					"event_type":     eventType,
					"owner":          "platform-security",
					"review_cadence": "90d",
					"control_id":     agginventory.GovernanceControlApproval,
				},
			})

			statuses := BuildControlProofStatus(snapshot, chain)
			if len(statuses) != 1 {
				t.Fatalf("expected one control proof status, got %+v", statuses)
			}
			status := statuses[0]
			if status.Status != "satisfied" {
				t.Fatalf("expected accepted-risk proof to satisfy approval requirement, got %+v", status)
			}
			if !containsControlProofValue(status.ExistingProof, agginventory.GovernanceControlApproval) {
				t.Fatalf("expected approval proof to be recorded, got %+v", status)
			}
			if containsControlProofValue(status.MissingProof, agginventory.GovernanceControlApproval) {
				t.Fatalf("expected approval proof not to be missing, got %+v", status)
			}
			if len(status.RecordIDs) != 1 || status.RecordIDs[0] != "rec-risk-accepted" {
				t.Fatalf("expected record id to be preserved, got %+v", status.RecordIDs)
			}
		})
	}
}

func containsControlProofValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
