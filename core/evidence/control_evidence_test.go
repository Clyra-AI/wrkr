package evidence

import (
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestControlEvidenceRecordVerifiesInProofChain(t *testing.T) {
	toolID := identity.ToolID("codex", "AGENTS.md")
	agentID := identity.AgentID(toolID, "acme")
	snapshot := controlEvidenceSnapshot(agentID, toolID, controlbacklog.Item{
		ID:                "cb-approve",
		Repo:              "acme/repo",
		Path:              "AGENTS.md",
		RecommendedAction: controlbacklog.ActionApprove,
		ClosureCriteria:   "Record owner-approved, time-bounded approval evidence and rescan.",
		GovernanceControls: []agginventory.GovernanceControlMapping{
			{Control: agginventory.GovernanceControlApproval, Status: agginventory.ControlStatusGap},
		},
	})
	chain := proof.NewChain("wrkr-proof")
	chain.Records = append(chain.Records, proof.Record{
		RecordID:   "rec-approval",
		RecordType: "approval",
		AgentID:    agentID,
		Timestamp:  time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC),
		Event: map[string]any{
			"event_type":     "approval_recorded",
			"owner":          "platform-security",
			"review_cadence": "90d",
			"control_id":     agginventory.GovernanceControlApproval,
		},
	})

	status := BuildControlEvidence(snapshot, chain)
	if len(status) != 1 {
		t.Fatalf("expected one control evidence status, got %+v", status)
	}
	if status[0].Status != "satisfied" {
		t.Fatalf("expected satisfied proof status, got %+v", status[0])
	}
	for _, required := range []string{
		agginventory.GovernanceControlApproval,
		agginventory.GovernanceControlOwnerAssigned,
		agginventory.GovernanceControlReviewCadence,
	} {
		if !containsString(status[0].ExistingProof, required) {
			t.Fatalf("expected %s proof, got %+v", required, status[0])
		}
	}
}

func TestBacklogClosureCriteriaMapsToProofRequirements(t *testing.T) {
	toolID := identity.ToolID("workflow", ".github/workflows/deploy.yml")
	agentID := identity.AgentID(toolID, "acme")
	snapshot := controlEvidenceSnapshot(agentID, toolID, controlbacklog.Item{
		ID:                "cb-secret-write",
		Repo:              "acme/repo",
		Path:              ".github/workflows/deploy.yml",
		RecommendedAction: controlbacklog.ActionAttachEvidence,
		ClosureCriteria:   "Attach proof for secret rotation, least privilege, and deployment gate evidence.",
		WritePathClasses:  []string{agginventory.WritePathRepoWrite, agginventory.WritePathDeployWrite},
		SecretSignalTypes: []string{"secret_rotation_evidence_missing"},
		GovernanceControls: []agginventory.GovernanceControlMapping{
			{Control: agginventory.GovernanceControlRotation, Status: agginventory.ControlStatusGap},
		},
	})
	chain := proof.NewChain("wrkr-proof")
	chain.Records = append(chain.Records, proof.Record{
		RecordID:   "rec-evidence",
		RecordType: "evidence",
		AgentID:    agentID,
		Event: map[string]any{
			"event_type":   "evidence_attached",
			"evidence_url": "https://tickets.example/SEC-123",
			"control_id":   agginventory.GovernanceControlRotation,
		},
	})

	status := BuildControlEvidence(snapshot, chain)
	if len(status) != 1 {
		t.Fatalf("expected one control evidence status, got %+v", status)
	}
	for _, required := range []string{
		agginventory.GovernanceControlLeastPrivilege,
		agginventory.GovernanceControlDeploymentGate,
		agginventory.GovernanceControlRotation,
		agginventory.GovernanceControlProof,
	} {
		if !containsString(status[0].MissingProof, required) {
			t.Fatalf("expected missing %s proof, got %+v", required, status[0])
		}
	}
	if !containsString(status[0].ExistingProof, "evidence_attached") {
		t.Fatalf("expected attached evidence proof, got %+v", status[0])
	}
}

func controlEvidenceSnapshot(agentID string, toolID string, item controlbacklog.Item) state.Snapshot {
	return state.Snapshot{
		Inventory: &agginventory.Inventory{
			Tools: []agginventory.Tool{
				{
					AgentID:   agentID,
					ToolID:    toolID,
					Org:       "acme",
					Repos:     []string{"acme/repo"},
					Locations: []agginventory.ToolLocation{{Repo: item.Repo, Location: item.Path}},
				},
			},
		},
		ControlBacklog: &controlbacklog.Backlog{Items: []controlbacklog.Item{item}},
		Identities: []manifest.IdentityRecord{
			{AgentID: agentID, ToolID: toolID, Org: "acme", Repo: item.Repo, Location: item.Path, Present: true},
		},
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
