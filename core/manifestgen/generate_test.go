package manifestgen

import (
	"testing"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestGenerateUnderReviewFromSnapshotIdentities(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	snapshot := state.Snapshot{
		Identities: []manifest.IdentityRecord{
			{
				AgentID:       "wrkr:mcp-aa:acme",
				ToolID:        "mcp-aa",
				ToolType:      "mcp",
				Org:           "acme",
				Repo:          "acme/backend",
				Location:      ".mcp.json",
				Status:        "active",
				ApprovalState: "valid",
				Approval: manifest.Approval{
					Approver: "@maria",
					Scope:    "read-only",
				},
				FirstSeen: "2026-01-01T00:00:00Z",
				LastSeen:  "2026-02-20T00:00:00Z",
				Present:   true,
			},
		},
	}

	generated, err := GenerateUnderReview(snapshot, now)
	if err != nil {
		t.Fatalf("generate under-review manifest: %v", err)
	}
	if len(generated.Identities) != 1 {
		t.Fatalf("expected one identity, got %d", len(generated.Identities))
	}
	record := generated.Identities[0]
	if record.Status != "under_review" {
		t.Fatalf("expected under_review status, got %q", record.Status)
	}
	if record.ApprovalState != "missing" {
		t.Fatalf("expected missing approval state, got %q", record.ApprovalState)
	}
	if record.Approval.Approver != "" || record.Approval.Scope != "" {
		t.Fatalf("expected approval to be cleared, got %+v", record.Approval)
	}
	if record.LastSeen != "2026-02-21T12:00:00Z" {
		t.Fatalf("unexpected last_seen: %q", record.LastSeen)
	}
}

func TestGenerateUnderReviewFallsBackToInventory(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	snapshot := state.Snapshot{
		Inventory: &agginventory.Inventory{
			Tools: []agginventory.Tool{
				{
					ToolID:        "cursor-aa",
					AgentID:       "wrkr:cursor-aa:acme",
					ToolType:      "cursor",
					Org:           "acme",
					DataClass:     "code",
					EndpointClass: "workspace",
					AutonomyLevel: "interactive",
					RiskScore:     6.5,
					Locations: []agginventory.ToolLocation{
						{Repo: "acme/backend", Location: ".cursorrules"},
					},
				},
			},
		},
	}

	generated, err := GenerateUnderReview(snapshot, now)
	if err != nil {
		t.Fatalf("generate under-review manifest: %v", err)
	}
	if len(generated.Identities) != 1 {
		t.Fatalf("expected one identity, got %d", len(generated.Identities))
	}
	record := generated.Identities[0]
	if record.AgentID != "wrkr:cursor-aa:acme" {
		t.Fatalf("unexpected agent id %q", record.AgentID)
	}
	if record.Status != "under_review" {
		t.Fatalf("expected under_review status, got %q", record.Status)
	}
}

func TestGenerateUnderReviewRequiresIdentityData(t *testing.T) {
	t.Parallel()

	if _, err := GenerateUnderReview(state.Snapshot{}, time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected error when state has no identities or inventory")
	}
}
