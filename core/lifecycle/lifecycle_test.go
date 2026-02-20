package lifecycle

import (
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/manifest"
)

func TestReconcileDerivesUnderReviewWhenApprovalExpired(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	prev := manifest.Manifest{Identities: []manifest.IdentityRecord{{
		AgentID: "wrkr:mcp-1:acme",
		ToolID:  "mcp-1",
		Status:  identity.StateActive,
		Approval: manifest.Approval{
			Approver: "@maria",
			Scope:    "read-only",
			Expires:  now.Add(-time.Hour).Format(time.RFC3339),
		},
		Present: true,
	}}}

	next, transitions := Reconcile(prev, []ObservedTool{{AgentID: "wrkr:mcp-1:acme", ToolID: "mcp-1", ToolType: "mcp", Org: "acme", Repo: "acme/repo", Location: ".mcp.json"}}, now)
	if next.Identities[0].Status != identity.StateUnderReview {
		t.Fatalf("expected under_review, got %s", next.Identities[0].Status)
	}
	if len(transitions) == 0 {
		t.Fatal("expected lifecycle transition when approval expiry changes state")
	}
	if transitions[0].Trigger != "state_changed" {
		t.Fatalf("expected state_changed trigger, got %s", transitions[0].Trigger)
	}
	if transitions[0].PreviousState != identity.StateActive || transitions[0].NewState != identity.StateUnderReview {
		t.Fatalf("unexpected state transition %+v", transitions[0])
	}
}

func TestReconcileEmitsRemovedAndReappearedTriggers(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	prev := manifest.Manifest{Identities: []manifest.IdentityRecord{{AgentID: "wrkr:mcp-1:acme", ToolID: "mcp-1", Status: identity.StateRevoked, Present: false}}}
	next, transitions := Reconcile(prev, []ObservedTool{{AgentID: "wrkr:mcp-1:acme", ToolID: "mcp-1", ToolType: "mcp", Org: "acme", Repo: "acme/repo", Location: ".mcp.json"}}, now)
	if len(next.Identities) != 1 {
		t.Fatalf("expected 1 identity, got %d", len(next.Identities))
	}
	if len(transitions) == 0 || transitions[0].Trigger != "reappeared" {
		t.Fatalf("expected reappeared transition, got %+v", transitions)
	}
}

func TestReconcileEmitsModifiedTriggerForContractFields(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	prev := manifest.Manifest{Identities: []manifest.IdentityRecord{{
		AgentID:       "wrkr:mcp-1:acme",
		ToolID:        "mcp-1",
		Status:        identity.StateUnderReview,
		Present:       true,
		DataClass:     "code",
		EndpointClass: "workspace",
		AutonomyLevel: "interactive",
	}}}
	_, transitions := Reconcile(prev, []ObservedTool{{
		AgentID:       "wrkr:mcp-1:acme",
		ToolID:        "mcp-1",
		ToolType:      "mcp",
		Org:           "acme",
		Repo:          "acme/repo",
		Location:      ".mcp.json",
		DataClass:     "credentials",
		EndpointClass: "network_service",
		AutonomyLevel: "headless_auto",
	}}, now)

	if len(transitions) == 0 || transitions[0].Trigger != "modified" {
		t.Fatalf("expected modified transition, got %+v", transitions)
	}
}

func TestParseExpiryDefault90Days(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	expires, err := ParseExpiry("", now)
	if err != nil {
		t.Fatalf("parse expiry: %v", err)
	}
	if expires.Sub(now) != 90*24*time.Hour {
		t.Fatalf("expected 90d expiry, got %s", expires.Sub(now))
	}
}
