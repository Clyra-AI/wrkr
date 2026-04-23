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

func TestReconcileLegacyAgentIDMigratesWithoutLosingState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	prev := manifest.Manifest{Identities: []manifest.IdentityRecord{{
		AgentID:       "wrkr:codex-legacy:acme",
		ToolID:        "codex-legacy",
		ToolType:      "codex",
		Org:           "acme",
		Repo:          "acme/repo",
		Location:      "AGENTS.md",
		Status:        identity.StateApproved,
		ApprovalState: "valid",
		Approval: manifest.Approval{
			Approver: "@maria",
			Scope:    "repo",
			Expires:  now.Add(24 * time.Hour).Format(time.RFC3339),
		},
		Present: true,
	}}}

	next, transitions := Reconcile(prev, []ObservedTool{{
		AgentID:       "wrkr:codex-inst-123:acme",
		LegacyAgentID: "wrkr:codex-legacy:acme",
		ToolID:        "codex-inst-123",
		ToolType:      "codex",
		Org:           "acme",
		Repo:          "acme/repo",
		Location:      "AGENTS.md",
	}}, now)

	if len(next.Identities) != 1 {
		t.Fatalf("expected one migrated identity, got %d", len(next.Identities))
	}
	if next.Identities[0].AgentID != "wrkr:codex-inst-123:acme" {
		t.Fatalf("expected migrated agent id, got %+v", next.Identities[0])
	}
	if next.Identities[0].Status != identity.StateActive {
		t.Fatalf("expected approved state semantics to continue as active, got %s", next.Identities[0].Status)
	}
	if len(transitions) == 0 || transitions[0].Trigger != "identity_migrated" {
		t.Fatalf("expected identity_migrated transition, got %+v", transitions)
	}
	if transitions[0].PreviousState != identity.StateApproved {
		t.Fatalf("expected previous approved state to be preserved, got %+v", transitions[0])
	}
}

func TestReconcileLegacyAgentIDMigrationDoesNotFanOutApprovalState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	prev := manifest.Manifest{Identities: []manifest.IdentityRecord{{
		AgentID:       "wrkr:codex-legacy:acme",
		ToolID:        "codex-legacy",
		ToolType:      "codex",
		Org:           "acme",
		Repo:          "acme/repo",
		Location:      "AGENTS.md",
		Status:        identity.StateApproved,
		ApprovalState: "valid",
		Approval: manifest.Approval{
			Approver: "@maria",
			Scope:    "repo",
			Expires:  now.Add(24 * time.Hour).Format(time.RFC3339),
		},
		Present: true,
	}}}

	next, transitions := Reconcile(prev, []ObservedTool{
		{
			AgentID:       "wrkr:codex-inst-100:acme",
			LegacyAgentID: "wrkr:codex-legacy:acme",
			ToolID:        "codex-inst-100",
			ToolType:      "codex",
			Org:           "acme",
			Repo:          "acme/repo",
			Location:      "AGENTS.md",
		},
		{
			AgentID:       "wrkr:codex-inst-200:acme",
			LegacyAgentID: "wrkr:codex-legacy:acme",
			ToolID:        "codex-inst-200",
			ToolType:      "codex",
			Org:           "acme",
			Repo:          "acme/repo",
			Location:      "AGENTS.md",
		},
	}, now)

	if len(next.Identities) != 2 {
		t.Fatalf("expected two successor identities, got %d", len(next.Identities))
	}

	var migrated, fresh *manifest.IdentityRecord
	for i := range next.Identities {
		switch next.Identities[i].AgentID {
		case "wrkr:codex-inst-100:acme":
			migrated = &next.Identities[i]
		case "wrkr:codex-inst-200:acme":
			fresh = &next.Identities[i]
		}
	}
	if migrated == nil || fresh == nil {
		t.Fatalf("expected deterministic successors, got %+v", next.Identities)
	}
	if migrated.Status != identity.StateActive {
		t.Fatalf("expected first successor to inherit approved semantics, got %+v", *migrated)
	}
	if fresh.Status != identity.StateUnderReview || fresh.ApprovalState != "missing" {
		t.Fatalf("expected additional successor to require new review, got %+v", *fresh)
	}

	var migratedTrigger, freshTrigger string
	for _, transition := range transitions {
		switch transition.AgentID {
		case "wrkr:codex-inst-100:acme":
			migratedTrigger = transition.Trigger
		case "wrkr:codex-inst-200:acme":
			freshTrigger = transition.Trigger
		}
	}
	if migratedTrigger != "identity_migrated" {
		t.Fatalf("expected identity_migrated for first successor, got %+v", transitions)
	}
	if freshTrigger != "first_seen" {
		t.Fatalf("expected first_seen for additional successor, got %+v", transitions)
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

func TestParseExpiryDaySuffix(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	expires, err := ParseExpiry("90d", now)
	if err != nil {
		t.Fatalf("parse expiry: %v", err)
	}
	if expires.Sub(now) != 90*24*time.Hour {
		t.Fatalf("expected 90d expiry, got %s", expires.Sub(now))
	}
}

func TestApplyManualStateNonApprovedStatesAlwaysRevokeApprovalStatus(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	baseManifest := manifest.Manifest{
		Version: manifest.Version,
		Identities: []manifest.IdentityRecord{
			{
				AgentID:       "wrkr:mcp-1:acme",
				ToolID:        "mcp-1",
				Status:        identity.StateActive,
				ApprovalState: "valid",
				Approval: manifest.Approval{
					Approver: "@maria",
					Scope:    "read-only",
					Approved: now.Add(-time.Hour).Format(time.RFC3339),
					Expires:  now.Add(24 * time.Hour).Format(time.RFC3339),
				},
				Present: true,
			},
		},
	}

	for _, stateName := range []string{identity.StateUnderReview, identity.StateDeprecated, identity.StateRevoked} {
		stateName := stateName
		t.Run(stateName, func(t *testing.T) {
			t.Parallel()

			// Clone manifest identities so parallel subtests do not share slice backing storage.
			testManifest := baseManifest
			testManifest.Identities = append([]manifest.IdentityRecord(nil), baseManifest.Identities...)
			next, transition, err := ApplyManualState(testManifest, "wrkr:mcp-1:acme", stateName, "", "", "", time.Time{}, now)
			if err != nil {
				t.Fatalf("apply manual state: %v", err)
			}
			if next.Identities[0].Status != stateName {
				t.Fatalf("expected status %s, got %s", stateName, next.Identities[0].Status)
			}
			if next.Identities[0].ApprovalState != "revoked" {
				t.Fatalf("expected approval_state=revoked, got %s", next.Identities[0].ApprovalState)
			}
			if next.Identities[0].Approval != (manifest.Approval{}) {
				t.Fatalf("expected approval metadata to be cleared, got %+v", next.Identities[0].Approval)
			}
			if transition.NewState != stateName {
				t.Fatalf("unexpected transition state: %+v", transition)
			}
			reconciled, _ := Reconcile(next, []ObservedTool{{
				AgentID:  "wrkr:mcp-1:acme",
				ToolID:   "mcp-1",
				ToolType: "mcp",
				Org:      "acme",
				Repo:     "acme/repo",
				Location: ".mcp.json",
			}}, now.Add(time.Minute))
			if reconciled.Identities[0].ApprovalState == "valid" {
				t.Fatalf("expected non-approved state to stay non-valid after reconcile, got %+v", reconciled.Identities[0])
			}
		})
	}
}
