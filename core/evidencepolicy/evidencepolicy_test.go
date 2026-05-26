package evidencepolicy

import (
	"testing"
	"time"
)

func TestResolveDecisionVerifiedProviderBeatsCodeowners(t *testing.T) {
	t.Parallel()

	decision := ResolveDecision([]Candidate{
		{
			Field:      FieldOwner,
			Value:      "@acme/platform",
			SourceType: SourceTypeCodeowners,
			Source:     "CODEOWNERS",
		},
		{
			Field:      FieldOwner,
			Value:      "@acme/security",
			SourceType: SourceTypeProviderExport,
			Source:     "github_team_export",
			ObservedAt: "2026-05-25T17:00:00Z",
			ValidUntil: "2026-05-26T17:00:00Z",
		},
	}, time.Date(2026, 5, 25, 17, 30, 30, 0, time.UTC))

	if decision.SelectedValue != "@acme/security" {
		t.Fatalf("expected provider export to win, got %+v", decision)
	}
	if decision.SelectedSourceType != SourceTypeProviderExport {
		t.Fatalf("expected provider export source type, got %+v", decision)
	}
	if decision.ConflictState != ConflictStateResolved {
		t.Fatalf("expected resolved conflict state, got %+v", decision)
	}
	if len(decision.RejectedCandidates) != 1 || decision.RejectedCandidates[0].Value != "@acme/platform" {
		t.Fatalf("expected rejected lower-precedence candidate, got %+v", decision)
	}
}

func TestResolveDecisionAmbiguousEqualPrecedenceConflict(t *testing.T) {
	t.Parallel()

	decision := ResolveDecision([]Candidate{
		{
			Field:      FieldOwner,
			Value:      "@acme/platform",
			SourceType: SourceTypeProviderExport,
			Source:     "provider-a",
			ObservedAt: "2026-05-25T17:00:00Z",
		},
		{
			Field:      FieldOwner,
			Value:      "@acme/security",
			SourceType: SourceTypeProviderExport,
			Source:     "provider-b",
			ObservedAt: "2026-05-25T17:01:00Z",
		},
	}, time.Date(2026, 5, 25, 17, 30, 30, 0, time.UTC))

	if decision.ConflictState != ConflictStateAmbiguous {
		t.Fatalf("expected ambiguous conflict state, got %+v", decision)
	}
	if len(decision.ConflictReasonCodes) == 0 {
		t.Fatalf("expected conflict reasons, got %+v", decision)
	}
}

func TestEvaluateFreshness(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 25, 18, 0, 0, 0, time.UTC)

	state, _, err := EvaluateFreshness(now, "2026-05-25T17:00:00Z", "2026-05-26T17:00:00Z", "", "")
	if err != nil || state != FreshnessStateFresh {
		t.Fatalf("expected fresh evidence, got state=%q err=%v", state, err)
	}

	state, _, err = EvaluateFreshness(now, "2026-05-25T17:00:00Z", "2026-05-25T17:30:00Z", "", "")
	if err != nil || state != FreshnessStateExpired {
		t.Fatalf("expected expired evidence, got state=%q err=%v", state, err)
	}

	state, _, err = EvaluateFreshness(now, "2026-05-25T17:00:00Z", "", "", "stale")
	if err != nil || state != FreshnessStateStale {
		t.Fatalf("expected stale evidence, got state=%q err=%v", state, err)
	}

	state, _, err = EvaluateFreshness(now, "2026-05-25T17:00:00Z", "", "", "")
	if err != nil || state != FreshnessStateUnknown {
		t.Fatalf("expected unknown freshness, got state=%q err=%v", state, err)
	}
}

func TestFreshnessStateFromValidityWindow(t *testing.T) {
	t.Parallel()

	state, _, err := EvaluateFreshness(
		time.Date(2026, 5, 25, 18, 0, 0, 0, time.UTC),
		"2026-05-25T17:00:00Z",
		"2026-05-25T19:00:00Z",
		"",
		"",
	)
	if err != nil {
		t.Fatalf("evaluate freshness: %v", err)
	}
	if state != FreshnessStateFresh {
		t.Fatalf("expected fresh validity-window state, got %q", state)
	}
}

func TestFreshnessStableWithGeneratedAt(t *testing.T) {
	t.Parallel()

	generatedAt := time.Date(2026, 5, 25, 18, 0, 0, 0, time.UTC)
	first, _, err := EvaluateFreshness(generatedAt, "2026-05-25T17:00:00Z", "2026-05-26T17:00:00Z", "", "")
	if err != nil {
		t.Fatalf("evaluate first freshness: %v", err)
	}
	second, _, err := EvaluateFreshness(generatedAt, "2026-05-25T17:00:00Z", "2026-05-26T17:00:00Z", "", "")
	if err != nil {
		t.Fatalf("evaluate second freshness: %v", err)
	}
	if first != second {
		t.Fatalf("expected deterministic freshness state, got %q and %q", first, second)
	}
}
