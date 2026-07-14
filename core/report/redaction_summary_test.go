package report

import (
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestSanitizeComposedActionPathsPublicKeepsTransitionStageRefsAligned(t *testing.T) {
	t.Parallel()

	input := []risk.ComposedActionPath{{
		CompositionID: "cap-1",
		Stages: []risk.CompositionStage{
			{StageID: "stage-source", Role: risk.CompositionStageRoleSource},
			{StageID: "stage-sink", Role: risk.CompositionStageRoleExternalSink},
		},
		Transitions: []risk.CompositionTransition{{
			TransitionID: "transition-1",
			FromStageID:  "stage-source",
			ToStageID:    "stage-sink",
		}},
	}}

	checkAlignment := func(paths []risk.ComposedActionPath) {
		t.Helper()
		if len(paths) != 1 || len(paths[0].Transitions) != 1 {
			t.Fatalf("expected one sanitized composition transition, got %+v", paths)
		}
		stageSet := map[string]struct{}{}
		for _, stage := range paths[0].Stages {
			stageSet[stage.StageID] = struct{}{}
		}
		transition := paths[0].Transitions[0]
		if _, ok := stageSet[transition.FromStageID]; !ok {
			t.Fatalf("expected from_stage_id %q to match a sanitized stage id, got %+v", transition.FromStageID, paths[0])
		}
		if _, ok := stageSet[transition.ToStageID]; !ok {
			t.Fatalf("expected to_stage_id %q to match a sanitized stage id, got %+v", transition.ToStageID, paths[0])
		}
	}

	checkAlignment(sanitizeComposedActionPathsPublic(input))
	checkAlignment(sanitizeComposedActionPathsWithConfig(input, ResolveRedactionConfig(ShareProfileInternal, []RedactionField{RedactionPaths})))
}

func TestSanitizeComposedActionPathsWithRepoRedactionHidesDerivedTargetsAndResolution(t *testing.T) {
	t.Parallel()

	input := []risk.ComposedActionPath{{
		CompositionID:     "cap-1",
		ResolutionKey:     "acme/private|release.yml",
		TargetIdentity:    "acme/private",
		DurableOutcomeKey: "asset=acme/private|target_class=production_impacting",
		AffectedAsset:     "acme/private",
		TruncatedCandidates: []string{
			"acme/private|release.yml->acme/private|deploy.yml",
		},
		Stages: []risk.CompositionStage{{
			StageID:       "stage-source",
			Role:          risk.CompositionStageRoleSource,
			ResolutionKey: "acme/private|release.yml",
		}},
		ProposedActionContract: &risk.ProposedActionContract{
			ResolutionKey:     "acme/private|release.yml",
			TargetConstraints: []risk.ProposedActionTargetConstraint{{Key: "target_identity", Value: "acme/private"}},
		},
	}}

	redacted := sanitizeComposedActionPathsWithConfig(input, ResolveRedactionConfig(ShareProfileInternal, []RedactionField{RedactionRepos}))
	if len(redacted) != 1 {
		t.Fatalf("expected one redacted composition, got %+v", redacted)
	}
	got := redacted[0]
	for _, value := range []string{got.ResolutionKey, got.TargetIdentity, got.DurableOutcomeKey, got.AffectedAsset, got.Stages[0].ResolutionKey, got.ProposedActionContract.ResolutionKey} {
		if strings.Contains(value, "acme/private") {
			t.Fatalf("expected repo-derived composed fields to be redacted, got %+v", got)
		}
	}
	if got.ProposedActionContract == nil || got.ProposedActionContract.TargetConstraints != nil {
		t.Fatalf("expected proposed contract to use public sanitizer under repo redaction, got %+v", got.ProposedActionContract)
	}
	if len(got.ProposedActionContractRefs) != 1 || got.ProposedActionContractRefs[0] != got.ProposedActionContract.ContractID {
		t.Fatalf("expected proposed contract refs to be remapped to sanitized contract id, got refs=%+v contract=%+v", got.ProposedActionContractRefs, got.ProposedActionContract)
	}
	if got.ProposedActionContract.ContractID == input[0].ProposedActionContract.ContractID ||
		got.ProposedActionContract.ContractContentDigest == input[0].ProposedActionContract.ContractContentDigest ||
		got.ProposedActionContract.ContractFamilyID == input[0].ProposedActionContract.ContractFamilyID {
		t.Fatalf("expected redacted proposed contract identity to be recomputed, got %+v", got.ProposedActionContract)
	}
	if len(got.TruncatedCandidates) != 1 || strings.Contains(got.TruncatedCandidates[0], "acme/private") {
		t.Fatalf("expected truncated candidates to be redacted under repo redaction, got %+v", got.TruncatedCandidates)
	}
}
