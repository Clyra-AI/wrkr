package report

import (
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
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
	if got.CompositionID == input[0].CompositionID {
		t.Fatalf("expected composition id to be redacted under repo redaction, got %+v", got)
	}
	if got.ProposedActionContract == nil || got.ProposedActionContract.TargetConstraints != nil {
		t.Fatalf("expected proposed contract to use public sanitizer under repo redaction, got %+v", got.ProposedActionContract)
	}
	if got.ProposedActionContract.CompositionRef != got.CompositionID {
		t.Fatalf("expected proposed contract composition ref to follow sanitized composition id, got %+v", got.ProposedActionContract)
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

func TestSanitizeComposedActionPathsPublicRedactsNestedGaitAndContradictionEvidenceRefs(t *testing.T) {
	t.Parallel()

	coverage := &risk.GaitCoverage{
		PolicyDecision:    risk.GaitCoverageDetail{Status: risk.GaitStatusPresent, EvidenceRefs: []string{"runtime:policy"}},
		Approval:          risk.GaitCoverageDetail{Status: risk.GaitStatusMissing, EvidenceRefs: []string{"proof:approval"}},
		JITCredential:     risk.GaitCoverageDetail{Status: risk.GaitStatusNotApplicable},
		FreezeWindow:      risk.GaitCoverageDetail{Status: risk.GaitStatusMissing, EvidenceRefs: []string{"constraint:freeze"}},
		KillSwitch:        risk.GaitCoverageDetail{Status: risk.GaitStatusMissing, EvidenceRefs: []string{"runtime:kill"}},
		ActionOutcome:     risk.GaitCoverageDetail{Status: risk.GaitStatusPresent, EvidenceRefs: []string{"runtime:outcome"}},
		ProofVerification: risk.GaitCoverageDetail{Status: risk.GaitStatusPresent, EvidenceRefs: []string{"proof:verify"}},
	}
	input := []risk.ComposedActionPath{{
		CompositionID: "cap-1",
		GaitCoverage:  coverage,
		Contradictions: []evidencepolicy.Contradiction{{
			Class:        "policy_conflict",
			EvidenceRefs: []string{"evidence://private/conflict"},
		}},
		Stages: []risk.CompositionStage{{
			StageID:      "stage-source",
			Role:         risk.CompositionStageRoleSource,
			GaitCoverage: coverage,
			Contradictions: []evidencepolicy.Contradiction{{
				Class:        "stage_conflict",
				EvidenceRefs: []string{"evidence://private/stage"},
			}},
		}},
		Transitions: []risk.CompositionTransition{{
			TransitionID: "transition-1",
			FromStageID:  "stage-source",
			ToStageID:    "stage-sink",
			GaitCoverage: coverage,
		}},
	}}

	redacted := sanitizeComposedActionPathsPublic(input)
	if len(redacted) != 1 {
		t.Fatalf("expected one redacted composition, got %+v", redacted)
	}
	assertRedactedRefs := func(label string, refs []string) {
		t.Helper()
		for _, ref := range refs {
			if !strings.HasPrefix(ref, "evidence-") {
				t.Fatalf("expected %s refs to be redacted, got %q", label, ref)
			}
		}
	}

	got := redacted[0]
	assertRedactedRefs("composition gait policy", got.GaitCoverage.PolicyDecision.EvidenceRefs)
	assertRedactedRefs("composition gait approval", got.GaitCoverage.Approval.EvidenceRefs)
	assertRedactedRefs("composition contradiction", got.Contradictions[0].EvidenceRefs)
	assertRedactedRefs("stage gait action outcome", got.Stages[0].GaitCoverage.ActionOutcome.EvidenceRefs)
	assertRedactedRefs("stage contradiction", got.Stages[0].Contradictions[0].EvidenceRefs)
	assertRedactedRefs("transition gait proof verification", got.Transitions[0].GaitCoverage.ProofVerification.EvidenceRefs)
}

func TestSanitizeAgentActionBOMRemapsCompositionIDsToSanitizedComposedPaths(t *testing.T) {
	t.Parallel()

	rawContract := &risk.ProposedActionContract{
		ContractID:            "pac-raw",
		ContractFamilyID:      "pac-family",
		ContractContentDigest: "pac-digest",
		CompositionRef:        "cap-raw",
	}
	raw := risk.ComposedActionPath{
		CompositionID:              "cap-raw",
		ResolutionKey:              "acme/private|release.yml",
		TargetIdentity:             "acme/private",
		DurableOutcomeKey:          "asset=acme/private|target_class=production_impacting",
		AffectedAsset:              "acme/private",
		ProposedActionContract:     rawContract,
		ProposedActionContractRefs: []string{"pac-raw"},
	}
	bom := &AgentActionBOM{
		ComposedActionPaths: []risk.ComposedActionPath{raw},
		Summary: AgentActionBOMSummary{
			PrimaryView: &AgentActionBOMPrimaryView{
				CompositionIDs:             []string{"cap-raw"},
				ProposedActionContractRefs: []string{"pac-raw"},
			},
		},
		Items: []AgentActionBOMItem{{
			CompositionIDs:             []string{"cap-raw"},
			ProposedActionContractRefs: []string{"pac-raw"},
		}},
	}

	redacted := sanitizeAgentActionBOM(bom, ShareProfileCustomerRedacted)
	if redacted == nil || len(redacted.ComposedActionPaths) != 1 {
		t.Fatalf("expected one redacted composed path, got %+v", redacted)
	}
	wantCompositionID := redacted.ComposedActionPaths[0].CompositionID
	if wantCompositionID == "cap-raw" {
		t.Fatalf("expected composed path id to be redacted, got %+v", redacted.ComposedActionPaths[0])
	}
	if redacted.ComposedActionPaths[0].ProposedActionContract == nil || redacted.ComposedActionPaths[0].ProposedActionContract.CompositionRef != wantCompositionID {
		t.Fatalf("expected sanitized contract composition ref to match sanitized composed path id, got %+v", redacted.ComposedActionPaths[0].ProposedActionContract)
	}
	if got := redacted.Summary.PrimaryView.CompositionIDs; len(got) != 1 || got[0] != wantCompositionID {
		t.Fatalf("expected primary view composition ids to be remapped, got %+v want %q", got, wantCompositionID)
	}
	if got := redacted.Items[0].CompositionIDs; len(got) != 1 || got[0] != wantCompositionID {
		t.Fatalf("expected BOM item composition ids to be remapped, got %+v want %q", got, wantCompositionID)
	}
}
