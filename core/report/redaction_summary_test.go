package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
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

func TestSanitizeComposedActionPathsPublicRedactsMultiStageBoundaryAndCorrelationRefs(t *testing.T) {
	t.Parallel()

	input := []risk.ComposedActionPath{
		{
			CompositionID: "cap-primary", PatternID: risk.CompositionPatternCodeToDeployMultiStage, ReachabilityState: risk.CompositionReachabilityPossible,
			AlternateRouteRefs: []string{"cap-alternate"}, EquivalentOutcomeRefs: []string{"cap-alternate"}, EquivalentOutcomeEscalationSource: "peer:cap-alternate", MostRestrictiveSource: "peer:cap-alternate",
			Stages: []risk.CompositionStage{{
				StageID: "stage-source", Role: risk.CompositionStageRoleSource, SystemClass: risk.CompositionSystemClassRepo,
				TrustBoundary: "repo:acme/private-repo", CorrelationRefs: []string{"workflow_chain:wfc-private"}, AlternateRouteRefs: []string{"cap-alternate"},
			}},
			Transitions: []risk.CompositionTransition{{
				TransitionID: "transition-private", FromStageID: "stage-source", ToStageID: "stage-source",
				TrustBoundary: "repo:acme/private-repo->ci:acme/private-repo", CorrelationRefs: []string{"workflow_chain:wfc-private"}, AlternateRouteRefs: []string{"cap-alternate"},
			}},
		},
		{CompositionID: "cap-alternate", PatternID: risk.CompositionPatternCodeToDeployMultiStage, ReachabilityState: risk.CompositionReachabilityPossible},
	}

	redacted := sanitizeComposedActionPathsPublic(input)
	if len(redacted) != 2 {
		t.Fatalf("expected both routes, got %+v", redacted)
	}
	primary := redacted[0]
	peerID := redacted[1].CompositionID
	if strings.Contains(primary.Stages[0].TrustBoundary, "acme") || strings.Contains(strings.Join(primary.Stages[0].CorrelationRefs, "|"), "wfc-private") {
		t.Fatalf("public multi-stage boundary/correlation evidence was not redacted: %+v", primary.Stages[0])
	}
	if len(primary.AlternateRouteRefs) != 1 || primary.AlternateRouteRefs[0] != peerID || primary.Stages[0].AlternateRouteRefs[0] != peerID || primary.Transitions[0].AlternateRouteRefs[0] != peerID {
		t.Fatalf("redacted alternate-route refs must align with the redacted peer id: primary=%+v peer=%s", primary, peerID)
	}
	if primary.EquivalentOutcomeEscalationSource != "peer:"+peerID {
		t.Fatalf("redacted parity source must align with the redacted peer id: primary=%+v peer=%s", primary, peerID)
	}
	if primary.MostRestrictiveSource != "peer:"+peerID {
		t.Fatalf("redacted most-restrictive source must align with the redacted peer id: primary=%+v peer=%s", primary, peerID)
	}
}

func TestProjectComposedActionPathsForShareProfileRedactsUnmappedAlternateRouteRefs(t *testing.T) {
	t.Parallel()

	input := risk.ComposedActionPath{
		CompositionID:                     "cap-primary",
		AlternateRouteRefs:                []string{"cap-peer"},
		EquivalentOutcomeRefs:             []string{"cap-peer"},
		EquivalentOutcomeEscalationSource: "peer:cap-peer",
		MostRestrictiveSource:             "peer:cap-peer",
		Stages: []risk.CompositionStage{{
			StageID:            "stage-source",
			Role:               risk.CompositionStageRoleSource,
			AlternateRouteRefs: []string{"cap-peer"},
		}},
		Transitions: []risk.CompositionTransition{{
			TransitionID:       "transition-source-peer",
			FromStageID:        "stage-source",
			ToStageID:          "stage-source",
			AlternateRouteRefs: []string{"cap-peer"},
		}},
	}

	redacted, err := ProjectComposedActionPathsForShareProfile(state.Snapshot{}, []risk.ComposedActionPath{input}, ShareProfileCustomerRedacted)
	if err != nil {
		t.Fatalf("project redacted composition: %v", err)
	}
	if len(redacted) != 1 {
		t.Fatalf("expected one selected composition, got %+v", redacted)
	}
	primary := redacted[0]
	wantPeerID := redactValue("composition", "cap-peer", 8)
	if primary.AlternateRouteRefs[0] != wantPeerID || primary.EquivalentOutcomeRefs[0] != wantPeerID {
		t.Fatalf("unmapped peer refs must be redacted: %+v", primary)
	}
	if primary.Stages[0].AlternateRouteRefs[0] != wantPeerID || primary.Transitions[0].AlternateRouteRefs[0] != wantPeerID {
		t.Fatalf("nested unmapped peer refs must be redacted: %+v", primary)
	}
	if primary.EquivalentOutcomeEscalationSource != "peer:"+wantPeerID || primary.MostRestrictiveSource != "peer:"+wantPeerID {
		t.Fatalf("peer-prefixed unmapped refs must be redacted: %+v", primary)
	}
	payload, err := json.Marshal(primary)
	if err != nil {
		t.Fatalf("marshal projected composition: %v", err)
	}
	if strings.Contains(string(payload), "cap-peer") {
		t.Fatalf("selected share-profile projection leaked raw peer composition ref: %s", payload)
	}
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

func TestSanitizeProposedActionContractPublicRedactsV3NestedRequirements(t *testing.T) {
	t.Parallel()

	contract := &risk.ProposedActionContract{
		ContractVersion: risk.ProposedActionContractVersionV3,
		ContractKind:    risk.ProposedActionContractKind,
		CompositionRef:  "cap-private",
		Revision:        1,
		ReportOnly:      true,
		AuthorityRequirements: []risk.ProposedActionRequirement{{
			RequirementID: "pacr-owner", Kind: "business_owner", RequiredConstraint: "owner:acme/private", ObservedValue: "alice@acme", EvidenceState: risk.EvidenceStateDeclared, FreshnessState: "fresh", EvidenceRefs: []string{"evidence://private/owner"},
		}},
		Preconditions: []risk.ProposedActionPrecondition{{
			RequirementID: "pacp-effect", Kind: "effect_contract", RequiredConstraint: "target:acme/private", ObservedValue: "release:acme/private", EvidenceState: risk.EvidenceStateDeclared, FreshnessState: "fresh", EvidenceRefs: []string{"evidence://private/effect"},
		}},
		ConfirmationRequirement: &risk.ProposedActionConfirmation{Mode: "explicit_confirmation", Required: true, EvidenceState: risk.EvidenceStateDeclared, FreshnessState: "fresh", EvidenceRefs: []string{"evidence://private/confirm"}},
		ApprovalRequirement:     &risk.ProposedActionApproval{Required: true, ScopeDigest: "sha256:abc", EvidenceState: risk.EvidenceStateDeclared, FreshnessState: "fresh", ApproverRoles: []string{"acme-approver"}, EvidenceRefs: []string{"evidence://private/approval"}},
		CompensationRequirement: &risk.ProposedActionCompensation{Required: true, Kind: "documented_recovery", ProcedureRef: "runbook://acme/private", Target: "acme/private", EvidenceState: risk.EvidenceStateDeclared, FreshnessState: "fresh", EvidenceRefs: []string{"evidence://private/recovery"}},
		LifecycleObservations:   []risk.ProposedActionLifecycleObservation{{ObservationID: "pacl-a", Kind: risk.LifecycleObservationAxymVerification, Producer: "axym", EvidenceState: risk.EvidenceStateDeclared, FreshnessState: "fresh", EvidenceRefs: []string{"evidence://private/verify"}, ProofRefs: []string{"proof://private/verify"}}},
	}
	risk.RefreshProposedActionContractIdentity(contract)
	redacted := sanitizeProposedActionContractPublic(contract)
	payload, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("marshal redacted contract: %v", err)
	}
	for _, sensitive := range []string{"acme/private", "alice@acme", "evidence://private", "proof://private", "acme-approver"} {
		if strings.Contains(string(payload), sensitive) {
			t.Fatalf("expected v3 nested contract field to be redacted for %q: %s", sensitive, payload)
		}
	}
	if redacted.ContractID == contract.ContractID || redacted.ContractContentDigest == contract.ContractContentDigest {
		t.Fatalf("expected redacted v3 contract to receive a distinct identity: %+v", redacted)
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

func TestSanitizeComposedActionPathsPublicRedactsOutcomeKeyAndAuthorityDeltas(t *testing.T) {
	t.Parallel()

	input := []risk.ComposedActionPath{{
		CompositionID:     "cap-1",
		TargetIdentity:    "prod:checkout",
		DurableOutcomeKey: "asset=prod:checkout|target_class=production_impacting|outcome=production_deploy|environment=production",
		OutcomeKey:        "asset=prod:checkout|target_class=production_impacting|outcome=production_deploy|environment=production",
		Stages: []risk.CompositionStage{{
			StageID:            "stage-source",
			Role:               risk.CompositionStageRoleSource,
			ParentAuthorityRef: "authority:repo-admin",
			ChildAuthorityRef:  "authority:prod-admin",
			ScopeDelta:         []string{"scope:added:prod:*"},
			TargetDelta:        []string{"target:added:prod:checkout"},
			CredentialDelta:    []string{"credential:added:aws:sts-role"},
			ExpiryDelta:        []string{"expiry:removed:2026-07-31T00:00:00Z"},
		}},
		Transitions: []risk.CompositionTransition{{
			TransitionID:       "transition-1",
			FromStageID:        "stage-source",
			ToStageID:          "stage-sink",
			ParentAuthorityRef: "authority:repo-admin",
			ChildAuthorityRef:  "authority:prod-admin",
			ScopeDelta:         []string{"scope:added:prod:*"},
			TargetDelta:        []string{"target:added:prod:checkout"},
			CredentialDelta:    []string{"credential:added:aws:sts-role"},
			ExpiryDelta:        []string{"expiry:removed:2026-07-31T00:00:00Z"},
		}},
	}}

	redacted := sanitizeComposedActionPathsPublic(input)
	if len(redacted) != 1 {
		t.Fatalf("expected one redacted composed path, got %+v", redacted)
	}
	got := redacted[0]
	for _, value := range []string{got.DurableOutcomeKey, got.OutcomeKey, got.Stages[0].ParentAuthorityRef, got.Stages[0].ChildAuthorityRef, got.Transitions[0].ParentAuthorityRef, got.Transitions[0].ChildAuthorityRef} {
		if strings.Contains(value, "prod:checkout") || strings.Contains(value, "authority:repo-admin") || strings.Contains(value, "authority:prod-admin") {
			t.Fatalf("expected composed outcome and authority refs to be redacted, got %+v", got)
		}
	}
	for _, values := range [][]string{got.Stages[0].ScopeDelta, got.Stages[0].TargetDelta, got.Stages[0].CredentialDelta, got.Stages[0].ExpiryDelta, got.Transitions[0].ScopeDelta, got.Transitions[0].TargetDelta, got.Transitions[0].CredentialDelta, got.Transitions[0].ExpiryDelta} {
		for _, value := range values {
			if strings.Contains(value, "prod:*") || strings.Contains(value, "prod:checkout") || strings.Contains(value, "aws:sts-role") || strings.Contains(value, "2026-07-31") {
				t.Fatalf("expected authority delta arrays to be redacted, got %+v", got)
			}
		}
	}
}

func TestSanitizeComposedActionPathsWithConfigRedactsOutcomeKeyAndAuthorityDeltas(t *testing.T) {
	t.Parallel()

	input := []risk.ComposedActionPath{{
		CompositionID:     "cap-1",
		TargetIdentity:    "prod:checkout",
		DurableOutcomeKey: "asset=prod:checkout|target_class=production_impacting|outcome=production_deploy|environment=production",
		OutcomeKey:        "asset=prod:checkout|target_class=production_impacting|outcome=production_deploy|environment=production",
		Stages: []risk.CompositionStage{{
			StageID:            "stage-source",
			Role:               risk.CompositionStageRoleSource,
			ResolutionKey:      "acme/private|release.yml",
			ParentAuthorityRef: "authority:repo-admin",
			ChildAuthorityRef:  "authority:prod-admin",
			ScopeDelta:         []string{"scope:added:prod:*"},
			TargetDelta:        []string{"target:added:prod:checkout"},
			CredentialDelta:    []string{"credential:added:aws:sts-role"},
			ExpiryDelta:        []string{"expiry:removed:2026-07-31T00:00:00Z"},
		}},
		Transitions: []risk.CompositionTransition{{
			TransitionID:       "transition-1",
			FromStageID:        "stage-source",
			ToStageID:          "stage-sink",
			ParentAuthorityRef: "authority:repo-admin",
			ChildAuthorityRef:  "authority:prod-admin",
			ScopeDelta:         []string{"scope:added:prod:*"},
			TargetDelta:        []string{"target:added:prod:checkout"},
			CredentialDelta:    []string{"credential:added:aws:sts-role"},
			ExpiryDelta:        []string{"expiry:removed:2026-07-31T00:00:00Z"},
		}},
	}}

	redacted := sanitizeComposedActionPathsWithConfig(input, ResolveRedactionConfig(ShareProfileInternal, []RedactionField{RedactionPaths}))
	if len(redacted) != 1 {
		t.Fatalf("expected one redacted composed path, got %+v", redacted)
	}
	got := redacted[0]
	for _, value := range []string{got.DurableOutcomeKey, got.OutcomeKey, got.Stages[0].ParentAuthorityRef, got.Stages[0].ChildAuthorityRef, got.Transitions[0].ParentAuthorityRef, got.Transitions[0].ChildAuthorityRef} {
		if strings.Contains(value, "prod:checkout") || strings.Contains(value, "authority:repo-admin") || strings.Contains(value, "authority:prod-admin") {
			t.Fatalf("expected configured composed outcome and authority refs to be redacted, got %+v", got)
		}
	}
	for _, values := range [][]string{got.Stages[0].ScopeDelta, got.Stages[0].TargetDelta, got.Stages[0].CredentialDelta, got.Stages[0].ExpiryDelta, got.Transitions[0].ScopeDelta, got.Transitions[0].TargetDelta, got.Transitions[0].CredentialDelta, got.Transitions[0].ExpiryDelta} {
		for _, value := range values {
			if strings.Contains(value, "prod:*") || strings.Contains(value, "prod:checkout") || strings.Contains(value, "aws:sts-role") || strings.Contains(value, "2026-07-31") {
				t.Fatalf("expected configured authority delta arrays to be redacted, got %+v", got)
			}
		}
	}
}

func TestSanitizeAgentActionBOMRemapsCompositionIDsToSanitizedComposedPaths(t *testing.T) {
	t.Parallel()

	rawContract := &risk.ProposedActionContract{
		ContractID:            "pac-raw",
		ContractFamilyID:      "pac-family",
		ContractContentDigest: "pac-digest",
		CompositionRef:        "cap-raw",
		ContractVersion:       risk.ProposedActionContractVersion,
		ContractKind:          risk.ProposedActionContractKind,
		ResolutionKey:         "acme/private|release.yml",
		ExpectedOutcomeClass:  "production_deploy",
	}
	raw := risk.ComposedActionPath{
		CompositionID:      "cap-raw",
		PathIDs:            []string{"apc-raw"},
		ResolutionKey:      "acme/private|release.yml",
		TargetIdentity:     "acme/private",
		DurableOutcomeKey:  "asset=acme/private|target_class=production_impacting",
		AffectedAsset:      "acme/private",
		OutcomeClass:       "production_deploy",
		RecommendedControl: risk.RecommendedControlBlockStandingCredential,
		TargetClass:        risk.TargetClassProductionImpacting,
		Stages: []risk.CompositionStage{{
			StageID:  "stage-raw",
			Role:     risk.CompositionStageRoleSource,
			PathID:   "apc-raw",
			Location: ".github/workflows/release.yml",
		}},
		ProposedActionContract:     rawContract,
		ProposedActionContractRefs: []string{"pac-raw"},
		ClosureRequirements: []risk.ClosureRequirement{{
			ID:          "closure-raw",
			ClosureRefs: []string{"evidence://private/closure"},
		}},
	}
	bom := &AgentActionBOM{
		ComposedActionPaths: []risk.ComposedActionPath{raw},
		Summary: AgentActionBOMSummary{
			PrimaryView: &AgentActionBOMPrimaryView{
				CompositionID:              "cap-raw",
				CompositionStageMap:        []AgentActionBOMCompositionStage{{StageID: "stage-raw", Role: risk.CompositionStageRoleSource, PathID: "apc-raw", Location: ".github/workflows/release.yml"}},
				TargetSummary:              "acme/private production_impacting",
				ProposedActionContract:     risk.CloneProposedActionContract(rawContract),
				ClosureRequirements:        risk.CloneClosureRequirements(raw.ClosureRequirements),
				CompositionIDs:             []string{"cap-raw"},
				ProposedActionContractRefs: []string{"pac-raw"},
			},
		},
		Items: []AgentActionBOMItem{{
			CompositionIDs:             []string{"cap-raw"},
			ProposedActionContractRefs: []string{"pac-raw"},
		}},
	}

	assertPrimaryViewRedaction := func(label string, redacted *AgentActionBOM) {
		t.Helper()
		if redacted == nil || len(redacted.ComposedActionPaths) != 1 {
			t.Fatalf("%s: expected one redacted composed path, got %+v", label, redacted)
		}
		wantCompositionID := redacted.ComposedActionPaths[0].CompositionID
		if wantCompositionID == "cap-raw" {
			t.Fatalf("%s: expected composed path id to be redacted, got %+v", label, redacted.ComposedActionPaths[0])
		}
		if redacted.ComposedActionPaths[0].ProposedActionContract == nil || redacted.ComposedActionPaths[0].ProposedActionContract.CompositionRef != wantCompositionID {
			t.Fatalf("%s: expected sanitized contract composition ref to match sanitized composed path id, got %+v", label, redacted.ComposedActionPaths[0].ProposedActionContract)
		}
		if got := redacted.Summary.PrimaryView.CompositionID; got != wantCompositionID {
			t.Fatalf("%s: expected primary view composition id to be remapped, got %q want %q", label, got, wantCompositionID)
		}
		if got := redacted.Summary.PrimaryView.CompositionIDs; len(got) != 1 || got[0] != wantCompositionID {
			t.Fatalf("%s: expected primary view composition ids to be remapped, got %+v want %q", label, got, wantCompositionID)
		}
		if got := redacted.Items[0].CompositionIDs; len(got) != 1 || got[0] != wantCompositionID {
			t.Fatalf("%s: expected BOM item composition ids to be remapped, got %+v want %q", label, got, wantCompositionID)
		}
		if len(redacted.Summary.PrimaryView.CompositionStageMap) != 1 {
			t.Fatalf("%s: expected primary view stage map to survive redaction, got %+v", label, redacted.Summary.PrimaryView.CompositionStageMap)
		}
		stage := redacted.Summary.PrimaryView.CompositionStageMap[0]
		composedStage := redacted.ComposedActionPaths[0].Stages[0]
		if stage.StageID != composedStage.StageID || stage.PathID != composedStage.PathID || stage.Location != composedStage.Location {
			t.Fatalf("%s: expected primary view stage map to follow sanitized composed stage, got %+v want %+v", label, stage, composedStage)
		}
		if strings.Contains(stage.PathID, "apc-raw") || strings.Contains(stage.Location, ".github/workflows/release.yml") {
			t.Fatalf("%s: expected primary view stage map to redact raw path/location, got %+v", label, stage)
		}
		if redacted.Summary.PrimaryView.ProposedActionContract == nil {
			t.Fatalf("%s: expected primary view proposed contract after redaction", label)
		}
		if redacted.Summary.PrimaryView.ProposedActionContract.ContractID != redacted.ComposedActionPaths[0].ProposedActionContract.ContractID {
			t.Fatalf("%s: expected primary view contract id to match sanitized composed path contract, got %+v vs %+v", label, redacted.Summary.PrimaryView.ProposedActionContract, redacted.ComposedActionPaths[0].ProposedActionContract)
		}
		if redacted.Summary.PrimaryView.ProposedActionContract.CompositionRef != wantCompositionID {
			t.Fatalf("%s: expected primary view contract composition ref to match sanitized composition id, got %+v", label, redacted.Summary.PrimaryView.ProposedActionContract)
		}
		if len(redacted.Summary.PrimaryView.ProposedActionContractRefs) != 1 || redacted.Summary.PrimaryView.ProposedActionContractRefs[0] != redacted.Summary.PrimaryView.ProposedActionContract.ContractID {
			t.Fatalf("%s: expected primary view contract refs to follow sanitized contract identity, got refs=%+v contract=%+v", label, redacted.Summary.PrimaryView.ProposedActionContractRefs, redacted.Summary.PrimaryView.ProposedActionContract)
		}
		if strings.Contains(redacted.Summary.PrimaryView.TargetSummary, "acme/private") {
			t.Fatalf("%s: expected primary view target summary to follow sanitized composition target fields, got %q", label, redacted.Summary.PrimaryView.TargetSummary)
		}
		if got, want := redacted.Summary.PrimaryView.ClosureRequirements, redacted.ComposedActionPaths[0].ClosureRequirements; len(got) != len(want) || len(got) != 1 || len(got[0].ClosureRefs) != len(want[0].ClosureRefs) || got[0].ClosureRefs[0] != want[0].ClosureRefs[0] {
			t.Fatalf("%s: expected primary view closure requirements to follow sanitized composed-path closure requirements, got %+v want %+v", label, got, want)
		}
	}

	assertPrimaryViewRedaction("public", sanitizeAgentActionBOM(bom, ShareProfileCustomerRedacted))
	assertPrimaryViewRedaction("config", sanitizeAgentActionBOMWithConfig(bom, ShareProfileInternal, ResolveRedactionConfig(ShareProfileInternal, []RedactionField{RedactionRepos, RedactionPaths})))
}
