package risk

import (
	"reflect"
	"testing"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
)

func TestBuildComposedActionPathsStableIDIgnoresPathIDChurn(t *testing.T) {
	first, _ := BuildComposedActionPaths([]ActionPath{
		compositionTestPath("apc-a", "rk-read", []string{"read"}, TargetClassCustomerDataAdjacent),
		compositionTestPath("apc-b", "rk-egress", []string{"egress"}, TargetClassUnknown),
	}, nil)
	second, _ := BuildComposedActionPaths([]ActionPath{
		compositionTestPath("apc-churned-b", "rk-egress", []string{"egress"}, TargetClassUnknown),
		compositionTestPath("apc-churned-a", "rk-read", []string{"read"}, TargetClassCustomerDataAdjacent),
	}, nil)

	if len(first) == 0 || len(second) == 0 {
		t.Fatalf("expected compositions, got first=%v second=%v", first, second)
	}
	if first[0].CompositionID != second[0].CompositionID {
		t.Fatalf("composition_id should ignore path_id churn: %s != %s", first[0].CompositionID, second[0].CompositionID)
	}
	if reflect.DeepEqual(first[0].PathIDs, second[0].PathIDs) {
		t.Fatalf("path refs should still reflect instance ids, got %v", first[0].PathIDs)
	}
}

func TestBuildComposedActionPathsSensitiveReadToEgress(t *testing.T) {
	paths := []ActionPath{
		compositionTestPath("apc-read", "rk-read", []string{"read"}, TargetClassCustomerDataAdjacent),
		compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown),
	}
	compositions, choice := BuildComposedActionPaths(paths, &agentresolver.WorkflowChainArtifact{
		Chains: []agentresolver.WorkflowChain{{
			ChainID: "wfc-read-egress",
			PathIDs: []string{"apc-read", "apc-egress"},
		}},
	})

	got := findCompositionByPattern(compositions, CompositionPatternSensitiveReadToEgress)
	if got == nil {
		t.Fatalf("expected sensitive-read-to-egress composition, got %+v", compositions)
		return
	}
	if got.ClaimState != CompositionClaimDeclaredPolicyOnly {
		t.Fatalf("declared policy should not become runtime control, got %q", got.ClaimState)
	}
	if len(got.Stages) != 2 || got.Stages[0].Role != CompositionStageRoleSource || got.Stages[1].Role != CompositionStageRoleExternalSink {
		t.Fatalf("unexpected stages: %+v", got.Stages)
	}
	if len(got.WorkflowChainRefs) != 1 || got.WorkflowChainRefs[0] != "wfc-read-egress" {
		t.Fatalf("expected workflow chain refs, got %v", got.WorkflowChainRefs)
	}
	if choice == nil || choice.Summary.TotalCompositions == 0 {
		t.Fatalf("expected control-first composition choice, got %+v", choice)
	}
}

func TestBuildComposedActionPathsCodeToDeployChangesOutcomeContext(t *testing.T) {
	staging := []ActionPath{
		compositionTestPath("apc-code", "rk-code", []string{"write"}, TargetClassReleaseAdjacent),
		compositionTestPath("apc-deploy-staging", "rk-deploy", []string{"deploy"}, TargetClassReleaseAdjacent),
	}
	production := []ActionPath{
		compositionTestPath("apc-code", "rk-code", []string{"write"}, TargetClassReleaseAdjacent),
		compositionTestPath("apc-deploy-prod", "rk-deploy", []string{"deploy"}, TargetClassProductionImpacting),
	}
	stagingCompositions, _ := BuildComposedActionPaths(staging, nil)
	productionCompositions, _ := BuildComposedActionPaths(production, nil)
	stagingCodeDeploy := findCompositionByPattern(stagingCompositions, CompositionPatternCodeToDeploy)
	productionCodeDeploy := findCompositionByPattern(productionCompositions, CompositionPatternCodeToDeploy)
	if stagingCodeDeploy == nil || productionCodeDeploy == nil {
		t.Fatalf("expected code-to-deploy compositions, staging=%+v production=%+v", stagingCompositions, productionCompositions)
		return
	}
	if stagingCodeDeploy.CompositionID == productionCodeDeploy.CompositionID {
		t.Fatalf("expected outcome context to affect composition_id: %s", stagingCodeDeploy.CompositionID)
	}
}

func TestCompositionCoverageDoesNotTreatDeclaredPolicyAsRuntimeControl(t *testing.T) {
	paths := []ActionPath{
		compositionTestPath("apc-secret", "rk-secret", []string{"secret"}, TargetClassUnknown),
		compositionTestPath("apc-network", "rk-network", []string{"network"}, TargetClassUnknown),
	}
	compositions, _ := BuildComposedActionPaths(paths, nil)
	got := findCompositionByPattern(compositions, CompositionPatternSecretToNetwork)
	if got == nil {
		t.Fatalf("expected secret-to-network composition, got %+v", compositions)
		return
	}
	if got.ClaimState == CompositionClaimRuntimeControlled || got.ClaimState == CompositionClaimObservedExecution {
		t.Fatalf("declared policy and missing runtime coverage must not imply control, got %q", got.ClaimState)
	}
}

func TestBuildComposedActionPathsObservedExecutionRequiresRuntimeEvidenceForEveryStage(t *testing.T) {
	t.Parallel()

	source := compositionTestPath("apc-read", "rk-read", []string{"read"}, TargetClassCustomerDataAdjacent)
	source.GaitCoverage.ActionOutcome = GaitCoverageDetail{
		Status:       GaitStatusPresent,
		EvidenceRefs: []string{"runtime:read"},
	}
	sink := compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown)

	compositions, _ := BuildComposedActionPaths([]ActionPath{source, sink}, nil)
	got := findCompositionByPattern(compositions, CompositionPatternSensitiveReadToEgress)
	if got == nil {
		t.Fatalf("expected sensitive-read-to-egress composition, got %+v", compositions)
		return
	}
	if got.ClaimState == CompositionClaimObservedExecution {
		t.Fatalf("expected missing sink runtime evidence to keep composed path below observed execution, got %+v", got)
	}
}

func TestBuildComposedActionPathsObservedExecutionWhenEveryStageHasRuntimeEvidence(t *testing.T) {
	t.Parallel()

	source := compositionTestPath("apc-read", "rk-read", []string{"read"}, TargetClassCustomerDataAdjacent)
	source.GaitCoverage.ActionOutcome = GaitCoverageDetail{
		Status:       GaitStatusPresent,
		EvidenceRefs: []string{"runtime:read"},
	}
	sink := compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown)
	sink.GaitCoverage.ActionOutcome = GaitCoverageDetail{
		Status:       GaitStatusPresent,
		EvidenceRefs: []string{"runtime:egress"},
	}

	compositions, _ := BuildComposedActionPaths([]ActionPath{source, sink}, nil)
	got := findCompositionByPattern(compositions, CompositionPatternSensitiveReadToEgress)
	if got == nil {
		t.Fatalf("expected sensitive-read-to-egress composition, got %+v", compositions)
		return
	}
	if got.ClaimState != CompositionClaimObservedExecution {
		t.Fatalf("expected full stage runtime evidence to upgrade composed path to observed execution, got %+v", got)
	}
}

func TestCompositionRuntimeControlledRequiresPerStageCoverage(t *testing.T) {
	t.Parallel()

	coverage := &GaitCoverage{
		PolicyDecision:    GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"runtime:policy"}},
		ActionOutcome:     GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"runtime:outcome"}},
		ProofVerification: GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"runtime:proof"}},
		Approval:          GaitCoverageDetail{Status: GaitStatusNotApplicable},
		JITCredential:     GaitCoverageDetail{Status: GaitStatusNotApplicable},
		FreezeWindow:      GaitCoverageDetail{Status: GaitStatusNotApplicable},
		KillSwitch:        GaitCoverageDetail{Status: GaitStatusNotApplicable},
	}
	stages := []CompositionStage{
		{
			Role:                 CompositionStageRoleSource,
			PolicyCoverageStatus: PolicyCoverageStatusRuntimeProven,
			FreshnessState:       evidencepolicy.FreshnessStateFresh,
			GaitCoverage: &GaitCoverage{
				PolicyDecision:    GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"runtime:policy"}},
				ActionOutcome:     GaitCoverageDetail{Status: GaitStatusMissing},
				ProofVerification: GaitCoverageDetail{Status: GaitStatusMissing},
				Approval:          GaitCoverageDetail{Status: GaitStatusNotApplicable},
				JITCredential:     GaitCoverageDetail{Status: GaitStatusNotApplicable},
				FreezeWindow:      GaitCoverageDetail{Status: GaitStatusNotApplicable},
				KillSwitch:        GaitCoverageDetail{Status: GaitStatusNotApplicable},
			},
		},
		{
			Role:                 CompositionStageRoleExternalSink,
			PolicyCoverageStatus: PolicyCoverageStatusRuntimeProven,
			FreshnessState:       evidencepolicy.FreshnessStateFresh,
			GaitCoverage: &GaitCoverage{
				PolicyDecision:    GaitCoverageDetail{Status: GaitStatusMissing},
				ActionOutcome:     GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"runtime:outcome"}},
				ProofVerification: GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"runtime:proof"}},
				Approval:          GaitCoverageDetail{Status: GaitStatusNotApplicable},
				JITCredential:     GaitCoverageDetail{Status: GaitStatusNotApplicable},
				FreezeWindow:      GaitCoverageDetail{Status: GaitStatusNotApplicable},
				KillSwitch:        GaitCoverageDetail{Status: GaitStatusNotApplicable},
			},
		},
	}

	if got := compositionClaimState(EvidenceStateDeclared, PolicyCoverageStatusRuntimeProven, evidencepolicy.FreshnessStateFresh, coverage, stages, nil); got == CompositionClaimRuntimeControlled {
		t.Fatalf("expected split stage runtime evidence to stay below runtime_controlled, got %q", got)
	}
}

func TestCompositionTargetIdentityPreservesEndpointTuples(t *testing.T) {
	t.Parallel()

	first := compositionTargetIdentity(compositionPatternSpec{}, []ActionPath{{
		MutableEndpointSemantics: []agginventory.MutableEndpointSemantic{
			{Surface: "apiA", Operation: "GET /x"},
			{Surface: "apiB", Operation: "POST /y"},
		},
	}})
	second := compositionTargetIdentity(compositionPatternSpec{}, []ActionPath{{
		MutableEndpointSemantics: []agginventory.MutableEndpointSemantic{
			{Surface: "apiA", Operation: "POST /y"},
			{Surface: "apiB", Operation: "GET /x"},
		},
	}})

	if first == second {
		t.Fatalf("expected endpoint tuple order to stay encoded in target identity, got %q", first)
	}
}

func TestCompositionTargetIdentityIgnoresCredentialTuplesForEquivalentOutcomes(t *testing.T) {
	t.Parallel()

	first := compositionTargetIdentity(compositionPatternSpec{}, []ActionPath{{
		MatchedProductionTargets: []string{"prod:checkout"},
		CredentialAuthority: &agginventory.CredentialAuthority{
			TargetSystem: "aws",
			LikelyScope:  "prod",
		},
		CredentialProvenance: &agginventory.CredentialProvenance{
			TargetSystem: "gcp",
			LikelyScope:  "staging",
		},
	}})
	second := compositionTargetIdentity(compositionPatternSpec{}, []ActionPath{{
		MatchedProductionTargets: []string{"prod:checkout"},
		CredentialAuthority: &agginventory.CredentialAuthority{
			TargetSystem: "aws",
			LikelyScope:  "staging",
		},
		CredentialProvenance: &agginventory.CredentialProvenance{
			TargetSystem: "gcp",
			LikelyScope:  "prod",
		},
	}})

	if first != second || first != "prod:checkout" {
		t.Fatalf("expected equivalent-outcome grouping to ignore credential tuples, got first=%q second=%q", first, second)
	}
}

func TestBuildComposedActionPathsAggregatesEvidenceCompletenessAcrossStages(t *testing.T) {
	t.Parallel()

	source := compositionTestPath("apc-read", "rk-read", []string{"read"}, TargetClassCustomerDataAdjacent)
	source.EvidenceCompleteness = &EvidenceCompleteness{
		TotalScore: 92,
		Label:      EvidenceCompletenessStrong,
		AxisScores: []EvidenceCompletenessAxisScore{
			{Axis: CompletenessAxisDiscovery, Score: 90, Reasons: []string{"source-discovery"}},
			{Axis: CompletenessAxisProof, Score: 95, Reasons: []string{"source-proof"}},
		},
		Reasons: []string{"source-strong"},
	}
	sink := compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown)
	sink.EvidenceCompleteness = &EvidenceCompleteness{
		TotalScore:   54,
		Label:        EvidenceCompletenessInsufficient,
		EvidenceGaps: []string{"missing sink proof"},
		AxisScores: []EvidenceCompletenessAxisScore{
			{Axis: CompletenessAxisDiscovery, Score: 40, Reasons: []string{"sink-discovery-gap"}},
			{Axis: CompletenessAxisProof, Score: 30, Reasons: []string{"sink-proof-gap"}},
		},
		Reasons: []string{"sink-insufficient"},
	}

	compositions, _ := BuildComposedActionPaths([]ActionPath{source, sink}, nil)
	got := findCompositionByPattern(compositions, CompositionPatternSensitiveReadToEgress)
	if got == nil || got.EvidenceCompleteness == nil {
		t.Fatalf("expected composition evidence completeness, got %+v", got)
		return
	}
	if got.EvidenceCompleteness.TotalScore != 54 || got.EvidenceCompleteness.Label != EvidenceCompletenessInsufficient {
		t.Fatalf("expected composition completeness to conservatively reflect the weaker stage, got %+v", got.EvidenceCompleteness)
	}
	if !containsAnyPathClass(got.EvidenceCompleteness.EvidenceGaps, "missing sink proof") {
		t.Fatalf("expected sink evidence gaps to be preserved, got %+v", got.EvidenceCompleteness)
	}
	if len(got.EvidenceCompleteness.AxisScores) < 2 {
		t.Fatalf("expected aggregated axis scores, got %+v", got.EvidenceCompleteness.AxisScores)
	}
	if got.EvidenceCompleteness.AxisScores[0].Axis != CompletenessAxisDiscovery || got.EvidenceCompleteness.AxisScores[0].Score != 40 {
		t.Fatalf("expected discovery axis to use conservative score, got %+v", got.EvidenceCompleteness.AxisScores)
	}
	if got.EvidenceCompleteness.AxisScores[1].Axis != CompletenessAxisProof || got.EvidenceCompleteness.AxisScores[1].Score != 30 {
		t.Fatalf("expected proof axis to use conservative score, got %+v", got.EvidenceCompleteness.AxisScores)
	}
}

func TestBuildComposedActionPathsCapCountsUniqueCompositionIDs(t *testing.T) {
	t.Parallel()

	paths := make([]ActionPath, 0, maxComposedActionPathCandidates+3)
	for idx := 0; idx < maxComposedActionPathCandidates+1; idx++ {
		source := compositionTestPath("apc-read-dup-"+string(rune('a'+(idx%26))), "rk-read-dup", []string{"read"}, TargetClassCustomerDataAdjacent)
		source.PathID = "apc-read-dup-" + string(rune('a'+(idx%26))) + string(rune('a'+(idx/26)))
		source.Repo = "checkout"
		source.Location = ".github/workflows/release.yml"
		paths = append(paths, source)
	}
	sink := compositionTestPath("apc-egress-dup", "rk-egress-dup", []string{"egress"}, TargetClassUnknown)
	sink.Repo = "checkout"
	paths = append(paths, sink)

	distinctSource := compositionTestPath("apc-read-distinct", "rk-read-distinct", []string{"read"}, TargetClassCustomerDataAdjacent)
	distinctSource.Repo = "payments"
	distinctSink := compositionTestPath("apc-egress-distinct", "rk-egress-distinct", []string{"egress"}, TargetClassUnknown)
	distinctSink.Repo = "payments"
	paths = append(paths, distinctSource, distinctSink)

	compositions, _ := BuildComposedActionPaths(paths, nil)
	if got := findCompositionByPattern(compositions, CompositionPatternSensitiveReadToEgress); got == nil {
		t.Fatalf("expected duplicated composition to still be present, got %+v", compositions)
	}
	foundDistinct := false
	for _, composition := range compositions {
		if composition.ResolutionKey == compositionResolutionKey([]ActionPath{distinctSource, distinctSink}) {
			foundDistinct = true
			break
		}
	}
	if !foundDistinct {
		t.Fatalf("expected distinct composition after duplicate pairs to survive cap accounting, got %+v", compositions)
	}
}

func TestDecorateActionPathCompositionRefs(t *testing.T) {
	paths := []ActionPath{
		compositionTestPath("apc-read", "rk-read", []string{"read"}, TargetClassCustomerDataAdjacent),
		compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown),
	}
	compositions, _ := BuildComposedActionPaths(paths, nil)
	decorated := DecorateActionPathCompositionRefs(paths, compositions)
	for _, path := range decorated {
		if len(path.CompositionIDs) == 0 {
			t.Fatalf("expected composition refs on %s: %+v", path.PathID, decorated)
		}
	}
}

func TestProposedActionContractIncludesCompositionTransitionsAndReportOnly(t *testing.T) {
	paths := []ActionPath{
		compositionTestPath("apc-code", "rk-code", []string{"write"}, TargetClassReleaseAdjacent),
		compositionTestPath("apc-deploy", "rk-deploy", []string{"deploy"}, TargetClassProductionImpacting),
	}
	compositions, _ := BuildComposedActionPaths(paths, nil)
	got := findCompositionByPattern(compositions, CompositionPatternCodeToDeploy)
	if got == nil || got.ProposedActionContract == nil {
		t.Fatalf("expected proposed contract on code-to-deploy composition, got %+v", got)
		return
	}
	contract := got.ProposedActionContract
	if !contract.ReportOnly {
		t.Fatalf("Wrkr proposed contracts must be report-only: %+v", contract)
	}
	if contract.ContractID == "" || contract.ContractFamilyID == "" || contract.ContractContentDigest == "" {
		t.Fatalf("expected stable contract identifiers, got %+v", contract)
	}
	if contract.CompositionRef != got.CompositionID {
		t.Fatalf("expected composition ref %s, got %s", got.CompositionID, contract.CompositionRef)
	}
	if len(contract.ApprovalRequiredTransitions) == 0 {
		t.Fatalf("expected approval-required transition, got %+v", contract)
	}
	if contract.ExpiresAt != "" {
		t.Fatalf("expiry must remain unset without deterministic source, got %q", contract.ExpiresAt)
	}
	if !containsAnyPathClass(contract.ReasonCodes, "expiry:deterministic_source_absent") {
		t.Fatalf("expected absent expiry reason code, got %v", contract.ReasonCodes)
	}
	if contract.ReadinessState != proposedActionContractReadinessNeedsEvidence {
		t.Fatalf("expected schema-valid needs-evidence readiness, got %q reasons=%v preconditions=%+v", contract.ReadinessState, contract.ReasonCodes, contract.Preconditions)
	}
	if contract.RequiredCredentialMode != proposedCredentialModeScoped {
		t.Fatalf("expected schema-valid scoped credential mode, got %q", contract.RequiredCredentialMode)
	}
}

func TestCompositionDelegationRelationshipDetectsBroadenedChildAuthority(t *testing.T) {
	source := compositionTestPath("apc-code", "rk-code", []string{"write"}, TargetClassReleaseAdjacent)
	source.CredentialAuthorityRef = "authority:repo-read"
	source.CredentialAuthority = &agginventory.CredentialAuthority{
		CredentialPresent: true,
		CredentialKind:    "github_token",
		AccessType:        agginventory.AuthorityAccessRead,
		TargetSystem:      "github",
		LikelyScope:       "repo:read",
		ReasonCodes:       []string{"source:repo-read"},
	}
	source.RecommendedControl = RecommendedControlAllow
	source.RecommendedControlReasons = nil

	sink := compositionTestPath("apc-deploy", "rk-deploy", []string{"deploy"}, TargetClassProductionImpacting)
	sink.CredentialAuthorityRef = "authority:prod-admin"
	sink.CredentialAuthority = &agginventory.CredentialAuthority{
		CredentialPresent: true,
		CredentialKind:    "cloud_role",
		AccessType:        agginventory.AuthorityAccessAdmin,
		StandingAccess:    true,
		TargetSystem:      "aws",
		LikelyScope:       "prod:*",
		ReasonCodes:       []string{"sink:prod-admin"},
	}
	sink.RecommendedControl = RecommendedControlApprovalRequired
	sink.RecommendedControlReasons = []string{"sink:approval_required"}

	compositions, _ := BuildComposedActionPaths([]ActionPath{source, sink}, nil)
	got := findCompositionByPattern(compositions, CompositionPatternCodeToDeploy)
	if got == nil || len(got.Transitions) == 0 {
		t.Fatalf("expected code-to-deploy composition with transition, got %+v", got)
		return
	}
	transition := got.Transitions[0]
	if transition.Relationship != CompositionDelegationBroadened {
		t.Fatalf("expected broadened delegation relationship, got %+v", transition)
	}
	if transition.ParentAuthorityRef == "" || transition.ChildAuthorityRef == "" || transition.ParentAuthorityRef == transition.ChildAuthorityRef {
		t.Fatalf("expected distinct parent/child authority refs, got %+v", transition)
	}
	if len(transition.ScopeDelta) == 0 || len(transition.TargetDelta) == 0 || len(transition.CredentialDelta) == 0 {
		t.Fatalf("expected scope/target/credential deltas, got %+v", transition)
	}
	if got.ProposedActionContract == nil || !containsAnyPathClass(got.ProposedActionContract.EvidenceRequirements, "delegation_relationship", "credential_attenuation", "runtime_token_propagation") {
		t.Fatalf("expected proposed contract delegation evidence requirements, got %+v", got.ProposedActionContract)
	}
}

func TestCompositionRecommendationUsesMostRestrictiveTransition(t *testing.T) {
	source := compositionTestPath("apc-code", "rk-code", []string{"write"}, TargetClassReleaseAdjacent)
	source.CredentialAuthorityRef = "authority:repo-write"
	source.CredentialAuthority = &agginventory.CredentialAuthority{CredentialPresent: true, AccessType: agginventory.AuthorityAccessWrite, LikelyScope: "repo"}
	source.RecommendedControl = RecommendedControlAllow
	source.RecommendedControlReasons = []string{"source:allow"}

	sink := compositionTestPath("apc-deploy", "rk-deploy", []string{"deploy"}, TargetClassProductionImpacting)
	sink.CredentialAuthorityRef = "authority:prod-admin"
	sink.CredentialAuthority = &agginventory.CredentialAuthority{CredentialPresent: true, AccessType: agginventory.AuthorityAccessAdmin, StandingAccess: true, LikelyScope: "prod"}
	sink.RecommendedControl = RecommendedControlApprovalRequired
	sink.RecommendedControlReasons = []string{"sink:approval_required"}

	compositions, _ := BuildComposedActionPaths([]ActionPath{source, sink}, nil)
	got := findCompositionByPattern(compositions, CompositionPatternCodeToDeploy)
	if got == nil {
		t.Fatalf("expected composition, got %+v", compositions)
		return
	}
	if got.RecommendedControl != RecommendedControlJITCredentialRequired {
		t.Fatalf("expected broadened transition to select JIT credential control, got %+v", got)
	}
	if len(got.EscalatingTransitionRefs) == 0 || got.MostRestrictiveSource == "" || !containsAnyPathClass(got.RecommendedControlReasons, "composition:delegation_broadened", "sink:approval_required") {
		t.Fatalf("expected transition-level rationale and preserved reasons, got %+v", got)
	}
}

func TestCompositionDelegationTreatsAddedTargetsAsBroadened(t *testing.T) {
	parent := compositionAuthorityProfile{
		Ref:     "authority:repo",
		Targets: []string{"prod:checkout"},
	}
	child := compositionAuthorityProfile{
		Ref:     "authority:repo",
		Targets: []string{"prod:checkout", "prod:billing"},
	}

	relationship, _, targetDelta, _, _, reasons := compareCompositionAuthority(parent, child)
	if relationship != CompositionDelegationBroadened {
		t.Fatalf("expected added targets to broaden delegation, got relationship=%q delta=%v reasons=%v", relationship, targetDelta, reasons)
	}
	if !containsAnyPathClass(targetDelta, "target:added:prod:billing") || !containsAnyPathClass(reasons, "target:broadened") {
		t.Fatalf("expected added target delta to preserve broadened rationale, got delta=%v reasons=%v", targetDelta, reasons)
	}
}

func TestMergeComposedActionPathPreservesDelegationMetadataAfterStageRebuild(t *testing.T) {
	base := ComposedActionPath{
		CompositionID: "cap-1",
		Stages: []CompositionStage{
			{
				StageID:       compositionStageID(CompositionStageRoleSource, "rk-source", TargetClassReleaseAdjacent, EvidenceStateDeclared),
				Role:          CompositionStageRoleSource,
				ResolutionKey: "rk-source",
				TargetClass:   TargetClassReleaseAdjacent,
				EvidenceState: EvidenceStateDeclared,
			},
			{
				StageID:       compositionStageID(CompositionStageRolePrivilegedSink, "rk-sink", TargetClassProductionImpacting, EvidenceStateDeclared),
				Role:          CompositionStageRolePrivilegedSink,
				ResolutionKey: "rk-sink",
				TargetClass:   TargetClassProductionImpacting,
				EvidenceState: EvidenceStateDeclared,
			},
		},
		EvidenceState:        EvidenceStateDeclared,
		PolicyCoverageStatus: PolicyCoverageStatusDeclared,
	}
	base.Transitions = buildCompositionTransitions(base.CompositionID, base.Stages)
	base.Transitions[0].Relationship = CompositionDelegationBroadened
	base.Transitions[0].ParentAuthorityRef = "authority:repo"
	base.Transitions[0].ChildAuthorityRef = "authority:prod"
	base.Transitions[0].TargetDelta = []string{"target:added:prod:billing"}
	base.Transitions[0].ReasonCodes = []string{"target:broadened"}
	base.EscalatingTransitionRefs = []string{base.Transitions[0].TransitionID}
	base.MostRestrictiveSource = "transition:" + base.Transitions[0].TransitionID

	incoming := base
	incoming.Stages = append([]CompositionStage(nil), base.Stages...)
	incoming.Stages[0].EvidenceState = EvidenceStateContradictory
	incoming.Stages[0].StageID = compositionStageID(incoming.Stages[0].Role, incoming.Stages[0].ResolutionKey, incoming.Stages[0].TargetClass, incoming.Stages[0].EvidenceState)
	incoming.Transitions = buildCompositionTransitions(incoming.CompositionID, incoming.Stages)

	merged := mergeComposedActionPath(base, incoming)
	if len(merged.Transitions) != 1 {
		t.Fatalf("expected merged composition to rebuild one transition, got %+v", merged.Transitions)
	}
	transition := merged.Transitions[0]
	if transition.Relationship != CompositionDelegationBroadened {
		t.Fatalf("expected rebuilt transition to preserve broadened delegation, got %+v", transition)
	}
	if transition.ParentAuthorityRef != "authority:repo" || transition.ChildAuthorityRef != "authority:prod" {
		t.Fatalf("expected rebuilt transition to preserve authority refs, got %+v", transition)
	}
	if !containsAnyPathClass(transition.TargetDelta, "target:added:prod:billing") || !containsAnyPathClass(transition.ReasonCodes, "target:broadened") {
		t.Fatalf("expected rebuilt transition to preserve target deltas and reasons, got %+v", transition)
	}
	if !containsAnyPathClass(merged.EscalatingTransitionRefs, transition.TransitionID) || merged.MostRestrictiveSource != "transition:"+transition.TransitionID {
		t.Fatalf("expected rebuilt transition refs to point at merged transition ids, got refs=%v source=%q transition=%+v", merged.EscalatingTransitionRefs, merged.MostRestrictiveSource, transition)
	}
}

func TestEquivalentOutcomeDoesNotGroupUnrelatedRepoActions(t *testing.T) {
	checkoutCode := compositionTestPath("apc-code-checkout", "rk-code-checkout", []string{"write"}, TargetClassReleaseAdjacent)
	checkoutCode.Repo = "checkout"
	checkoutDeploy := compositionTestPath("apc-deploy-checkout", "rk-deploy-checkout", []string{"deploy"}, TargetClassProductionImpacting)
	checkoutDeploy.Repo = "checkout"
	checkoutDeploy.MatchedProductionTargets = []string{"prod:checkout"}

	billingCode := compositionTestPath("apc-code-billing", "rk-code-billing", []string{"write"}, TargetClassReleaseAdjacent)
	billingCode.Repo = "billing"
	billingDeploy := compositionTestPath("apc-deploy-billing", "rk-deploy-billing", []string{"deploy"}, TargetClassProductionImpacting)
	billingDeploy.Repo = "billing"
	billingDeploy.MatchedProductionTargets = []string{"prod:billing"}

	compositions, _ := BuildComposedActionPaths([]ActionPath{checkoutCode, checkoutDeploy, billingCode, billingDeploy}, nil)
	for _, composition := range compositions {
		if len(composition.EquivalentOutcomeRefs) > 0 {
			t.Fatalf("did not expect unrelated repo/target compositions to be grouped, got %+v", composition)
		}
	}
}

func TestEquivalentOutcomeSignalsApprovalEvasionForWeakerRoute(t *testing.T) {
	codeA := compositionTestPath("apc-code-a", "rk-code-a", []string{"write"}, TargetClassReleaseAdjacent)
	codeA.RecommendedControl = RecommendedControlApprovalRequired
	deployA := compositionTestPath("apc-deploy-a", "rk-deploy-a", []string{"deploy"}, TargetClassProductionImpacting)
	deployA.MatchedProductionTargets = []string{"prod:checkout"}
	deployA.CredentialAuthorityRef = "authority:prod-admin-a"
	deployA.CredentialAuthority = &agginventory.CredentialAuthority{CredentialPresent: true, AccessType: agginventory.AuthorityAccessAdmin, TargetSystem: "aws", LikelyScope: "prod:checkout"}
	deployA.PolicyCoverageStatus = PolicyCoverageStatusRuntimeProven
	deployA.ProofEvidenceState = EvidenceStateVerified
	deployA.RuntimeEvidenceState = EvidenceStateVerified
	deployA.RecommendedControl = RecommendedControlApprovalRequired

	codeB := compositionTestPath("apc-code-b", "rk-code-b", []string{"write"}, TargetClassReleaseAdjacent)
	codeB.RecommendedControl = RecommendedControlAllow
	deployB := compositionTestPath("apc-deploy-b", "rk-deploy-b", []string{"deploy"}, TargetClassProductionImpacting)
	deployB.MatchedProductionTargets = []string{"prod:checkout"}
	deployB.CredentialAuthorityRef = "authority:prod-admin-b"
	deployB.CredentialProvenance = &agginventory.CredentialProvenance{Subject: "sts-role", AccessType: agginventory.AuthorityAccessWrite, TargetSystem: "aws", LikelyScope: "prod:checkout"}
	deployB.PolicyCoverageStatus = PolicyCoverageStatusNone
	deployB.ProofEvidenceState = EvidenceStateUnknown
	deployB.RuntimeEvidenceState = EvidenceStateUnknown
	deployB.RecommendedControl = RecommendedControlAllow

	compositions, _ := BuildComposedActionPaths([]ActionPath{codeA, deployA, codeB, deployB}, nil)
	found := false
	for _, composition := range compositions {
		if len(composition.EquivalentOutcomeRefs) == 0 {
			continue
		}
		found = true
		if composition.Materiality != CompositionMaterialityMaterial || len(composition.CoverageDeltaReasons) == 0 {
			t.Fatalf("expected material bounded equivalent-outcome deltas, got %+v", composition)
		}
	}
	if !found {
		t.Fatalf("expected equivalent outcome refs, got %+v", compositions)
	}
}

func TestEquivalentOutcomeControlParityRaisesWeakerRouteOnceAndRebuildsContract(t *testing.T) {
	weaker := ComposedActionPath{
		CompositionID:      "cap-weaker",
		OutcomeKey:         "outcome:prod:checkout",
		DurableOutcomeKey:  "outcome:prod:checkout",
		OutcomeClass:       "production_deploy",
		TargetIdentity:     "prod:checkout",
		TargetClass:        TargetClassProductionImpacting,
		RecommendedControl: RecommendedControlAllow,
		Stages: []CompositionStage{
			{StageID: "source", Role: CompositionStageRoleSource},
			{StageID: "sink", Role: CompositionStageRolePrivilegedSink},
		},
	}
	stronger := weaker
	stronger.CompositionID = "cap-stronger"
	stronger.RecommendedControl = RecommendedControlBlock
	stronger.TargetClass = TargetClassProductionImpacting

	compositions := []ComposedActionPath{weaker, stronger}
	annotateEquivalentOutcomeSignals(compositions)

	got := compositions[0]
	if got.RecommendedControl != RecommendedControlBlock {
		t.Fatalf("expected weaker equivalent route to raise to block, got %q", got.RecommendedControl)
	}
	if got.EquivalentOutcomeEscalationSource != "peer:cap-stronger" {
		t.Fatalf("expected stable parity source, got %q", got.EquivalentOutcomeEscalationSource)
	}
	if !containsAnyPathClass(got.RecommendedControlReasons, "composition:equivalent_outcome_control_parity") {
		t.Fatalf("expected exactly one canonical parity reason, got %v", got.RecommendedControlReasons)
	}
	if got.ProposedActionContract == nil || !containsAnyPathClass(got.ProposedActionContract.ReasonCodes, "composition:equivalent_outcome_control_parity") {
		t.Fatalf("expected rebuilt proposed contract to identify parity, got %+v", got.ProposedActionContract)
	}

	// Reversing input must preserve the exact result and must not cause the
	// raised route to feed a reciprocal second pass.
	reversed := []ComposedActionPath{stronger, weaker}
	annotateEquivalentOutcomeSignals(reversed)
	for _, composition := range reversed {
		if composition.CompositionID != "cap-weaker" {
			continue
		}
		if composition.RecommendedControl != RecommendedControlBlock || composition.EquivalentOutcomeEscalationSource != "peer:cap-stronger" {
			t.Fatalf("expected order-independent parity result, got %+v", composition)
		}
	}
}

func TestEquivalentOutcomeControlParityFailsClosedForUnknownControl(t *testing.T) {
	unknown := ComposedActionPath{
		CompositionID:      "cap-unknown",
		OutcomeKey:         "outcome:prod:checkout",
		DurableOutcomeKey:  "outcome:prod:checkout",
		OutcomeClass:       "production_deploy",
		TargetIdentity:     "prod:checkout",
		TargetClass:        TargetClassProductionImpacting,
		RecommendedControl: "future_unranked_control",
	}
	known := unknown
	known.CompositionID = "cap-known"
	known.RecommendedControl = RecommendedControlAllow

	compositions := []ComposedActionPath{unknown, known}
	annotateEquivalentOutcomeSignals(compositions)
	if compositions[0].RecommendedControl != RecommendedControlBlock {
		t.Fatalf("expected unknown control to fail closed to block, got %q", compositions[0].RecommendedControl)
	}
	if !containsAnyPathClass(compositions[0].RecommendedControlReasons, "composition:unknown_recommended_control") {
		t.Fatalf("expected fail-closed reason, got %v", compositions[0].RecommendedControlReasons)
	}
}

func TestProposedActionContractReadinessMapsSpecificGapsToNeedsEvidence(t *testing.T) {
	base := ComposedActionPath{
		CompositionID: "cap-1",
		Stages: []CompositionStage{
			{StageID: "stage-1", Role: CompositionStageRoleSource},
			{StageID: "stage-2", Role: CompositionStageRoleExternalSink},
		},
	}

	readiness, reasons := proposedActionContractReadiness(ComposedActionPath{
		CompositionID: "cap-correlation",
		Stages:        base.Stages[:1],
	})
	if readiness != proposedActionContractReadinessNeedsEvidence {
		t.Fatalf("expected schema-valid needs-evidence readiness for correlation gap, got %q", readiness)
	}
	if !containsAnyPathClass(reasons, "readiness:needs_composition_correlation") {
		t.Fatalf("expected correlation reason code, got %v", reasons)
	}

	readiness, reasons = proposedActionContractReadiness(ComposedActionPath{
		CompositionID:        "cap-2",
		Stages:               base.Stages,
		EvidenceState:        EvidenceStateUnknown,
		PolicyCoverageStatus: PolicyCoverageStatusDeclared,
	})
	if readiness != proposedActionContractReadinessNeedsEvidence {
		t.Fatalf("expected schema-valid needs-evidence readiness for proof gap, got %q", readiness)
	}
	if !containsAnyPathClass(reasons, "readiness:needs_proof_evidence") {
		t.Fatalf("expected proof reason code, got %v", reasons)
	}

	readiness, reasons = proposedActionContractReadiness(ComposedActionPath{
		CompositionID:        "cap-3",
		Stages:               base.Stages,
		EvidenceState:        EvidenceStateDeclared,
		PolicyCoverageStatus: PolicyCoverageStatusNone,
	})
	if readiness != proposedActionContractReadinessNeedsEvidence {
		t.Fatalf("expected schema-valid needs-evidence readiness for policy gap, got %q", readiness)
	}
	if !containsAnyPathClass(reasons, "readiness:needs_policy_evidence") {
		t.Fatalf("expected policy reason code, got %v", reasons)
	}

	readiness, reasons = proposedActionContractReadiness(ComposedActionPath{
		CompositionID:        "cap-4",
		Stages:               base.Stages,
		EvidenceState:        EvidenceStateDeclared,
		PolicyCoverageStatus: PolicyCoverageStatusStale,
	})
	if readiness != proposedActionContractReadinessNeedsEvidence {
		t.Fatalf("expected stale policy to remain an evidence gap, got %q", readiness)
	}
	if !containsAnyPathClass(reasons, "readiness:needs_policy_evidence") {
		t.Fatalf("expected stale policy reason code, got %v", reasons)
	}

	readiness, reasons = proposedActionContractReadiness(ComposedActionPath{
		CompositionID:        "cap-5",
		Stages:               base.Stages,
		EvidenceState:        EvidenceStateDeclared,
		PolicyCoverageStatus: PolicyCoverageStatusMatched,
		FreshnessState:       evidencepolicy.FreshnessStateExpired,
	})
	if readiness != proposedActionContractReadinessNeedsEvidence {
		t.Fatalf("expected stale freshness to remain an evidence gap, got %q", readiness)
	}
	if !containsAnyPathClass(reasons, "readiness:needs_fresh_evidence") {
		t.Fatalf("expected freshness reason code, got %v", reasons)
	}
}

func TestMergeComposedActionPathRevalidatesObservedExecutionAfterDuplicates(t *testing.T) {
	t.Parallel()

	current := ComposedActionPath{
		CompositionID:        "cap-1",
		ClaimState:           CompositionClaimObservedExecution,
		EvidenceState:        EvidenceStateDeclared,
		PolicyCoverageStatus: PolicyCoverageStatusDeclared,
		FreshnessState:       evidencepolicy.FreshnessStateFresh,
		GaitCoverage: &GaitCoverage{
			ActionOutcome: GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"runtime:sequence"}},
		},
		Stages: []CompositionStage{
			{
				StageID:        "stage-1",
				Role:           CompositionStageRoleSource,
				FreshnessState: evidencepolicy.FreshnessStateFresh,
				GaitCoverage: &GaitCoverage{
					ActionOutcome: GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"runtime:source"}},
				},
			},
			{
				StageID:        "stage-2",
				Role:           CompositionStageRoleExternalSink,
				FreshnessState: evidencepolicy.FreshnessStateFresh,
				GaitCoverage: &GaitCoverage{
					ActionOutcome: GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"runtime:sink"}},
				},
			},
		},
	}
	incoming := ComposedActionPath{
		CompositionID:        "cap-1",
		EvidenceState:        EvidenceStateDeclared,
		PolicyCoverageStatus: PolicyCoverageStatusDeclared,
		FreshnessState:       evidencepolicy.FreshnessStateFresh,
		GaitCoverage: &GaitCoverage{
			ActionOutcome: GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"runtime:sequence"}},
		},
		Stages: []CompositionStage{
			{
				StageID:        "stage-1",
				Role:           CompositionStageRoleSource,
				FreshnessState: evidencepolicy.FreshnessStateFresh,
				GaitCoverage: &GaitCoverage{
					ActionOutcome: GaitCoverageDetail{Status: GaitStatusMissing},
				},
			},
			{
				StageID:        "stage-2",
				Role:           CompositionStageRoleExternalSink,
				FreshnessState: evidencepolicy.FreshnessStateFresh,
				GaitCoverage: &GaitCoverage{
					ActionOutcome: GaitCoverageDetail{Status: GaitStatusPresent, EvidenceRefs: []string{"runtime:sink"}},
				},
			},
		},
	}

	merged := mergeComposedActionPath(current, incoming)
	if merged.ClaimState == CompositionClaimObservedExecution {
		t.Fatalf("expected merged duplicate without full stage runtime proof to drop observed_execution, got %+v", merged)
	}
}

func TestBuildComposedActionPathsSurfacesTruncation(t *testing.T) {
	paths := make([]ActionPath, 0, 24)
	for idx := 0; idx < 12; idx++ {
		paths = append(paths, compositionTestPath("apc-read-"+string(rune('a'+idx)), "rk-read-"+string(rune('a'+idx)), []string{"read"}, TargetClassCustomerDataAdjacent))
		paths = append(paths, compositionTestPath("apc-egress-"+string(rune('a'+idx)), "rk-egress-"+string(rune('a'+idx)), []string{"egress"}, TargetClassUnknown))
	}

	compositions, choice := BuildComposedActionPaths(paths, nil)
	if len(compositions) != maxComposedActionPathCandidates {
		t.Fatalf("expected composition cap at %d, got %d", maxComposedActionPathCandidates, len(compositions))
	}
	if choice == nil || choice.Summary.TruncatedCandidatePatterns != 1 {
		t.Fatalf("expected one truncated pattern in summary, got %+v", choice)
	}
	flagged := 0
	for _, composition := range compositions {
		if len(composition.TruncatedCandidates) > 0 {
			flagged++
		}
	}
	if flagged != 1 {
		t.Fatalf("expected one representative composition to carry truncation evidence, got %d", flagged)
	}
}

func TestBuildComposedActionPathsSkipsContextOnlyCandidates(t *testing.T) {
	t.Parallel()

	contextOnlySource := ProjectActionPath(ActionPath{
		PathID:   "appendix-openapi",
		Org:      "acme",
		Repo:     "checkout",
		ToolType: "openapi",
		Location: "openapi/customer-export.yaml",
		PathContext: &agginventory.PathContext{
			Kind:       agginventory.PathContextRuntimeSource,
			Confidence: "high",
		},
		MutableEndpointSemantics: []agginventory.MutableEndpointSemantic{{
			Semantic:     agginventory.EndpointSemanticDataExport,
			Confidence:   "high",
			Surface:      "openapi",
			Operation:    "GET /v1/customers/export",
			EvidenceRefs: []string{"GET /v1/customers/export"},
		}},
	})
	if contextOnlySource.ActionPathEligible {
		t.Fatalf("expected appendix-only openapi path to stay out of action-path composition, got %+v", contextOnlySource)
	}
	if contextOnlySource.ConfidenceLane != ConfidenceLaneContextOnly {
		t.Fatalf("expected appendix-only openapi path to stay context_only, got %+v", contextOnlySource)
	}

	compositions, _ := BuildComposedActionPaths([]ActionPath{contextOnlySource}, nil)
	if got := findCompositionByPattern(compositions, CompositionPatternSensitiveReadToEgress); got != nil {
		t.Fatalf("expected context-only appendix path to stay out of composed contracts, got %+v", got)
	}
}

func TestMergeComposedActionPathRebuildsProposedContract(t *testing.T) {
	base := ComposedActionPath{
		CompositionID:  "cap-1",
		ResolutionKey:  "rk",
		TargetIdentity: "prod",
		OutcomeClass:   "production_deploy",
		TargetClass:    TargetClassProductionImpacting,
		Environment:    "production",
		Stages: []CompositionStage{
			{
				StageID:              compositionStageID(CompositionStageRoleSource, "rk-source", TargetClassProductionImpacting, EvidenceStateDeclared),
				Role:                 CompositionStageRoleSource,
				ResolutionKey:        "rk-source",
				TargetClass:          TargetClassProductionImpacting,
				EvidenceState:        EvidenceStateDeclared,
				PolicyCoverageStatus: PolicyCoverageStatusDeclared,
			},
			{
				StageID:              compositionStageID(CompositionStageRolePrivilegedSink, "rk-sink", TargetClassProductionImpacting, EvidenceStateDeclared),
				Role:                 CompositionStageRolePrivilegedSink,
				ResolutionKey:        "rk-sink",
				TargetClass:          TargetClassProductionImpacting,
				EvidenceState:        EvidenceStateDeclared,
				PolicyCoverageStatus: PolicyCoverageStatusDeclared,
			},
		},
		EvidenceState:        EvidenceStateDeclared,
		PolicyCoverageStatus: PolicyCoverageStatusDeclared,
		RecommendedControl:   RecommendedControlApprovalRequired,
	}
	base.Transitions = buildCompositionTransitions(base.CompositionID, base.Stages)
	base.ProposedActionContract = BuildProposedActionContract(base)
	base.ProposedActionContractRefs = []string{base.ProposedActionContract.ContractID}

	incoming := base
	incoming.Stages[0].EvidenceState = EvidenceStateContradictory
	incoming.Stages[0].StageID = compositionStageID(incoming.Stages[0].Role, incoming.Stages[0].ResolutionKey, incoming.Stages[0].TargetClass, incoming.Stages[0].EvidenceState)
	incoming.Transitions = buildCompositionTransitions(incoming.CompositionID, incoming.Stages)
	incoming.EvidenceState = EvidenceStateContradictory
	incoming.ClaimState = CompositionClaimContradictory
	incoming.RecommendedControl = RecommendedControlBlock

	merged := mergeComposedActionPath(base, incoming)
	if merged.ProposedActionContract == nil {
		t.Fatalf("expected merged proposed contract, got %+v", merged)
	}
	if len(merged.Stages) != 2 || merged.Stages[0].EvidenceState != EvidenceStateContradictory {
		t.Fatalf("expected merged stages to reflect strongest evidence state, got %+v", merged.Stages)
	}
	if len(merged.Transitions) != 1 || merged.Transitions[0].FromStageID != merged.Stages[0].StageID {
		t.Fatalf("expected transitions to be rebuilt from merged stages, got %+v with stages %+v", merged.Transitions, merged.Stages)
	}
	if merged.Transitions[0].ClaimState != merged.ClaimState || len(merged.Transitions[0].ReasonCodes) == 0 {
		t.Fatalf("expected rebuilt transitions to carry merged audit context, got %+v", merged.Transitions[0])
	}
	if merged.ProposedActionContract.ReadinessState != ActionContractReadinessBlockedContradict {
		t.Fatalf("expected merged contract to reflect contradictory state, got %+v", merged.ProposedActionContract)
	}
	if len(merged.ProposedActionContractRefs) != 1 || merged.ProposedActionContractRefs[0] != merged.ProposedActionContract.ContractID {
		t.Fatalf("expected merged contract refs to be rebuilt, got %+v", merged.ProposedActionContractRefs)
	}
}

func TestProposedApprovalRequiredTransitionsSkipsProhibitedTransitions(t *testing.T) {
	transitions := []ProposedActionTransition{{TransitionID: "transition-1", FromStageID: "stage-1", ToStageID: "stage-2"}}
	got := proposedApprovalRequiredTransitions(ComposedActionPath{
		ClaimState:         CompositionClaimContradictory,
		RecommendedControl: RecommendedControlBlock,
	}, transitions)
	if got != nil {
		t.Fatalf("expected prohibited transitions to stay out of approval-required set, got %+v", got)
	}
}

func TestProposedAllowedTransitionsSkipsProhibitedTransitions(t *testing.T) {
	transitions := []ProposedActionTransition{{TransitionID: "transition-1", FromStageID: "stage-1", ToStageID: "stage-2"}}
	got := proposedAllowedTransitions(ComposedActionPath{
		ClaimState:         CompositionClaimObservedExecution,
		RecommendedControl: RecommendedControlBlock,
	}, transitions)
	if got != nil {
		t.Fatalf("expected prohibited transitions to stay out of allowed set, got %+v", got)
	}
}

func TestCompositionEvidenceStateSeedsFirstConcreteStage(t *testing.T) {
	if got := compositionEvidenceState("", EvidenceStateDeclared); got != EvidenceStateDeclared {
		t.Fatalf("expected first concrete evidence state to seed aggregation, got %q", got)
	}
}

func TestCompositionFreshnessStateSeedsFirstConcreteStage(t *testing.T) {
	if got := compositionFreshnessState("", evidencepolicy.FreshnessStateFresh); got != evidencepolicy.FreshnessStateFresh {
		t.Fatalf("expected first concrete freshness state to seed aggregation, got %q", got)
	}
}

func TestCompositionPolicyCoverageStatusPreservesMissingStageGap(t *testing.T) {
	if got := compositionPolicyCoverageStatusFromStages([]CompositionStage{
		{PolicyCoverageStatus: PolicyCoverageStatusDeclared},
		{PolicyCoverageStatus: PolicyCoverageStatusNone},
	}); got != PolicyCoverageStatusNone {
		t.Fatalf("expected missing stage policy to keep composition coverage at none, got %q", got)
	}
}

func TestMergeComposedActionPathPreservesContradictionOverObservedExecution(t *testing.T) {
	current := ComposedActionPath{
		CompositionID: "cap-1",
		ClaimState:    CompositionClaimObservedExecution,
		Stages: []CompositionStage{
			{StageID: "stage-1", Role: CompositionStageRoleSource},
			{StageID: "stage-2", Role: CompositionStageRolePrivilegedSink},
		},
	}
	incoming := ComposedActionPath{
		CompositionID:        "cap-1",
		EvidenceState:        EvidenceStateContradictory,
		PolicyCoverageStatus: PolicyCoverageStatusConflict,
		Stages: []CompositionStage{
			{StageID: "stage-1", Role: CompositionStageRoleSource},
			{StageID: "stage-2", Role: CompositionStageRolePrivilegedSink},
		},
	}
	merged := mergeComposedActionPath(current, incoming)
	if merged.ClaimState != CompositionClaimContradictory {
		t.Fatalf("expected contradiction to dominate observed execution, got %+v", merged)
	}
}

func compositionTestPath(pathID, resolutionKey string, actionClasses []string, targetClass string) ActionPath {
	return ProjectActionPath(ActionPath{
		PathID:                   pathID,
		Org:                      "acme",
		Repo:                     "checkout",
		ToolType:                 "ci_agent",
		Location:                 ".github/workflows/release.yml",
		ResolutionKey:            resolutionKey,
		WriteCapable:             containsAnyPathClass(actionClasses, "write"),
		DeployWrite:              containsAnyPathClass(actionClasses, "deploy"),
		ProductionWrite:          targetClass == TargetClassProductionImpacting,
		CredentialAccess:         containsAnyPathClass(actionClasses, "secret", "credential"),
		ActionClasses:            actionClasses,
		TargetClass:              targetClass,
		MatchedProductionTargets: targetForClass(targetClass),
		PolicyCoverageStatus:     PolicyCoverageStatusDeclared,
		ApprovalEvidenceState:    EvidenceStateDeclared,
		OwnerEvidenceState:       EvidenceStateDeclared,
		ProofEvidenceState:       EvidenceStateUnknown,
		RuntimeEvidenceState:     EvidenceStateUnknown,
		TargetEvidenceState:      EvidenceStateDeclared,
		CredentialEvidenceState:  EvidenceStateDeclared,
		GaitCoverage: &GaitCoverage{
			PolicyDecision:    GaitCoverageDetail{Status: GaitStatusMissing},
			Approval:          GaitCoverageDetail{Status: GaitStatusMissing},
			JITCredential:     GaitCoverageDetail{Status: GaitStatusMissing},
			FreezeWindow:      GaitCoverageDetail{Status: GaitStatusNotApplicable},
			KillSwitch:        GaitCoverageDetail{Status: GaitStatusNotApplicable},
			ActionOutcome:     GaitCoverageDetail{Status: GaitStatusMissing},
			ProofVerification: GaitCoverageDetail{Status: GaitStatusMissing},
		},
		MutableEndpointSemantics: []agginventory.MutableEndpointSemantic{{
			Semantic: semanticForAction(actionClasses),
			Surface:  "api",
		}},
	})
}

func semanticForAction(actionClasses []string) string {
	switch {
	case containsAnyPathClass(actionClasses, "egress", "network"):
		return agginventory.EndpointSemanticDataExport
	case containsAnyPathClass(actionClasses, "read"):
		return agginventory.EndpointSemanticRead
	default:
		return agginventory.EndpointSemanticWrite
	}
}

func targetForClass(targetClass string) []string {
	if targetClass == TargetClassProductionImpacting {
		return []string{"prod:checkout"}
	}
	return nil
}

func findCompositionByPattern(paths []ComposedActionPath, patternID string) *ComposedActionPath {
	for idx := range paths {
		if paths[idx].PatternID == patternID {
			return &paths[idx]
		}
	}
	return nil
}
