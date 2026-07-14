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
	}
	if got.ClaimState == CompositionClaimRuntimeControlled || got.ClaimState == CompositionClaimObservedExecution {
		t.Fatalf("declared policy and missing runtime coverage must not imply control, got %q", got.ClaimState)
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
		t.Fatalf("expected schema-valid needs-evidence readiness, got %q", contract.ReadinessState)
	}
	if contract.RequiredCredentialMode != proposedCredentialModeScoped {
		t.Fatalf("expected schema-valid scoped credential mode, got %q", contract.RequiredCredentialMode)
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
