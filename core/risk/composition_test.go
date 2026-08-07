package risk

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
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

func TestCompositionCandidateFallbackTargetIdentityNormalizesValues(t *testing.T) {
	tests := []struct {
		name                             string
		sourceTargetClass, sourceOrgRepo string
		sinkTargetClass, sinkOrgRepo     string
		want                             string
	}{
		{
			name:              "sorts and deduplicates",
			sourceTargetClass: "cloud",
			sourceOrgRepo:     "acme/payments",
			sinkTargetClass:   "cloud",
			sinkOrgRepo:       "acme/payments",
			want:              "acme/payments+cloud",
		},
		{
			name:            "skips empty values",
			sourceOrgRepo:   "acme/payments",
			sinkTargetClass: "production",
			want:            "acme/payments+production",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := compositionCandidateFallbackTargetIdentity(test.sourceTargetClass, test.sourceOrgRepo, test.sinkTargetClass, test.sinkOrgRepo)
			if got != test.want {
				t.Fatalf("compositionCandidateFallbackTargetIdentity() = %q, want %q", got, test.want)
			}
		})
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

func TestBuildComposedActionPathsContextStopsBeforeAnalysis(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := BuildComposedActionPathsContext(ctx, []ActionPath{
		compositionTestPath("apc-read", "rk-read", []string{"read"}, TargetClassCustomerDataAdjacent),
		compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown),
	}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected canceled composition build, got %v", err)
	}
}

func TestBuildComposedActionPathsContextSkipsCrossScopeCandidatePairs(t *testing.T) {
	const candidatesPerSide = 24
	paths := make([]ActionPath, 0, candidatesPerSide*2)
	for index := 0; index < candidatesPerSide; index++ {
		source := compositionTestPath(fmt.Sprintf("apc-read-%02d", index), fmt.Sprintf("rk-read-%02d", index), []string{"read"}, TargetClassCustomerDataAdjacent)
		source.Repo = fmt.Sprintf("read-repo-%02d", index)
		paths = append(paths, source)

		sink := compositionTestPath(fmt.Sprintf("apc-egress-%02d", index), fmt.Sprintf("rk-egress-%02d", index), []string{"egress"}, TargetClassUnknown)
		sink.Repo = fmt.Sprintf("egress-repo-%02d", index)
		paths = append(paths, sink)
	}

	ctx := &deadlineAfterCallsContext{Context: context.Background(), allowedCalls: 700}
	compositions, choice, err := BuildComposedActionPathsContext(ctx, paths, nil)
	if err != nil {
		t.Fatalf("BuildComposedActionPathsContext() error = %v", err)
	}
	if len(compositions) == 0 || choice == nil {
		t.Fatalf("expected same-scope egress self-compositions, got compositions=%+v choice=%+v", compositions, choice)
	}
	for _, composition := range compositions {
		for _, pathID := range composition.PathIDs {
			if strings.HasPrefix(pathID, "apc-read-") {
				t.Fatalf("cross-scope read candidate was composed: %+v", composition)
			}
		}
	}
}

func TestProjectActionPathsContextHonorsCancellationDuringProjectionAndSort(t *testing.T) {
	paths := []ActionPath{
		compositionTestPath("apc-read", "rk-read", []string{"read"}, TargetClassCustomerDataAdjacent),
		compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown),
		compositionTestPath("apc-write", "rk-write", []string{"write"}, TargetClassReleaseAdjacent),
	}

	projectionCtx := &deadlineAfterCallsContext{Context: context.Background(), allowedCalls: 1}
	if _, err := ProjectActionPathsContext(projectionCtx, paths); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("projection cancellation error = %v, want deadline exceeded", err)
	}

	sortCtx := &deadlineAfterCallsContext{Context: context.Background(), allowedCalls: len(paths) + 2}
	if _, err := ProjectActionPathsContext(sortCtx, paths); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("sort cancellation error = %v, want deadline exceeded", err)
	}
}

func TestBuildComposedActionPathsBoundsSuppressedCandidateEvidence(t *testing.T) {
	paths := make([]ActionPath, 0, 40)
	for index := 0; index < 20; index++ {
		paths = append(paths,
			compositionTestPath(fmt.Sprintf("apc-read-%02d", index), fmt.Sprintf("rk-read-%02d", index), []string{"read"}, TargetClassCustomerDataAdjacent),
			compositionTestPath(fmt.Sprintf("apc-egress-%02d", index), fmt.Sprintf("rk-egress-%02d", index), []string{"egress"}, TargetClassUnknown),
		)
	}

	compositions, _ := BuildComposedActionPaths(paths, nil)
	if len(compositions) != maxComposedActionPathCandidates {
		t.Fatalf("expected %d retained compositions, got %d", maxComposedActionPathCandidates, len(compositions))
	}
	composition := findCompositionByPattern(compositions, CompositionPatternSensitiveReadToEgress)
	if composition == nil {
		t.Fatalf("expected %s composition", CompositionPatternSensitiveReadToEgress)
		return
	}
	if len(composition.TruncatedCandidates) > maxComposedActionPathTruncatedCandidates {
		t.Fatalf("truncated candidate examples = %d, want <= %d", len(composition.TruncatedCandidates), maxComposedActionPathTruncatedCandidates)
	}
	var receipt *CompositionTruncation
	for index := range composition.Truncations {
		candidate := composition.Truncations[index]
		if candidate.Reason == CompositionTruncationCandidateCap && candidate.Limit == maxComposedActionPathCandidates {
			receipt = &candidate
			break
		}
	}
	if receipt == nil {
		t.Fatalf("expected candidate cap receipt, got %+v", composition.Truncations)
		return
	}
	if receipt.ObservedCandidates <= maxComposedActionPathCandidates || receipt.OmittedCandidates != receipt.ObservedCandidates-maxComposedActionPathCandidates {
		t.Fatalf("unexpected suppression receipt %+v", receipt)
	}
}

func TestBuildComposedActionPathsBoundsDuplicateCandidateEvaluation(t *testing.T) {
	paths := make([]ActionPath, 0, maxComposedActionPathCandidateEvaluations+2)
	for index := 0; index < maxComposedActionPathCandidateEvaluations+1; index++ {
		source := compositionTestPath(fmt.Sprintf("apc-read-%04d", index), fmt.Sprintf("rk-read-%04d", index), []string{"read"}, TargetClassCustomerDataAdjacent)
		source.Repo = "checkout"
		paths = append(paths, source)
	}
	sink := compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown)
	sink.Repo = "checkout"
	paths = append(paths, sink)

	compositions, _ := BuildComposedActionPaths(paths, nil)
	composition := findCompositionByPattern(compositions, CompositionPatternSensitiveReadToEgress)
	if composition == nil {
		t.Fatalf("expected %s composition", CompositionPatternSensitiveReadToEgress)
		return
	}
	var receipt *CompositionTruncation
	for index := range composition.Truncations {
		candidate := composition.Truncations[index]
		if candidate.Reason == CompositionTruncationCandidateCap && candidate.Limit == maxComposedActionPathCandidates {
			receipt = &candidate
			break
		}
	}
	if receipt == nil || receipt.OmittedCandidates == 0 {
		t.Fatalf("expected candidate cap receipt, got %+v", composition.Truncations)
		return
	}
	if receipt.ObservedCandidates != maxComposedActionPathCandidates+receipt.OmittedCandidates {
		t.Fatalf("observed candidates = %d, want emitted %d plus omitted %d", receipt.ObservedCandidates, maxComposedActionPathCandidates, receipt.OmittedCandidates)
	}
	if len(composition.PathIDs) > maxOutputEvidenceRefs {
		t.Fatalf("path ids = %d, want <= %d", len(composition.PathIDs), maxOutputEvidenceRefs)
	}
}

func TestBuildComposedActionPathsPreservesGroupedDuplicateMembershipBeyondEvaluationCap(t *testing.T) {
	duplicateCount := maxComposedActionPathCandidateEvaluations + 1
	paths := make([]ActionPath, 0, duplicateCount+1)
	for index := 0; index < duplicateCount; index++ {
		source := compositionTestPath(fmt.Sprintf("apc-read-%04d", index), "rk-read-shared", []string{"read"}, TargetClassCustomerDataAdjacent)
		source.Repo = "checkout"
		paths = append(paths, source)
	}
	sink := compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown)
	sink.Repo = "checkout"
	paths = append(paths, sink)

	compositions, _ := BuildComposedActionPaths(paths, nil)
	expectedCompositionID := buildComposedActionPath(compositionPatternSpecs()[0], paths[0], sink, nil).CompositionID
	composition := findCompositionByID(compositions, expectedCompositionID)
	if composition == nil {
		t.Fatalf("expected %s composition %s", CompositionPatternSensitiveReadToEgress, expectedCompositionID)
	}
	if got, want := len(composition.memberPathIDs), duplicateCount+1; got != want {
		t.Fatalf("internal membership path ids = %d, want %d", got, want)
	}
	if len(composition.PathIDs) > maxOutputEvidenceRefs {
		t.Fatalf("serialized path ids = %d, want <= %d", len(composition.PathIDs), maxOutputEvidenceRefs)
	}

	decorated, err := DecorateActionPathCompositionRefsContext(context.Background(), paths, compositions)
	if err != nil {
		t.Fatalf("DecorateActionPathCompositionRefsContext() error = %v", err)
	}
	for _, path := range decorated {
		if !containsAnyPathClass(path.CompositionIDs, composition.CompositionID) {
			t.Fatalf("path %s is missing composition membership: %+v", path.PathID, path)
		}
		if len(path.ProposedActionContractRefs) == 0 {
			t.Fatalf("path %s is missing proposed action contract membership: %+v", path.PathID, path)
		}
	}
}

func TestBuildComposedActionPathsKeepsOutcomeDistinctCandidatesSeparate(t *testing.T) {
	paymentRead := compositionTestPath("apc-payment-read", "rk-read-shared", []string{"read"}, TargetClassCustomerDataAdjacent)
	paymentRead.MatchedProductionTargets = []string{"production:payments"}
	paymentRead.EndpointRefGroupID = "payments-api"
	paymentRead.MutableEndpointSemantics = []agginventory.MutableEndpointSemantic{{
		Semantic:  agginventory.EndpointSemanticRead,
		Surface:   "openapi",
		Operation: "GET /payments",
	}}
	billingRead := compositionTestPath("apc-billing-read", "rk-read-shared", []string{"read"}, TargetClassCustomerDataAdjacent)
	billingRead.MatchedProductionTargets = []string{"production:billing"}
	billingRead.EndpointRefGroupID = "billing-api"
	billingRead.MutableEndpointSemantics = []agginventory.MutableEndpointSemantic{{
		Semantic:  agginventory.EndpointSemanticRead,
		Surface:   "openapi",
		Operation: "GET /billing",
	}}
	egress := compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown)

	paths := []ActionPath{paymentRead, billingRead, egress}
	compositions, _ := BuildComposedActionPaths(paths, nil)
	byProductionTarget := map[string]*ComposedActionPath{}
	for index := range compositions {
		composition := &compositions[index]
		if composition.PatternID != CompositionPatternSensitiveReadToEgress {
			continue
		}
		for _, target := range []string{"production:payments", "production:billing"} {
			if strings.Contains(composition.TargetIdentity, target) {
				byProductionTarget[target] = composition
			}
		}
	}
	if got, want := len(byProductionTarget), 2; got != want {
		t.Fatalf("sensitive-read compositions = %d, want %d: %+v", got, want, compositions)
	}
	for target, pathID := range map[string]string{
		"production:payments": paymentRead.PathID,
		"production:billing":  billingRead.PathID,
	} {
		composition := byProductionTarget[target]
		if composition == nil {
			t.Fatalf("missing composition for %s: %+v", target, compositions)
		}
		if !containsAnyPathClass(composition.memberPathIDs, pathID) {
			t.Fatalf("composition for %s did not retain %s: %+v", target, pathID, composition)
		}
	}

	decorated, err := DecorateActionPathCompositionRefsContext(context.Background(), paths, compositions)
	if err != nil {
		t.Fatalf("DecorateActionPathCompositionRefsContext() error = %v", err)
	}
	for pathID, target := range map[string]string{
		paymentRead.PathID: "production:payments",
		billingRead.PathID: "production:billing",
	} {
		var path *ActionPath
		for index := range decorated {
			if decorated[index].PathID == pathID {
				path = &decorated[index]
				break
			}
		}
		if path == nil {
			t.Fatalf("missing decorated path %s", pathID)
		}
		if !containsAnyPathClass(path.CompositionIDs, byProductionTarget[target].CompositionID) {
			t.Fatalf("path %s has wrong composition target: %+v", pathID, path)
		}
	}
}

func TestBuildComposedActionPathsKeepsGovernanceDistinctCandidatesSeparate(t *testing.T) {
	governedRead := compositionTestPath("apc-governed-read", "rk-read-shared", []string{"read"}, TargetClassCustomerDataAdjacent)
	governedRead.PolicyCoverageStatus = PolicyCoverageStatusMatched
	governedRead.ControlEvidenceRefs = []string{"evidence:governed-read"}
	governedRead.CredentialAuthorityRef = "authority:read"
	governedRead.CredentialAuthority = &agginventory.CredentialAuthority{
		CredentialPresent: true,
		AccessType:        agginventory.AuthorityAccessRead,
		LikelyScope:       "customer-data:read",
	}

	weakerRead := governedRead
	weakerRead.PathID = "apc-weaker-read"
	weakerRead.PolicyCoverageStatus = PolicyCoverageStatusDeclared
	weakerRead.ControlEvidenceRefs = []string{"evidence:weaker-read"}
	weakerRead.CredentialAuthorityRef = "authority:read-weaker"
	weakerRead.CredentialAuthority = &agginventory.CredentialAuthority{
		CredentialPresent: true,
		AccessType:        agginventory.AuthorityAccessRead,
		LikelyScope:       "customer-data:read",
		ReasonCodes:       []string{"authority:weaker"},
	}
	contradictoryCandidate := governedRead
	contradictoryCandidate.PathID = "apc-contradictory-read"
	contradictoryCandidate.Contradictions = []evidencepolicy.Contradiction{{
		Class:             "credential_policy_conflict",
		ReasonCodes:       []string{"policy:conflicting_credential_authority"},
		EvidenceRefs:      []string{"evidence:credential-conflict"},
		RecommendedAction: RecommendedControlBlock,
	}}

	egress := compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown)
	egress.CredentialAuthorityRef = "authority:egress"
	egress.CredentialAuthority = &agginventory.CredentialAuthority{
		CredentialPresent: true,
		AccessType:        agginventory.AuthorityAccessRead,
		LikelyScope:       "network:egress",
	}

	grouped, memberships := groupCompositionCandidates([]compositionCandidate{
		newCompositionCandidate(governedRead),
		newCompositionCandidate(weakerRead),
	})
	if got, want := len(grouped), 2; got != want || len(memberships) != want {
		t.Fatalf("governance-distinct candidates were grouped: grouped=%+v memberships=%+v", grouped, memberships)
	}
	contradictionGroups, _ := groupCompositionCandidates([]compositionCandidate{
		newCompositionCandidate(governedRead),
		newCompositionCandidate(contradictoryCandidate),
	})
	if got, want := len(contradictionGroups), 2; got != want {
		t.Fatalf("contradictory candidate was grouped with an otherwise identical path: %+v", contradictionGroups)
	}

	compositions, _ := BuildComposedActionPaths([]ActionPath{governedRead, weakerRead, egress}, nil)
	composition := findCompositionByPattern(compositions, CompositionPatternSensitiveReadToEgress)
	if composition == nil {
		t.Fatalf("expected sensitive-read composition, got %+v", compositions)
	}
	if composition.PolicyCoverageStatus != PolicyCoverageStatusDeclared {
		t.Fatalf("governance state was not merged conservatively: %+v", composition)
	}
	if !containsAnyPathClass(composition.memberPathIDs, governedRead.PathID, weakerRead.PathID) ||
		!containsAnyPathClass(composition.EvidenceRefs, "evidence:weaker-read") {
		t.Fatalf("expected governance evidence from both candidates, got %+v", composition)
	}
}

func TestCompositionCandidateIDMatchesMaterializedComposition(t *testing.T) {
	spec := compositionPatternSpecs()[0]
	for name, paths := range map[string][]ActionPath{
		"fallback target identity": {
			compositionTestPath("apc-read", "rk-read", []string{"read"}, TargetClassCustomerDataAdjacent),
			compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown),
		},
		"endpoint target identity": {
			func() ActionPath {
				path := compositionTestPath("apc-read", "rk-read", []string{"read"}, TargetClassCustomerDataAdjacent)
				path.EndpointRefGroupID = "group-customers"
				return path
			}(),
			func() ActionPath {
				path := compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown)
				path.MutableEndpointSemantics = []agginventory.MutableEndpointSemantic{{Surface: "openapi", Operation: "POST /v1/export"}}
				return path
			}(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := compositionCandidateID(spec, paths[0], paths[1])
			want := buildComposedActionPath(spec, paths[0], paths[1], nil).CompositionID
			if got != want {
				t.Fatalf("candidate identity = %q, want %q", got, want)
			}
		})
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

func TestDecorateActionPathCompositionRefsRetainsUnboundedMembership(t *testing.T) {
	paths := make([]ActionPath, 0, maxOutputEvidenceRefs+2)
	for index := 0; index <= maxOutputEvidenceRefs; index++ {
		source := compositionTestPath(fmt.Sprintf("apc-read-%03d", index), "rk-read-shared", []string{"read"}, TargetClassCustomerDataAdjacent)
		source.Repo = "checkout"
		paths = append(paths, source)
	}
	sink := compositionTestPath("apc-egress", "rk-egress", []string{"egress"}, TargetClassUnknown)
	sink.Repo = "checkout"
	paths = append(paths, sink)

	compositions, _ := BuildComposedActionPaths(paths, nil)
	var composition *ComposedActionPath
	for index := range compositions {
		candidate := &compositions[index]
		if len(candidate.memberPathIDs) > maxOutputEvidenceRefs {
			composition = candidate
			break
		}
	}
	if composition == nil {
		t.Fatalf("expected a collapsed composition with unbounded internal membership, got %+v", compositions)
		return
	}
	if len(composition.PathIDs) != maxOutputEvidenceRefs {
		t.Fatalf("serialized path ids = %d, want cap %d", len(composition.PathIDs), maxOutputEvidenceRefs)
	}

	decorated := DecorateActionPathCompositionRefs(paths, compositions)
	for _, path := range decorated {
		if !containsAnyPathClass(path.CompositionIDs, composition.CompositionID) {
			t.Fatalf("path %s lost composition membership: %+v", path.PathID, path)
		}
		if !containsAnyPathClass(path.ProposedActionContractRefs, composition.ProposedActionContractRefs[0]) {
			t.Fatalf("path %s lost proposed action contract membership: %+v", path.PathID, path)
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

func TestMergeComposedActionPathPrefersMostRestrictiveDelegationRelationship(t *testing.T) {
	base := ComposedActionPath{
		CompositionID: "cap-restrictive-transition",
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
	base.Transitions[0].Relationship = CompositionDelegationEqual
	base.Transitions[0].ParentAuthorityRef = "authority:repo-read"
	base.Transitions[0].ChildAuthorityRef = "authority:prod-read"

	incoming := base
	incoming.Transitions = append([]CompositionTransition(nil), base.Transitions...)
	incoming.Transitions[0].Relationship = CompositionDelegationContradictory
	incoming.Transitions[0].ParentAuthorityRef = "authority:repo-conflicted"
	incoming.Transitions[0].ChildAuthorityRef = "authority:prod-conflicted"
	incoming.Transitions[0].ReasonCodes = []string{"delegation_relationship:contradictory_evidence"}

	merged := mergeComposedActionPath(base, incoming)
	if len(merged.Transitions) != 1 {
		t.Fatalf("expected one merged transition, got %+v", merged.Transitions)
	}
	transition := merged.Transitions[0]
	if transition.Relationship != CompositionDelegationContradictory ||
		transition.ParentAuthorityRef != "authority:repo-conflicted" ||
		transition.ChildAuthorityRef != "authority:prod-conflicted" ||
		!containsAnyPathClass(transition.ReasonCodes, "delegation_relationship:contradictory_evidence") {
		t.Fatalf("expected most restrictive delegation to survive merge, got %+v", transition)
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

type deadlineAfterCallsContext struct {
	context.Context
	allowedCalls int
	calls        int
}

func (c *deadlineAfterCallsContext) Err() error {
	c.calls++
	if c.calls > c.allowedCalls {
		return context.DeadlineExceeded
	}
	return nil
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

func findCompositionByID(paths []ComposedActionPath, compositionID string) *ComposedActionPath {
	for index := range paths {
		if paths[index].CompositionID == compositionID {
			return &paths[index]
		}
	}
	return nil
}
