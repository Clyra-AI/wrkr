package report

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/governancequeue"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func sanitizeProofReferenceWithConfig(in ProofReference, config RedactionConfig) ProofReference {
	copyRef := in
	copyRef.ChainPath = maybeRedactProofChainPath(copyRef.ChainPath, config)
	if shouldRedactFindingKeys(config) {
		copyRef.CanonicalFindingKeys = redactStringSlice(copyRef.CanonicalFindingKeys, "finding")
	} else {
		copyRef.CanonicalFindingKeys = cloneStrings(copyRef.CanonicalFindingKeys)
	}
	return copyRef
}

func sanitizeLifecycleSummaryWithConfig(in LifecycleSummary, config RedactionConfig) LifecycleSummary {
	copySummary := in
	copySummary.RecentTransitions = append([]LifecycleTransition(nil), in.RecentTransitions...)
	copySummary.Gaps = append([]lifecycle.Gap(nil), in.Gaps...)
	copySummary.Queue = append([]governancequeue.Item(nil), in.Queue...)
	for idx := range copySummary.Gaps {
		copySummary.Gaps[idx].Repo = maybeRedactRepo(copySummary.Gaps[idx].Repo, config)
		copySummary.Gaps[idx].Location = maybeRedactLocationLike(copySummary.Gaps[idx].Location, config)
		copySummary.Gaps[idx].Owner = maybeRedactOwner(copySummary.Gaps[idx].Owner, config)
	}
	for idx := range copySummary.Queue {
		copySummary.Queue[idx].AgentID = maybeRedactPathID(copySummary.Queue[idx].AgentID, config)
		copySummary.Queue[idx].Repo = maybeRedactRepo(copySummary.Queue[idx].Repo, config)
		copySummary.Queue[idx].Path = maybeRedactLocationLike(copySummary.Queue[idx].Path, config)
		copySummary.Queue[idx].Owner = maybeRedactOwner(copySummary.Queue[idx].Owner, config)
		copySummary.Queue[idx].EvidenceRefs = maybeRedactStringSlice(copySummary.Queue[idx].EvidenceRefs, "evidence", config.Has(RedactionProofRefs))
		copySummary.Queue[idx].SourceConflicts = maybeRedactStringSlice(copySummary.Queue[idx].SourceConflicts, "owner", config.Has(RedactionOwners))
	}
	return copySummary
}

func sanitizeRiskItemsWithConfig(in []RiskItem, config RedactionConfig) []RiskItem {
	out := make([]RiskItem, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.CanonicalKey = maybeRedactFindingKey(copyItem.CanonicalKey, config)
		copyItem.Location = maybeRedactLocationLike(copyItem.Location, config)
		copyItem.Repo = maybeRedactRepo(copyItem.Repo, config)
		copyItem.Org = maybeRedactOrg(copyItem.Org, config)
		copyItem.PathID = maybeRedactPathID(copyItem.PathID, config)
		out = append(out, copyItem)
	}
	return out
}

func sanitizeActivationSummaryWithConfig(in *ActivationSummary, config RedactionConfig) *ActivationSummary {
	if in == nil {
		return nil
	}
	copySummary := *in
	copySummary.Items = append([]ActivationItem(nil), in.Items...)
	for idx := range copySummary.Items {
		copySummary.Items[idx].Location = maybeRedactLocationLike(copySummary.Items[idx].Location, config)
		copySummary.Items[idx].Repo = maybeRedactRepo(copySummary.Items[idx].Repo, config)
	}
	return &copySummary
}

func sanitizeActionPathsWithConfig(in []risk.ActionPath, config RedactionConfig) []risk.ActionPath {
	return sanitizeActionPathsWithConfigAndContractRefs(in, config, nil, nil)
}

func sanitizeActionPathsWithConfigAndContractRefs(in []risk.ActionPath, config RedactionConfig, proposedContractRefMap map[string]string, compositionIDMap map[string]string) []risk.ActionPath {
	if len(in) == 0 {
		return nil
	}
	out := make([]risk.ActionPath, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.PathID = maybeRedactPathID(copyItem.PathID, config)
		copyItem.Org = maybeRedactOrg(copyItem.Org, config)
		copyItem.Repo = maybeRedactRepo(copyItem.Repo, config)
		copyItem.Location = maybeRedactLocationLike(copyItem.Location, config)
		copyItem.OperationalOwner = maybeRedactOwner(copyItem.OperationalOwner, config)
		copyItem.ReviewOwner = maybeRedactOwner(copyItem.ReviewOwner, config)
		copyItem.ReviewSource = maybeRedactCompositeLabel(copyItem.ReviewSource, config)
		copyItem.ReviewRationale = maybeRedactCompositeLabel(copyItem.ReviewRationale, config)
		copyItem.ConfigSource = maybeRedactLocationLike(copyItem.ConfigSource, config)
		copyItem.OccurrenceRefs = maybeRedactStringSlice(copyItem.OccurrenceRefs, "path", config.Has(RedactionPaths) || config.Has(RedactionRepos))
		copyItem.AttackPathRefs = maybeRedactStringSlice(copyItem.AttackPathRefs, "attack", config.Has(RedactionGraphRefs))
		copyItem.SourceFindingKeys = maybeRedactStringSlice(copyItem.SourceFindingKeys, "finding", shouldRedactFindingKeys(config))
		copyItem.ControlEvidenceRefs = maybeRedactEvidenceRefSlice(copyItem.ControlEvidenceRefs, config)
		copyItem.ConstraintEvidenceRefs = maybeRedactEvidenceRefSlice(copyItem.ConstraintEvidenceRefs, config)
		copyItem.TargetClassEvidenceRefs = maybeRedactEvidenceRefSlice(copyItem.TargetClassEvidenceRefs, config)
		copyItem.ActionPathTypeEvidenceRefs = maybeRedactEvidenceRefSlice(copyItem.ActionPathTypeEvidenceRefs, config)
		if copyItem.CredentialProvenance != nil {
			copyItem.CredentialProvenance = agginventory.CloneCredentialProvenance(copyItem.CredentialProvenance)
			copyItem.CredentialProvenance.Subject = maybeRedactCredentialSubject(copyItem.CredentialProvenance.Subject, config)
			copyItem.CredentialProvenance.EvidenceBasis = cloneStrings(copyItem.CredentialProvenance.EvidenceBasis)
			copyItem.CredentialProvenance.EvidenceLocation = maybeRedactLocationLike(copyItem.CredentialProvenance.EvidenceLocation, config)
			copyItem.CredentialProvenance.ClassificationReasons = cloneStrings(copyItem.CredentialProvenance.ClassificationReasons)
		}
		if copyItem.CredentialAuthority != nil {
			copyItem.CredentialAuthority = agginventory.CloneCredentialAuthority(copyItem.CredentialAuthority)
			copyItem.CredentialAuthority.ReasonCodes = cloneStrings(copyItem.CredentialAuthority.ReasonCodes)
		}
		copyItem.EndpointRefGroupProjection = sanitizeEndpointRefGroupProjectionWithConfig(copyItem.EndpointRefGroupProjection, config)
		copyItem.MutableEndpointSemantics = sanitizeMutableEndpointSemanticsWithConfig(copyItem.MutableEndpointSemantics, config)
		copyItem.Credentials = redactCredentialsWithConfig(copyItem.Credentials, config)
		copyItem.ClosureRequirements = sanitizeClosureRequirementsWithConfig(copyItem.ClosureRequirements, config)
		copyItem.EvidenceCompleteness = risk.CloneEvidenceCompleteness(copyItem.EvidenceCompleteness)
		copyItem.ActionLineage = sanitizeActionLineageWithConfig(copyItem.ActionLineage, config)
		copyItem.IntroducedBy = sanitizeIntroducedByWithConfig(copyItem.IntroducedBy, config)
		copyItem.AgenticDeliverySystemChange = sanitizeAgenticDeliverySystemChangeWithConfig(copyItem.AgenticDeliverySystemChange, config)
		copyItem.RuntimeProvider = maybeRedactProviderContext(copyItem.RuntimeProvider, config)
		copyItem.RuntimeHost = maybeRedactProviderContext(copyItem.RuntimeHost, config)
		copyItem.RuntimeKind = maybeRedactProviderContext(copyItem.RuntimeKind, config)
		copyItem.ModelProvider = maybeRedactProviderContext(copyItem.ModelProvider, config)
		copyItem.ModelVersion = maybeRedactProviderContext(copyItem.ModelVersion, config)
		copyItem.ExecutionEnvironment = maybeRedactProviderContext(copyItem.ExecutionEnvironment, config)
		copyItem.StateLocationRefs = maybeRedactLocationLikeSlice(copyItem.StateLocationRefs, config)
		copyItem.StateDigestRefs = maybeRedactStringSlice(copyItem.StateDigestRefs, "digest", config.Has(RedactionProofRefs))
		copyItem.PolicyRefs = maybeRedactStringSlice(copyItem.PolicyRefs, "policy", config.Has(RedactionPaths) || config.Has(RedactionRepos) || config.Has(RedactionProofRefs))
		copyItem.PolicyEvidenceRefs = maybeRedactEvidenceRefSlice(copyItem.PolicyEvidenceRefs, config)
		copyItem.AutonomyTierEvidenceRefs = maybeRedactEvidenceRefSlice(copyItem.AutonomyTierEvidenceRefs, config)
		copyItem.RiskClassificationValidationRefs = maybeRedactEvidenceRefSlice(copyItem.RiskClassificationValidationRefs, config)
		copyItem.AgentIdentity = sanitizeAgentIdentityWithConfig(copyItem.AgentIdentity, config)
		copyItem.DecisionPrecedent = sanitizeDecisionPrecedentWithConfig(copyItem.DecisionPrecedent, config)
		copyItem.DeliveryControlContext = sanitizeDeliveryControlContextWithConfig(copyItem.DeliveryControlContext, config)
		copyItem.ReviewAuditContext = sanitizeReviewAuditContextWithConfig(copyItem.ReviewAuditContext, config)
		copyItem.ResolvedAppendixRefs = maybeRedactLocationLikeSlice(copyItem.ResolvedAppendixRefs, config)
		copyItem.ReopenEvidenceRefs = maybeRedactEvidenceRefSlice(copyItem.ReopenEvidenceRefs, config)
		copyItem.DeliveryHarnesses = maybeRedactCompositeLabelSlice(copyItem.DeliveryHarnesses, config)
		copyItem.ResolverRefs = maybeRedactLocationLikeSlice(copyItem.ResolverRefs, config)
		copyItem.EvalConfigRefs = maybeRedactLocationLikeSlice(copyItem.EvalConfigRefs, config)
		copyItem.SandboxGates = maybeRedactLocationLikeSlice(copyItem.SandboxGates, config)
		copyItem.TestGates = maybeRedactCompositeLabelSlice(copyItem.TestGates, config)
		copyItem.ValidationRequirements = maybeRedactCompositeLabelSlice(copyItem.ValidationRequirements, config)
		copyItem.HighStakesPresets = sanitizeHighStakesPresetsWithConfig(copyItem.HighStakesPresets, config)
		copyItem.EvidenceDecisions = sanitizeEvidenceDecisionsWithConfig(copyItem.EvidenceDecisions, config)
		copyItem.ProductionContext = sanitizeProductionContextWithConfig(copyItem.ProductionContext, config)
		copyItem.EvidencePacketRefs = maybeRedactStringSlice(copyItem.EvidencePacketRefs, "packet", config.Has(RedactionPaths) || config.Has(RedactionProofRefs))
		copyItem.DecisionTraceRefs = maybeRedactStringSlice(copyItem.DecisionTraceRefs, "proof", config.Has(RedactionProofRefs))
		copyItem.CompositionIDs = remapCompositionRefs(copyItem.CompositionIDs, compositionIDMap)
		copyItem.ProposedActionContractRefs = remapProposedActionContractRefs(copyItem.ProposedActionContractRefs, proposedContractRefMap)
		copyItem.MatchedProductionTargets = cloneStrings(copyItem.MatchedProductionTargets)
		out = append(out, copyItem)
	}
	return out
}

func sanitizeActionPathToControlFirstWithContractRefs(in *risk.ActionPathToControlFirst, config RedactionConfig, proposedContractRefMap map[string]string, compositionIDMap map[string]string) *risk.ActionPathToControlFirst {
	if in == nil {
		return nil
	}
	copySummary := in.Summary
	paths := sanitizeActionPathsWithConfigAndContractRefs([]risk.ActionPath{in.Path}, config, proposedContractRefMap, compositionIDMap)
	if len(paths) == 0 {
		return &risk.ActionPathToControlFirst{Summary: copySummary}
	}
	return &risk.ActionPathToControlFirst{
		Summary: copySummary,
		Path:    paths[0],
	}
}

func sanitizeComposedActionPathsPublic(in []risk.ComposedActionPath) []risk.ComposedActionPath {
	if len(in) == 0 {
		return nil
	}
	out := make([]risk.ComposedActionPath, 0, len(in))
	compositionIDMap := map[string]string{}
	for _, item := range in {
		compositionIDMap[strings.TrimSpace(item.CompositionID)] = redactValue("composition", item.CompositionID, 8)
	}
	for _, item := range in {
		copyItem := item
		copyItem.CompositionID = compositionIDMap[strings.TrimSpace(copyItem.CompositionID)]
		copyItem.PathIDs = redactStringSlice(copyItem.PathIDs, "path")
		copyItem.WorkflowChainRefs = redactStringSlice(copyItem.WorkflowChainRefs, "workflow")
		copyItem.ResolutionKey = redactValue("resolution", copyItem.ResolutionKey, 8)
		copyItem.TargetIdentity = redactValue("target", copyItem.TargetIdentity, 8)
		copyItem.DurableOutcomeKey = redactValue("outcome", copyItem.DurableOutcomeKey, 8)
		copyItem.OutcomeKey = redactValue("outcome", copyItem.OutcomeKey, 8)
		copyItem.AffectedAsset = redactValue("target", copyItem.AffectedAsset, 8)
		copyItem.EvidenceRefs = redactStringSlice(copyItem.EvidenceRefs, "evidence")
		copyItem.ProofRefs = redactStringSlice(copyItem.ProofRefs, "proof")
		copyItem.SourceDecisionRefs = redactStringSlice(copyItem.SourceDecisionRefs, "decision")
		copyItem.TruncatedCandidates = redactStringSlice(copyItem.TruncatedCandidates, "candidate")
		copyItem.AlternateRouteRefs = remapCompositionRefs(copyItem.AlternateRouteRefs, compositionIDMap)
		copyItem.EquivalentOutcomeRefs = remapCompositionRefs(copyItem.EquivalentOutcomeRefs, compositionIDMap)
		copyItem.EquivalentOutcomeEscalationSource = remapCompositionRef(copyItem.EquivalentOutcomeEscalationSource, compositionIDMap)
		copyItem.MostRestrictiveSource = remapCompositionRef(copyItem.MostRestrictiveSource, compositionIDMap)
		copyItem.ClosureRequirements = sanitizeClosureRequirementsPublic(copyItem.ClosureRequirements)
		copyItem.EvidenceCompleteness = risk.CloneEvidenceCompleteness(copyItem.EvidenceCompleteness)
		copyItem.GaitCoverage = sanitizeGaitCoveragePublic(copyItem.GaitCoverage)
		copyItem.Contradictions = sanitizeContradictionsPublic(copyItem.Contradictions)
		stageIDMap := map[string]string{}
		copyItem.Stages = sanitizeCompositionStagesPublic(copyItem.Stages, stageIDMap)
		copyItem.Transitions = sanitizeCompositionTransitionsPublic(copyItem.Transitions, stageIDMap)
		for idx := range copyItem.Stages {
			copyItem.Stages[idx].AlternateRouteRefs = remapCompositionRefs(copyItem.Stages[idx].AlternateRouteRefs, compositionIDMap)
		}
		for idx := range copyItem.Transitions {
			copyItem.Transitions[idx].AlternateRouteRefs = remapCompositionRefs(copyItem.Transitions[idx].AlternateRouteRefs, compositionIDMap)
		}
		copyItem.ProposedActionContract = sanitizeProposedActionContractPublic(copyItem.ProposedActionContract)
		if copyItem.ProposedActionContract != nil {
			copyItem.ProposedActionContract.CompositionRef = copyItem.CompositionID
			risk.RefreshProposedActionContractIdentity(copyItem.ProposedActionContract)
		}
		copyItem.ProposedActionContractRefs = sanitizeProposedActionContractRefs(copyItem.ProposedActionContract, copyItem.ProposedActionContractRefs)
		out = append(out, copyItem)
	}
	return out
}

func sanitizeComposedActionPathToControlFirstPublic(in *risk.ComposedActionPathToControlFirst) *risk.ComposedActionPathToControlFirst {
	if in == nil {
		return nil
	}
	paths := sanitizeComposedActionPathsPublic([]risk.ComposedActionPath{in.Path})
	out := &risk.ComposedActionPathToControlFirst{Summary: in.Summary}
	if len(paths) > 0 {
		out.Path = paths[0]
	}
	return out
}

func remapCompositionRef(ref string, compositionIDMap map[string]string) string {
	trimmed := strings.TrimSpace(ref)
	if trimmed == "" {
		return ""
	}
	if mapped := strings.TrimSpace(compositionIDMap[trimmed]); mapped != "" {
		return mapped
	}
	if strings.HasPrefix(trimmed, "peer:") {
		peer := strings.TrimSpace(strings.TrimPrefix(trimmed, "peer:"))
		if mapped := strings.TrimSpace(compositionIDMap[peer]); mapped != "" {
			return "peer:" + mapped
		}
		if compositionIDMap != nil {
			return "peer:" + redactValue("composition", peer, 8)
		}
	}
	if compositionIDMap != nil {
		return redactValue("composition", trimmed, 8)
	}
	return trimmed
}

func sanitizeComposedActionPathsWithConfig(in []risk.ComposedActionPath, config RedactionConfig) []risk.ComposedActionPath {
	if len(in) == 0 {
		return nil
	}
	out := make([]risk.ComposedActionPath, 0, len(in))
	compositionIDMap := map[string]string{}
	for _, item := range in {
		value := strings.TrimSpace(item.CompositionID)
		if config.Has(RedactionPaths) || config.Has(RedactionRepos) {
			value = redactValue("composition", value, 8)
		}
		compositionIDMap[strings.TrimSpace(item.CompositionID)] = value
	}
	for _, item := range in {
		copyItem := item
		redactComposedIdentity := config.Has(RedactionPaths) || config.Has(RedactionRepos)
		if redactComposedIdentity {
			copyItem.CompositionID = compositionIDMap[strings.TrimSpace(copyItem.CompositionID)]
		}
		if config.Has(RedactionPaths) {
			copyItem.PathIDs = redactStringSlice(copyItem.PathIDs, "path")
			copyItem.WorkflowChainRefs = redactStringSlice(copyItem.WorkflowChainRefs, "workflow")
			copyItem.ResolutionKey = redactValue("resolution", copyItem.ResolutionKey, 8)
			copyItem.TargetIdentity = redactValue("target", copyItem.TargetIdentity, 8)
			copyItem.DurableOutcomeKey = redactValue("outcome", copyItem.DurableOutcomeKey, 8)
			copyItem.OutcomeKey = redactValue("outcome", copyItem.OutcomeKey, 8)
			copyItem.AffectedAsset = redactValue("target", copyItem.AffectedAsset, 8)
			stageIDMap := map[string]string{}
			copyItem.Stages = sanitizeCompositionStagesPublic(copyItem.Stages, stageIDMap)
			copyItem.Transitions = sanitizeCompositionTransitionsPublic(copyItem.Transitions, stageIDMap)
		} else {
			copyItem.PathIDs = cloneStrings(copyItem.PathIDs)
			copyItem.WorkflowChainRefs = cloneStrings(copyItem.WorkflowChainRefs)
			stageIDMap := map[string]string{}
			copyItem.Stages = sanitizeCompositionStagesWithConfig(copyItem.Stages, config, stageIDMap)
			copyItem.Transitions = sanitizeCompositionTransitionsWithConfig(copyItem.Transitions, config, stageIDMap)
			if redactComposedIdentity {
				copyItem.ResolutionKey = redactValue("resolution", copyItem.ResolutionKey, 8)
				copyItem.TargetIdentity = redactValue("target", copyItem.TargetIdentity, 8)
				copyItem.DurableOutcomeKey = redactValue("outcome", copyItem.DurableOutcomeKey, 8)
				copyItem.OutcomeKey = redactValue("outcome", copyItem.OutcomeKey, 8)
				copyItem.AffectedAsset = redactValue("target", copyItem.AffectedAsset, 8)
			}
		}
		copyItem.EvidenceRefs = maybeRedactEvidenceRefSlice(copyItem.EvidenceRefs, config)
		copyItem.ProofRefs = maybeRedactStringSlice(copyItem.ProofRefs, "proof", config.Has(RedactionProofRefs))
		copyItem.SourceDecisionRefs = maybeRedactStringSlice(copyItem.SourceDecisionRefs, "decision", config.Has(RedactionProofRefs))
		if redactComposedIdentity {
			copyItem.TruncatedCandidates = redactStringSlice(copyItem.TruncatedCandidates, "candidate")
			copyItem.AlternateRouteRefs = remapCompositionRefs(copyItem.AlternateRouteRefs, compositionIDMap)
			copyItem.EquivalentOutcomeRefs = remapCompositionRefs(copyItem.EquivalentOutcomeRefs, compositionIDMap)
			copyItem.EquivalentOutcomeEscalationSource = remapCompositionRef(copyItem.EquivalentOutcomeEscalationSource, compositionIDMap)
			copyItem.MostRestrictiveSource = remapCompositionRef(copyItem.MostRestrictiveSource, compositionIDMap)
		} else {
			copyItem.TruncatedCandidates = cloneStrings(copyItem.TruncatedCandidates)
			copyItem.AlternateRouteRefs = cloneStrings(copyItem.AlternateRouteRefs)
			copyItem.EquivalentOutcomeRefs = cloneStrings(copyItem.EquivalentOutcomeRefs)
		}
		if redactComposedIdentity {
			for idx := range copyItem.Stages {
				copyItem.Stages[idx].AlternateRouteRefs = remapCompositionRefs(copyItem.Stages[idx].AlternateRouteRefs, compositionIDMap)
			}
			for idx := range copyItem.Transitions {
				copyItem.Transitions[idx].AlternateRouteRefs = remapCompositionRefs(copyItem.Transitions[idx].AlternateRouteRefs, compositionIDMap)
			}
		}
		copyItem.ClosureRequirements = sanitizeClosureRequirementsWithConfig(copyItem.ClosureRequirements, config)
		copyItem.EvidenceCompleteness = risk.CloneEvidenceCompleteness(copyItem.EvidenceCompleteness)
		copyItem.GaitCoverage = sanitizeGaitCoverageWithConfig(copyItem.GaitCoverage, config)
		copyItem.Contradictions = sanitizeContradictionsWithConfig(copyItem.Contradictions, config)
		if redactComposedIdentity || config.Has(RedactionProofRefs) || config.Has(RedactionOwners) {
			copyItem.ProposedActionContract = sanitizeProposedActionContractPublic(copyItem.ProposedActionContract)
		} else {
			copyItem.ProposedActionContract = risk.CloneProposedActionContract(copyItem.ProposedActionContract)
		}
		copyItem.ProposedActionContractRefs = sanitizeProposedActionContractRefs(copyItem.ProposedActionContract, copyItem.ProposedActionContractRefs)
		if copyItem.ProposedActionContract != nil && redactComposedIdentity {
			copyItem.ProposedActionContract.CompositionRef = copyItem.CompositionID
			risk.RefreshProposedActionContractIdentity(copyItem.ProposedActionContract)
			copyItem.ProposedActionContractRefs = sanitizeProposedActionContractRefs(copyItem.ProposedActionContract, copyItem.ProposedActionContractRefs)
		}
		out = append(out, copyItem)
	}
	return out
}

func sanitizeComposedActionPathToControlFirstWithConfig(in *risk.ComposedActionPathToControlFirst, config RedactionConfig) *risk.ComposedActionPathToControlFirst {
	if in == nil {
		return nil
	}
	paths := sanitizeComposedActionPathsWithConfig([]risk.ComposedActionPath{in.Path}, config)
	out := &risk.ComposedActionPathToControlFirst{Summary: in.Summary}
	if len(paths) > 0 {
		out.Path = paths[0]
	}
	return out
}

func sanitizeCompositionStagesPublic(in []risk.CompositionStage, stageIDMap map[string]string) []risk.CompositionStage {
	out := make([]risk.CompositionStage, 0, len(in))
	for _, stage := range in {
		copyStage := stage
		copyStage.StageID = remapStageID(copyStage.StageID, stageIDMap)
		copyStage.PathID = redactValue("path", copyStage.PathID, 8)
		copyStage.ResolutionKey = redactValue("resolution", copyStage.ResolutionKey, 8)
		copyStage.Location = redactValue("loc", copyStage.Location, 8)
		copyStage.ParentAuthorityRef = redactValue("authority", copyStage.ParentAuthorityRef, 8)
		copyStage.ChildAuthorityRef = redactValue("authority", copyStage.ChildAuthorityRef, 8)
		copyStage.ScopeDelta = redactStringSlice(copyStage.ScopeDelta, "scope")
		copyStage.TargetDelta = redactStringSlice(copyStage.TargetDelta, "target")
		copyStage.CredentialDelta = redactStringSlice(copyStage.CredentialDelta, "credential")
		copyStage.ExpiryDelta = redactStringSlice(copyStage.ExpiryDelta, "expiry")
		copyStage.EvidenceRefs = redactStringSlice(copyStage.EvidenceRefs, "evidence")
		copyStage.ProofRefs = redactStringSlice(copyStage.ProofRefs, "proof")
		copyStage.SourceDecisionRefs = redactStringSlice(copyStage.SourceDecisionRefs, "decision")
		copyStage.TrustBoundary = redactValue("boundary", copyStage.TrustBoundary, 8)
		copyStage.CorrelationRefs = redactStringSlice(copyStage.CorrelationRefs, "correlation")
		copyStage.GaitCoverage = sanitizeGaitCoveragePublic(copyStage.GaitCoverage)
		copyStage.Contradictions = sanitizeContradictionsPublic(copyStage.Contradictions)
		out = append(out, copyStage)
	}
	return out
}

func sanitizeCompositionStagesWithConfig(in []risk.CompositionStage, config RedactionConfig, stageIDMap map[string]string) []risk.CompositionStage {
	out := make([]risk.CompositionStage, 0, len(in))
	for _, stage := range in {
		copyStage := stage
		if config.Has(RedactionPaths) || config.Has(RedactionRepos) {
			copyStage.StageID = remapStageID(copyStage.StageID, stageIDMap)
		}
		copyStage.PathID = maybeRedactPathID(copyStage.PathID, config)
		if config.Has(RedactionPaths) || config.Has(RedactionRepos) {
			copyStage.ResolutionKey = redactValue("resolution", copyStage.ResolutionKey, 8)
			copyStage.ParentAuthorityRef = redactValue("authority", copyStage.ParentAuthorityRef, 8)
			copyStage.ChildAuthorityRef = redactValue("authority", copyStage.ChildAuthorityRef, 8)
			copyStage.ScopeDelta = redactStringSlice(copyStage.ScopeDelta, "scope")
			copyStage.TargetDelta = redactStringSlice(copyStage.TargetDelta, "target")
			copyStage.CredentialDelta = redactStringSlice(copyStage.CredentialDelta, "credential")
			copyStage.ExpiryDelta = redactStringSlice(copyStage.ExpiryDelta, "expiry")
		}
		copyStage.Location = maybeRedactLocationLike(copyStage.Location, config)
		copyStage.EvidenceRefs = maybeRedactEvidenceRefSlice(copyStage.EvidenceRefs, config)
		copyStage.ProofRefs = maybeRedactStringSlice(copyStage.ProofRefs, "proof", config.Has(RedactionProofRefs))
		copyStage.SourceDecisionRefs = maybeRedactStringSlice(copyStage.SourceDecisionRefs, "decision", config.Has(RedactionProofRefs))
		if config.Has(RedactionPaths) || config.Has(RedactionRepos) {
			copyStage.TrustBoundary = redactValue("boundary", copyStage.TrustBoundary, 8)
			copyStage.CorrelationRefs = redactStringSlice(copyStage.CorrelationRefs, "correlation")
		} else {
			copyStage.CorrelationRefs = maybeRedactCorrelationRefSlice(copyStage.CorrelationRefs, config)
		}
		copyStage.GaitCoverage = sanitizeGaitCoverageWithConfig(copyStage.GaitCoverage, config)
		copyStage.Contradictions = sanitizeContradictionsWithConfig(copyStage.Contradictions, config)
		out = append(out, copyStage)
	}
	return out
}

func sanitizeCompositionTransitionsPublic(in []risk.CompositionTransition, stageIDMap map[string]string) []risk.CompositionTransition {
	out := make([]risk.CompositionTransition, 0, len(in))
	for _, transition := range in {
		copyTransition := transition
		copyTransition.TransitionID = redactValue("transition", copyTransition.TransitionID, 8)
		copyTransition.FromStageID = remapStageID(copyTransition.FromStageID, stageIDMap)
		copyTransition.ToStageID = remapStageID(copyTransition.ToStageID, stageIDMap)
		copyTransition.ParentAuthorityRef = redactValue("authority", copyTransition.ParentAuthorityRef, 8)
		copyTransition.ChildAuthorityRef = redactValue("authority", copyTransition.ChildAuthorityRef, 8)
		copyTransition.ScopeDelta = redactStringSlice(copyTransition.ScopeDelta, "scope")
		copyTransition.TargetDelta = redactStringSlice(copyTransition.TargetDelta, "target")
		copyTransition.CredentialDelta = redactStringSlice(copyTransition.CredentialDelta, "credential")
		copyTransition.ExpiryDelta = redactStringSlice(copyTransition.ExpiryDelta, "expiry")
		copyTransition.EvidenceRefs = redactStringSlice(copyTransition.EvidenceRefs, "evidence")
		copyTransition.ProofRefs = redactStringSlice(copyTransition.ProofRefs, "proof")
		copyTransition.SourceDecisionRefs = redactStringSlice(copyTransition.SourceDecisionRefs, "decision")
		copyTransition.TrustBoundary = redactValue("boundary", copyTransition.TrustBoundary, 8)
		copyTransition.CorrelationRefs = redactStringSlice(copyTransition.CorrelationRefs, "correlation")
		copyTransition.GaitCoverage = sanitizeGaitCoveragePublic(copyTransition.GaitCoverage)
		out = append(out, copyTransition)
	}
	return out
}

func sanitizeCompositionTransitionsWithConfig(in []risk.CompositionTransition, config RedactionConfig, stageIDMap map[string]string) []risk.CompositionTransition {
	out := make([]risk.CompositionTransition, 0, len(in))
	for _, transition := range in {
		copyTransition := transition
		if config.Has(RedactionPaths) || config.Has(RedactionRepos) {
			copyTransition.TransitionID = redactValue("transition", copyTransition.TransitionID, 8)
			copyTransition.FromStageID = remapStageID(copyTransition.FromStageID, stageIDMap)
			copyTransition.ToStageID = remapStageID(copyTransition.ToStageID, stageIDMap)
			copyTransition.ParentAuthorityRef = redactValue("authority", copyTransition.ParentAuthorityRef, 8)
			copyTransition.ChildAuthorityRef = redactValue("authority", copyTransition.ChildAuthorityRef, 8)
			copyTransition.ScopeDelta = redactStringSlice(copyTransition.ScopeDelta, "scope")
			copyTransition.TargetDelta = redactStringSlice(copyTransition.TargetDelta, "target")
			copyTransition.CredentialDelta = redactStringSlice(copyTransition.CredentialDelta, "credential")
			copyTransition.ExpiryDelta = redactStringSlice(copyTransition.ExpiryDelta, "expiry")
		}
		copyTransition.EvidenceRefs = maybeRedactEvidenceRefSlice(copyTransition.EvidenceRefs, config)
		copyTransition.ProofRefs = maybeRedactStringSlice(copyTransition.ProofRefs, "proof", config.Has(RedactionProofRefs))
		copyTransition.SourceDecisionRefs = maybeRedactStringSlice(copyTransition.SourceDecisionRefs, "decision", config.Has(RedactionProofRefs))
		if config.Has(RedactionPaths) || config.Has(RedactionRepos) {
			copyTransition.TrustBoundary = redactValue("boundary", copyTransition.TrustBoundary, 8)
			copyTransition.CorrelationRefs = redactStringSlice(copyTransition.CorrelationRefs, "correlation")
		} else {
			copyTransition.CorrelationRefs = maybeRedactCorrelationRefSlice(copyTransition.CorrelationRefs, config)
		}
		copyTransition.GaitCoverage = sanitizeGaitCoverageWithConfig(copyTransition.GaitCoverage, config)
		out = append(out, copyTransition)
	}
	return out
}

func sanitizeGaitCoveragePublic(in *risk.GaitCoverage) *risk.GaitCoverage {
	if in == nil {
		return nil
	}
	out := risk.CloneGaitCoverage(in)
	out.PolicyDecision.EvidenceRefs = redactStringSlice(out.PolicyDecision.EvidenceRefs, "evidence")
	out.Approval.EvidenceRefs = redactStringSlice(out.Approval.EvidenceRefs, "evidence")
	out.JITCredential.EvidenceRefs = redactStringSlice(out.JITCredential.EvidenceRefs, "evidence")
	out.FreezeWindow.EvidenceRefs = redactStringSlice(out.FreezeWindow.EvidenceRefs, "evidence")
	out.KillSwitch.EvidenceRefs = redactStringSlice(out.KillSwitch.EvidenceRefs, "evidence")
	out.ActionOutcome.EvidenceRefs = redactStringSlice(out.ActionOutcome.EvidenceRefs, "evidence")
	out.ProofVerification.EvidenceRefs = redactStringSlice(out.ProofVerification.EvidenceRefs, "evidence")
	return out
}

func sanitizeGaitCoverageWithConfig(in *risk.GaitCoverage, config RedactionConfig) *risk.GaitCoverage {
	if in == nil {
		return nil
	}
	out := risk.CloneGaitCoverage(in)
	out.PolicyDecision.EvidenceRefs = maybeRedactEvidenceRefSlice(out.PolicyDecision.EvidenceRefs, config)
	out.Approval.EvidenceRefs = maybeRedactEvidenceRefSlice(out.Approval.EvidenceRefs, config)
	out.JITCredential.EvidenceRefs = maybeRedactEvidenceRefSlice(out.JITCredential.EvidenceRefs, config)
	out.FreezeWindow.EvidenceRefs = maybeRedactEvidenceRefSlice(out.FreezeWindow.EvidenceRefs, config)
	out.KillSwitch.EvidenceRefs = maybeRedactEvidenceRefSlice(out.KillSwitch.EvidenceRefs, config)
	out.ActionOutcome.EvidenceRefs = maybeRedactEvidenceRefSlice(out.ActionOutcome.EvidenceRefs, config)
	out.ProofVerification.EvidenceRefs = maybeRedactEvidenceRefSlice(out.ProofVerification.EvidenceRefs, config)
	return out
}

func sanitizeContradictionsPublic(in []evidencepolicy.Contradiction) []evidencepolicy.Contradiction {
	if len(in) == 0 {
		return nil
	}
	out := append([]evidencepolicy.Contradiction(nil), in...)
	for idx := range out {
		out[idx].ReasonCodes = cloneStrings(out[idx].ReasonCodes)
		out[idx].EvidenceRefs = redactStringSlice(out[idx].EvidenceRefs, "evidence")
	}
	return out
}

func sanitizeContradictionsWithConfig(in []evidencepolicy.Contradiction, config RedactionConfig) []evidencepolicy.Contradiction {
	if len(in) == 0 {
		return nil
	}
	out := append([]evidencepolicy.Contradiction(nil), in...)
	for idx := range out {
		out[idx].ReasonCodes = cloneStrings(out[idx].ReasonCodes)
		out[idx].EvidenceRefs = maybeRedactEvidenceRefSlice(out[idx].EvidenceRefs, config)
	}
	return out
}

func sanitizeProposedActionContractPublic(in *risk.ProposedActionContract) *risk.ProposedActionContract {
	if in == nil {
		return nil
	}
	out := risk.CloneProposedActionContract(in)
	out.ResolutionKey = redactValue("resolution", out.ResolutionKey, 8)
	out.AllowedTransitions = nil
	out.ProhibitedTransitions = nil
	out.ApprovalRequiredTransitions = nil
	out.TargetConstraints = nil
	out.AcceptableCountersigners = nil
	out.SourceDigests = nil
	for idx := range out.AuthorityRequirements {
		out.AuthorityRequirements[idx].RequiredConstraint = redactValue("constraint", out.AuthorityRequirements[idx].RequiredConstraint, 8)
		out.AuthorityRequirements[idx].ObservedValue = redactValue("authority", out.AuthorityRequirements[idx].ObservedValue, 8)
		out.AuthorityRequirements[idx].EvidenceRefs = redactStringSlice(out.AuthorityRequirements[idx].EvidenceRefs, "evidence")
	}
	for idx := range out.Preconditions {
		out.Preconditions[idx].RequiredConstraint = redactValue("constraint", out.Preconditions[idx].RequiredConstraint, 8)
		out.Preconditions[idx].ObservedValue = redactValue("precondition", out.Preconditions[idx].ObservedValue, 8)
		out.Preconditions[idx].ObservedResult = redactValue("result", out.Preconditions[idx].ObservedResult, 8)
		out.Preconditions[idx].EvidenceRefs = redactStringSlice(out.Preconditions[idx].EvidenceRefs, "evidence")
	}
	if out.ConfirmationRequirement != nil {
		out.ConfirmationRequirement.EvidenceRefs = redactStringSlice(out.ConfirmationRequirement.EvidenceRefs, "evidence")
	}
	if out.ApprovalRequirement != nil {
		out.ApprovalRequirement.ApproverRoles = redactStringSlice(out.ApprovalRequirement.ApproverRoles, "role")
		out.ApprovalRequirement.EvidenceRefs = redactStringSlice(out.ApprovalRequirement.EvidenceRefs, "evidence")
	}
	if out.CompensationRequirement != nil {
		out.CompensationRequirement.ProcedureRef = redactValue("procedure", out.CompensationRequirement.ProcedureRef, 8)
		out.CompensationRequirement.Target = redactValue("target", out.CompensationRequirement.Target, 8)
		out.CompensationRequirement.EvidenceRefs = redactStringSlice(out.CompensationRequirement.EvidenceRefs, "evidence")
	}
	for idx := range out.LifecycleObservations {
		out.LifecycleObservations[idx].EvidenceRefs = redactStringSlice(out.LifecycleObservations[idx].EvidenceRefs, "evidence")
		out.LifecycleObservations[idx].ActionContractArtifactRefs = redactStringSlice(out.LifecycleObservations[idx].ActionContractArtifactRefs, "artifact")
		out.LifecycleObservations[idx].ProofRefs = redactStringSlice(out.LifecycleObservations[idx].ProofRefs, "proof")
	}
	risk.RefreshProposedActionContractIdentity(out)
	return out
}

func sanitizeProposedActionContractRefs(contract *risk.ProposedActionContract, refs []string) []string {
	if contract != nil && strings.TrimSpace(contract.ContractID) != "" {
		return []string{strings.TrimSpace(contract.ContractID)}
	}
	return cloneStrings(refs)
}

func remapStageID(value string, stageIDMap map[string]string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	if stageIDMap == nil {
		return redactValue("stage", trimmed, 8)
	}
	if mapped, ok := stageIDMap[trimmed]; ok {
		return mapped
	}
	mapped := redactValue("stage", trimmed, 8)
	stageIDMap[trimmed] = mapped
	return mapped
}

func sanitizeActionSurfaceRegistryWithConfig(in []ActionSurfaceRegistryEntry, config RedactionConfig) []ActionSurfaceRegistryEntry {
	if len(in) == 0 {
		return nil
	}
	out := make([]ActionSurfaceRegistryEntry, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.Org = maybeRedactOrg(copyItem.Org, config)
		copyItem.Repo = maybeRedactRepo(copyItem.Repo, config)
		copyItem.Location = maybeRedactLocationLike(copyItem.Location, config)
		copyItem.Owner = maybeRedactOwner(copyItem.Owner, config)
		copyItem.ConfigSource = maybeRedactLocationLike(copyItem.ConfigSource, config)
		copyItem.Credentials = redactCredentialsWithConfig(copyItem.Credentials, config)
		copyItem.MutableEndpointSemantics = sanitizeMutableEndpointSemanticsWithConfig(copyItem.MutableEndpointSemantics, config)
		copyItem.AuthorityBindingRefs = maybeRedactStringSlice(copyItem.AuthorityBindingRefs, "binding", config.Has(RedactionPaths) || config.Has(RedactionRepos))
		copyItem.PathIDs = maybeRedactStringSlice(copyItem.PathIDs, "path", config.Has(RedactionPaths))
		copyItem.GraphRefs = sanitizeGraphRefsWithConfig(copyItem.GraphRefs, config)
		if copyItem.CredentialAuthority != nil {
			copyItem.CredentialAuthority = agginventory.CloneCredentialAuthority(copyItem.CredentialAuthority)
			copyItem.CredentialAuthority.ReasonCodes = cloneStrings(copyItem.CredentialAuthority.ReasonCodes)
		}
		copyItem.EndpointRefGroupProjection = sanitizeEndpointRefGroupProjectionWithConfig(copyItem.EndpointRefGroupProjection, config)
		out = append(out, copyItem)
	}
	return out
}

func sanitizeMutableEndpointSemanticsWithConfig(in []agginventory.MutableEndpointSemantic, config RedactionConfig) []agginventory.MutableEndpointSemantic {
	if len(in) == 0 {
		return nil
	}
	out := agginventory.CloneMutableEndpointSemantics(in)
	for idx := range out {
		if config.Has(RedactionPaths) {
			out[idx].Operation = redactValue("endpoint", out[idx].Operation, 8)
			out[idx].EvidenceRefs = redactStringSlice(out[idx].EvidenceRefs, "endpoint")
		} else {
			out[idx].Operation = strings.TrimSpace(out[idx].Operation)
			out[idx].EvidenceRefs = cloneStrings(out[idx].EvidenceRefs)
		}
	}
	return out
}

func sanitizeEndpointRefGroupProjectionWithConfig(in agginventory.EndpointRefGroupProjection, config RedactionConfig) agginventory.EndpointRefGroupProjection {
	out := in
	if !config.Has(RedactionPaths) {
		out.EndpointRouteGroups = cloneStrings(out.EndpointRouteGroups)
		out.EndpointRefSamples = append([]agginventory.EndpointRefSample(nil), out.EndpointRefSamples...)
		for idx := range out.EndpointRefSamples {
			out.EndpointRefSamples[idx].Operation = strings.TrimSpace(out.EndpointRefSamples[idx].Operation)
			out.EndpointRefSamples[idx].Surface = strings.TrimSpace(out.EndpointRefSamples[idx].Surface)
			out.EndpointRefSamples[idx].Semantics = cloneStrings(out.EndpointRefSamples[idx].Semantics)
		}
		return out
	}
	out.EndpointRouteGroups = redactStringSlice(out.EndpointRouteGroups, "endpoint")
	out.EndpointRefSamples = append([]agginventory.EndpointRefSample(nil), out.EndpointRefSamples...)
	for idx := range out.EndpointRefSamples {
		out.EndpointRefSamples[idx].Operation = redactValue("endpoint", out.EndpointRefSamples[idx].Operation, 8)
		out.EndpointRefSamples[idx].Surface = strings.TrimSpace(out.EndpointRefSamples[idx].Surface)
		out.EndpointRefSamples[idx].Semantics = cloneStrings(out.EndpointRefSamples[idx].Semantics)
	}
	return out
}

func redactCredentialsWithConfig(in []*agginventory.CredentialProvenance, config RedactionConfig) []*agginventory.CredentialProvenance {
	out := agginventory.CloneCredentialProvenances(in)
	for idx := range out {
		out[idx].Subject = maybeRedactCredentialSubject(out[idx].Subject, config)
		out[idx].EvidenceBasis = cloneStrings(out[idx].EvidenceBasis)
		out[idx].EvidenceLocation = maybeRedactLocationLike(out[idx].EvidenceLocation, config)
		out[idx].ClassificationReasons = cloneStrings(out[idx].ClassificationReasons)
	}
	return out
}

func sanitizeExposureGroupsWithConfig(in []risk.ExposureGroup, config RedactionConfig) []risk.ExposureGroup {
	if len(in) == 0 {
		return nil
	}
	out := make([]risk.ExposureGroup, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.Org = maybeRedactOrg(copyItem.Org, config)
		copyItem.ExampleRepo = maybeRedactRepo(copyItem.ExampleRepo, config)
		copyItem.ExampleLocation = maybeRedactLocationLike(copyItem.ExampleLocation, config)
		if config.Has(RedactionRepos) {
			copyItem.Repos = redactStringSlice(copyItem.Repos, "repo")
		} else {
			copyItem.Repos = cloneStrings(copyItem.Repos)
		}
		copyItem.PathIDs = maybeRedactStringSlice(copyItem.PathIDs, "path", config.Has(RedactionPaths))
		out = append(out, copyItem)
	}
	return out
}

func sanitizeAssessmentSummaryWithConfig(in *AssessmentSummary, config RedactionConfig, proposedContractRefMap map[string]string, compositionIDMap map[string]string) *AssessmentSummary {
	if in == nil {
		return nil
	}
	copySummary := *in
	if in.TopPathToControlFirst != nil {
		paths := sanitizeActionPathsWithConfigAndContractRefs([]risk.ActionPath{*in.TopPathToControlFirst}, config, proposedContractRefMap, compositionIDMap)
		if len(paths) == 1 {
			copySummary.TopPathToControlFirst = &paths[0]
		}
	}
	if in.TopExecutionIdentityBacked != nil {
		paths := sanitizeActionPathsWithConfigAndContractRefs([]risk.ActionPath{*in.TopExecutionIdentityBacked}, config, proposedContractRefMap, compositionIDMap)
		if len(paths) == 1 {
			copySummary.TopExecutionIdentityBacked = &paths[0]
		}
	}
	copySummary.ProofChainPath = sanitizeProofReferenceWithConfig(ProofReference{ChainPath: in.ProofChainPath}, config).ChainPath
	return &copySummary
}

func sanitizeControlPathGraphWithConfig(in *aggattack.ControlPathGraph, config RedactionConfig) *aggattack.ControlPathGraph {
	if in == nil {
		return nil
	}
	copyGraph := *in
	copyGraph.Nodes = append([]aggattack.ControlPathNode(nil), in.Nodes...)
	copyGraph.Edges = append([]aggattack.ControlPathEdge(nil), in.Edges...)
	for idx := range copyGraph.Nodes {
		if config.Has(RedactionGraphRefs) {
			copyGraph.Nodes[idx].NodeID = redactValue("node", copyGraph.Nodes[idx].NodeID, 8)
			copyGraph.Nodes[idx].EvidenceRefs = redactStringSlice(copyGraph.Nodes[idx].EvidenceRefs, "evidence")
			copyGraph.Nodes[idx].AttackPathRefs = redactStringSlice(copyGraph.Nodes[idx].AttackPathRefs, "attack")
		} else {
			copyGraph.Nodes[idx].NodeID = strings.TrimSpace(copyGraph.Nodes[idx].NodeID)
			copyGraph.Nodes[idx].EvidenceRefs = cloneStrings(copyGraph.Nodes[idx].EvidenceRefs)
			copyGraph.Nodes[idx].AttackPathRefs = cloneStrings(copyGraph.Nodes[idx].AttackPathRefs)
		}
		copyGraph.Nodes[idx].PathID = maybeRedactPathID(copyGraph.Nodes[idx].PathID, config)
		copyGraph.Nodes[idx].Org = maybeRedactOrg(copyGraph.Nodes[idx].Org, config)
		copyGraph.Nodes[idx].Repo = maybeRedactRepo(copyGraph.Nodes[idx].Repo, config)
		copyGraph.Nodes[idx].Label = maybeRedactCompositeLabel(copyGraph.Nodes[idx].Label, config)
		copyGraph.Nodes[idx].Location = maybeRedactLocationLike(copyGraph.Nodes[idx].Location, config)
		copyGraph.Nodes[idx].ConfigSource = maybeRedactLocationLike(copyGraph.Nodes[idx].ConfigSource, config)
		copyGraph.Nodes[idx].AuthorityBindingRefs = maybeRedactStringSlice(copyGraph.Nodes[idx].AuthorityBindingRefs, "binding", config.Has(RedactionPaths) || config.Has(RedactionRepos))
		copyGraph.Nodes[idx].MutableEndpointSemantics = sanitizeMutableEndpointSemanticsWithConfig(copyGraph.Nodes[idx].MutableEndpointSemantics, config)
		copyGraph.Nodes[idx].SourceRefs = cloneStrings(copyGraph.Nodes[idx].SourceRefs)
		copyGraph.Nodes[idx].SourceFindingKeys = maybeRedactStringSlice(copyGraph.Nodes[idx].SourceFindingKeys, "finding", shouldRedactFindingKeys(config))
		if copyGraph.Nodes[idx].CredentialAuthority != nil {
			copyGraph.Nodes[idx].CredentialAuthority = agginventory.CloneCredentialAuthority(copyGraph.Nodes[idx].CredentialAuthority)
			copyGraph.Nodes[idx].CredentialAuthority.ReasonCodes = cloneStrings(copyGraph.Nodes[idx].CredentialAuthority.ReasonCodes)
		}
		copyGraph.Nodes[idx].EndpointRefGroupProjection = sanitizeEndpointRefGroupProjectionWithConfig(copyGraph.Nodes[idx].EndpointRefGroupProjection, config)
	}
	for idx := range copyGraph.Edges {
		if config.Has(RedactionGraphRefs) {
			copyGraph.Edges[idx].EdgeID = redactValue("edge", copyGraph.Edges[idx].EdgeID, 8)
			copyGraph.Edges[idx].FromNodeID = redactValue("node", copyGraph.Edges[idx].FromNodeID, 8)
			copyGraph.Edges[idx].ToNodeID = redactValue("node", copyGraph.Edges[idx].ToNodeID, 8)
			copyGraph.Edges[idx].EvidenceRefs = redactStringSlice(copyGraph.Edges[idx].EvidenceRefs, "evidence")
			copyGraph.Edges[idx].AttackPathRefs = redactStringSlice(copyGraph.Edges[idx].AttackPathRefs, "attack")
		} else {
			copyGraph.Edges[idx].EvidenceRefs = cloneStrings(copyGraph.Edges[idx].EvidenceRefs)
			copyGraph.Edges[idx].AttackPathRefs = cloneStrings(copyGraph.Edges[idx].AttackPathRefs)
		}
		copyGraph.Edges[idx].PathID = maybeRedactPathID(copyGraph.Edges[idx].PathID, config)
		copyGraph.Edges[idx].SourceRefs = cloneStrings(copyGraph.Edges[idx].SourceRefs)
		copyGraph.Edges[idx].SourceFindingKeys = maybeRedactStringSlice(copyGraph.Edges[idx].SourceFindingKeys, "finding", shouldRedactFindingKeys(config))
	}
	sortControlPathGraphForReport(&copyGraph)
	return &copyGraph
}

func sanitizeWorkflowChainsWithConfig(in *agentresolver.WorkflowChainArtifact, config RedactionConfig) *agentresolver.WorkflowChainArtifact {
	if in == nil {
		return nil
	}
	copyArtifact := &agentresolver.WorkflowChainArtifact{
		Version: strings.TrimSpace(in.Version),
		Summary: sanitizeWorkflowChainSummaryWithConfig(in.Summary, config),
		Chains:  make([]agentresolver.WorkflowChain, 0, len(in.Chains)),
	}
	for _, chain := range in.Chains {
		copyChain := chain
		copyChain.PathIDs = maybeRedactStringSlice(copyChain.PathIDs, "path", config.Has(RedactionPaths))
		copyChain.GraphNodeRefs = maybeRedactStringSlice(copyChain.GraphNodeRefs, "node", config.Has(RedactionGraphRefs))
		copyChain.GraphEdgeRefs = maybeRedactStringSlice(copyChain.GraphEdgeRefs, "edge", config.Has(RedactionGraphRefs))
		copyChain.ProofRefs = maybeRedactStringSlice(copyChain.ProofRefs, "proof", config.Has(RedactionProofRefs))
		copyChain.EvidenceRefs = maybeRedactStringSlice(copyChain.EvidenceRefs, "evidence", config.Has(RedactionProofRefs) || config.Has(RedactionProviders))
		copyChain.SourceFindingKeys = maybeRedactStringSlice(copyChain.SourceFindingKeys, "finding", shouldRedactFindingKeys(config))
		copyChain.Repo = sanitizeWorkflowChainDimensionWithConfig(copyChain.Repo, config)
		copyChain.PullRequest = sanitizeWorkflowChainDimensionWithConfig(copyChain.PullRequest, config)
		copyChain.Workflow = sanitizeWorkflowChainDimensionWithConfig(copyChain.Workflow, config)
		copyChain.Task = sanitizeWorkflowChainDimensionWithConfig(copyChain.Task, config)
		copyChain.Tool = sanitizeWorkflowChainDimensionWithConfig(copyChain.Tool, config)
		copyChain.Credential = sanitizeWorkflowChainDimensionWithConfig(copyChain.Credential, config)
		copyChain.Owner = sanitizeWorkflowChainDimensionWithConfig(copyChain.Owner, config)
		copyChain.Approval = sanitizeWorkflowChainDimensionWithConfig(copyChain.Approval, config)
		copyChain.Target = sanitizeWorkflowChainDimensionWithConfig(copyChain.Target, config)
		copyChain.Evidence = sanitizeWorkflowChainDimensionWithConfig(copyChain.Evidence, config)
		copyChain.Outcome = sanitizeWorkflowChainDimensionWithConfig(copyChain.Outcome, config)
		copyChain.IntroducedBy = sanitizeIntroducedByWithConfig(copyChain.IntroducedBy, config)
		copyArtifact.Chains = append(copyArtifact.Chains, copyChain)
	}
	return copyArtifact
}

func sanitizeWorkflowChainDimensionWithConfig(in agentresolver.WorkflowChainDimension, config RedactionConfig) agentresolver.WorkflowChainDimension {
	out := in
	out.Key = maybeRedactLocationLike(out.Key, config)
	out.Key = maybeRedactRepo(out.Key, config)
	out.Key = maybeRedactOwner(out.Key, config)
	out.Label = maybeRedactLocationLike(out.Label, config)
	out.Label = maybeRedactRepo(out.Label, config)
	out.Label = maybeRedactOwner(out.Label, config)
	out.EvidenceRefs = maybeRedactStringSlice(out.EvidenceRefs, "evidence", config.Has(RedactionProofRefs) || config.Has(RedactionProviders))
	return out
}

func sanitizeWorkflowChainSummaryWithConfig(in agentresolver.WorkflowChainSummary, config RedactionConfig) agentresolver.WorkflowChainSummary {
	out := in
	out.Repos = sanitizeWorkflowChainRepoRollupsWithConfig(in.Repos, config)
	out.Workflows = sanitizeWorkflowChainWorkflowRollupsWithConfig(in.Workflows, config)
	return out
}

func sanitizeWorkflowChainRepoRollupsWithConfig(in []agentresolver.WorkflowChainRollup, config RedactionConfig) []agentresolver.WorkflowChainRollup {
	if len(in) == 0 {
		return nil
	}
	out := make([]agentresolver.WorkflowChainRollup, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.Value = maybeRedactRepo(copyItem.Value, config)
		out = append(out, copyItem)
	}
	return out
}

func sanitizeWorkflowChainWorkflowRollupsWithConfig(in []agentresolver.WorkflowChainRollup, config RedactionConfig) []agentresolver.WorkflowChainRollup {
	if len(in) == 0 {
		return nil
	}
	out := make([]agentresolver.WorkflowChainRollup, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.Value = maybeRedactLocationLike(copyItem.Value, config)
		out = append(out, copyItem)
	}
	return out
}

func sanitizeControlBacklogWithConfig(in *controlbacklog.Backlog, config RedactionConfig) *controlbacklog.Backlog {
	if in == nil {
		return nil
	}
	copyBacklog := *in
	copyBacklog.Items = append([]controlbacklog.Item(nil), in.Items...)
	for idx := range copyBacklog.Items {
		copyBacklog.Items[idx].Repo = maybeRedactRepo(copyBacklog.Items[idx].Repo, config)
		copyBacklog.Items[idx].Path = maybeRedactLocationLike(copyBacklog.Items[idx].Path, config)
		copyBacklog.Items[idx].Owner = maybeRedactOwner(copyBacklog.Items[idx].Owner, config)
		copyBacklog.Items[idx].ReviewOwner = maybeRedactOwner(copyBacklog.Items[idx].ReviewOwner, config)
		copyBacklog.Items[idx].ReviewSource = maybeRedactCompositeLabel(copyBacklog.Items[idx].ReviewSource, config)
		copyBacklog.Items[idx].ReviewRationale = maybeRedactCompositeLabel(copyBacklog.Items[idx].ReviewRationale, config)
		copyBacklog.Items[idx].LinkedFindingIDs = maybeRedactStringSlice(copyBacklog.Items[idx].LinkedFindingIDs, "finding", shouldRedactFindingKeys(config))
		copyBacklog.Items[idx].LinkedActionPathID = maybeRedactPathID(copyBacklog.Items[idx].LinkedActionPathID, config)
		copyBacklog.Items[idx].LinkedControlPathNodeIDs = maybeRedactStringSlice(copyBacklog.Items[idx].LinkedControlPathNodeIDs, "node", config.Has(RedactionGraphRefs))
		copyBacklog.Items[idx].LinkedControlPathEdgeIDs = maybeRedactStringSlice(copyBacklog.Items[idx].LinkedControlPathEdgeIDs, "edge", config.Has(RedactionGraphRefs))
		copyBacklog.Items[idx].OwnershipEvidence = cloneStrings(copyBacklog.Items[idx].OwnershipEvidence)
		copyBacklog.Items[idx].OwnershipConflicts = maybeRedactStringSlice(copyBacklog.Items[idx].OwnershipConflicts, "owner", config.Has(RedactionOwners))
		copyBacklog.Items[idx].EvidenceDecisions = sanitizeEvidenceDecisionsWithConfig(copyBacklog.Items[idx].EvidenceDecisions, config)
		copyBacklog.Items[idx].ControlEvidenceRefs = maybeRedactEvidenceRefSlice(copyBacklog.Items[idx].ControlEvidenceRefs, config)
		copyBacklog.Items[idx].ConstraintEvidenceRefs = maybeRedactEvidenceRefSlice(copyBacklog.Items[idx].ConstraintEvidenceRefs, config)
		copyBacklog.Items[idx].TargetClassEvidenceRefs = maybeRedactEvidenceRefSlice(copyBacklog.Items[idx].TargetClassEvidenceRefs, config)
		copyBacklog.Items[idx].ActionPathTypeEvidenceRefs = maybeRedactEvidenceRefSlice(copyBacklog.Items[idx].ActionPathTypeEvidenceRefs, config)
		copyBacklog.Items[idx].AutonomyTierEvidenceRefs = maybeRedactEvidenceRefSlice(copyBacklog.Items[idx].AutonomyTierEvidenceRefs, config)
		copyBacklog.Items[idx].RiskClassificationValidationRefs = maybeRedactEvidenceRefSlice(copyBacklog.Items[idx].RiskClassificationValidationRefs, config)
		copyBacklog.Items[idx].ClosureRequirements = sanitizeClosureRequirementsWithConfig(copyBacklog.Items[idx].ClosureRequirements, config)
		copyBacklog.Items[idx].ClosureActions = sanitizeClosureActionsWithConfig(copyBacklog.Items[idx].ClosureActions, config)
		copyBacklog.Items[idx].EvidenceCompleteness = risk.CloneEvidenceCompleteness(copyBacklog.Items[idx].EvidenceCompleteness)
		copyBacklog.Items[idx].GovernanceDisposition = sanitizeGovernanceDispositionWithConfig(copyBacklog.Items[idx].GovernanceDisposition, config)
		copyBacklog.Items[idx].LifecycleQueue = sanitizeLifecycleQueueWithConfig(copyBacklog.Items[idx].LifecycleQueue, config)
		copyBacklog.Items[idx].ProductionContext = sanitizeProductionContextWithConfig(copyBacklog.Items[idx].ProductionContext, config)
		copyBacklog.Items[idx].ReviewAuditContext = sanitizeReviewAuditContextWithConfig(copyBacklog.Items[idx].ReviewAuditContext, config)
		copyBacklog.Items[idx].ResolvedAppendixRefs = maybeRedactLocationLikeSlice(copyBacklog.Items[idx].ResolvedAppendixRefs, config)
		copyBacklog.Items[idx].ReopenEvidenceRefs = maybeRedactEvidenceRefSlice(copyBacklog.Items[idx].ReopenEvidenceRefs, config)
		copyBacklog.Items[idx].PolicyRefs = maybeRedactStringSlice(copyBacklog.Items[idx].PolicyRefs, "policy", config.Has(RedactionPaths) || config.Has(RedactionRepos) || config.Has(RedactionProofRefs))
		copyBacklog.Items[idx].PolicyEvidenceRefs = maybeRedactEvidenceRefSlice(copyBacklog.Items[idx].PolicyEvidenceRefs, config)
		copyBacklog.Items[idx].HighStakesPresets = sanitizeHighStakesPresetsWithConfig(copyBacklog.Items[idx].HighStakesPresets, config)
		copyBacklog.Items[idx].SecurityTestRecipes = sanitizeSecurityTestRecipesWithConfig(copyBacklog.Items[idx].SecurityTestRecipes, config)
		if copyBacklog.Items[idx].CredentialProvenance != nil {
			copyBacklog.Items[idx].CredentialProvenance = agginventory.CloneCredentialProvenance(copyBacklog.Items[idx].CredentialProvenance)
			copyBacklog.Items[idx].CredentialProvenance.Subject = maybeRedactCredentialSubject(copyBacklog.Items[idx].CredentialProvenance.Subject, config)
			copyBacklog.Items[idx].CredentialProvenance.EvidenceBasis = cloneStrings(copyBacklog.Items[idx].CredentialProvenance.EvidenceBasis)
			copyBacklog.Items[idx].CredentialProvenance.EvidenceLocation = maybeRedactLocationLike(copyBacklog.Items[idx].CredentialProvenance.EvidenceLocation, config)
		}
		if copyBacklog.Items[idx].CredentialAuthority != nil {
			copyBacklog.Items[idx].CredentialAuthority = agginventory.CloneCredentialAuthority(copyBacklog.Items[idx].CredentialAuthority)
			copyBacklog.Items[idx].CredentialAuthority.ReasonCodes = cloneStrings(copyBacklog.Items[idx].CredentialAuthority.ReasonCodes)
		}
	}
	return &copyBacklog
}

func sanitizeAgentActionBOMWithConfig(in *AgentActionBOM, profile ShareProfile, config RedactionConfig) *AgentActionBOM {
	if in == nil {
		return nil
	}
	copyBOM := *in
	copyBOM.ShareProfile = string(profile)
	copyBOM.ShareProfileMetadata = cloneShareProfileMetadata(in.ShareProfileMetadata)
	copyBOM.Summary.EvidenceCompleteness = risk.CloneEvidenceCompletenessSummary(in.Summary.EvidenceCompleteness)
	copyBOM.ScanQuality = sanitizeScanQualityWithConfig(in.ScanQuality, config)
	copyBOM.ComposedActionPaths = sanitizeComposedActionPathsWithConfig(in.ComposedActionPaths, config)
	proposedContractRefMap := proposedActionContractRefMap(in.ComposedActionPaths, copyBOM.ComposedActionPaths)
	compositionIDMap := compositionRefMap(in.ComposedActionPaths, copyBOM.ComposedActionPaths)
	compositionProjectionMap := primaryViewCompositionProjectionMap(in.ComposedActionPaths, copyBOM.ComposedActionPaths)
	copyBOM.EvidenceRefs = maybeRedactStringSlice(in.EvidenceRefs, "evidence", config.Has(RedactionProofRefs))
	copyBOM.ProofRefs = maybeRedactStringSlice(in.ProofRefs, "proof", config.Has(RedactionProofRefs))
	copyBOM.GraphRefs = sanitizeGraphRefsWithConfig(in.GraphRefs, config)
	copyBOM.Summary.PrimaryView = sanitizePrimaryViewWithContractRefs(in.Summary.PrimaryView, config, proposedContractRefMap, compositionIDMap, compositionProjectionMap)
	copyBOM.Items = append([]AgentActionBOMItem(nil), in.Items...)
	for idx := range copyBOM.Items {
		copyBOM.Items[idx].PathID = maybeRedactPathID(copyBOM.Items[idx].PathID, config)
		copyBOM.Items[idx].Org = maybeRedactOrg(copyBOM.Items[idx].Org, config)
		copyBOM.Items[idx].Repo = maybeRedactRepo(copyBOM.Items[idx].Repo, config)
		copyBOM.Items[idx].Location = maybeRedactLocationLike(copyBOM.Items[idx].Location, config)
		copyBOM.Items[idx].Owner = maybeRedactOwner(copyBOM.Items[idx].Owner, config)
		copyBOM.Items[idx].ReviewOwner = maybeRedactOwner(copyBOM.Items[idx].ReviewOwner, config)
		copyBOM.Items[idx].ReviewSource = maybeRedactCompositeLabel(copyBOM.Items[idx].ReviewSource, config)
		copyBOM.Items[idx].ReviewRationale = maybeRedactCompositeLabel(copyBOM.Items[idx].ReviewRationale, config)
		copyBOM.Items[idx].ConfigSource = maybeRedactLocationLike(copyBOM.Items[idx].ConfigSource, config)
		copyBOM.Items[idx].OccurrenceRefs = maybeRedactStringSlice(copyBOM.Items[idx].OccurrenceRefs, "path", config.Has(RedactionPaths) || config.Has(RedactionRepos))
		copyBOM.Items[idx].ProofRefs = maybeRedactStringSlice(copyBOM.Items[idx].ProofRefs, "proof", config.Has(RedactionProofRefs))
		copyBOM.Items[idx].RuntimeSessionRefs = maybeRedactStringSlice(copyBOM.Items[idx].RuntimeSessionRefs, "session", config.Has(RedactionPaths) || config.Has(RedactionProofRefs))
		for itemIdx := range copyBOM.Items[idx].ObservedChangedFiles {
			copyBOM.Items[idx].ObservedChangedFiles[itemIdx] = maybeRedactLocationLike(copyBOM.Items[idx].ObservedChangedFiles[itemIdx], config)
		}
		copyBOM.Items[idx].RuntimeEvidenceRefs = maybeRedactEvidenceRefSlice(copyBOM.Items[idx].RuntimeEvidenceRefs, config)
		copyBOM.Items[idx].PolicyRefs = maybeRedactStringSlice(copyBOM.Items[idx].PolicyRefs, "policy", config.Has(RedactionPaths) || config.Has(RedactionRepos) || config.Has(RedactionProofRefs))
		copyBOM.Items[idx].PolicyEvidenceRefs = maybeRedactEvidenceRefSlice(copyBOM.Items[idx].PolicyEvidenceRefs, config)
		copyBOM.Items[idx].ControlEvidenceRefs = maybeRedactEvidenceRefSlice(copyBOM.Items[idx].ControlEvidenceRefs, config)
		copyBOM.Items[idx].ConstraintEvidenceRefs = maybeRedactEvidenceRefSlice(copyBOM.Items[idx].ConstraintEvidenceRefs, config)
		copyBOM.Items[idx].TargetClassEvidenceRefs = maybeRedactEvidenceRefSlice(copyBOM.Items[idx].TargetClassEvidenceRefs, config)
		copyBOM.Items[idx].ActionPathTypeEvidenceRefs = maybeRedactEvidenceRefSlice(copyBOM.Items[idx].ActionPathTypeEvidenceRefs, config)
		copyBOM.Items[idx].AutonomyTierEvidenceRefs = maybeRedactEvidenceRefSlice(copyBOM.Items[idx].AutonomyTierEvidenceRefs, config)
		copyBOM.Items[idx].RiskClassificationValidationRefs = maybeRedactEvidenceRefSlice(copyBOM.Items[idx].RiskClassificationValidationRefs, config)
		copyBOM.Items[idx].ClosureRequirements = sanitizeClosureRequirementsWithConfig(copyBOM.Items[idx].ClosureRequirements, config)
		copyBOM.Items[idx].ClosureActions = sanitizeClosureActionsWithConfig(copyBOM.Items[idx].ClosureActions, config)
		copyBOM.Items[idx].EvidenceCompleteness = risk.CloneEvidenceCompleteness(copyBOM.Items[idx].EvidenceCompleteness)
		copyBOM.Items[idx].GovernanceDisposition = sanitizeGovernanceDispositionWithConfig(copyBOM.Items[idx].GovernanceDisposition, config)
		copyBOM.Items[idx].LifecycleQueue = sanitizeLifecycleQueueWithConfig(copyBOM.Items[idx].LifecycleQueue, config)
		copyBOM.Items[idx].AttackPathRefs = maybeRedactStringSlice(copyBOM.Items[idx].AttackPathRefs, "attack", config.Has(RedactionGraphRefs))
		copyBOM.Items[idx].SourceFindingKeys = maybeRedactStringSlice(copyBOM.Items[idx].SourceFindingKeys, "finding", shouldRedactFindingKeys(config))
		copyBOM.Items[idx].CompositionIDs = remapCompositionRefs(copyBOM.Items[idx].CompositionIDs, compositionIDMap)
		copyBOM.Items[idx].ProposedActionContractRefs = remapProposedActionContractRefs(copyBOM.Items[idx].ProposedActionContractRefs, proposedContractRefMap)
		copyBOM.Items[idx].EvidenceRefs = maybeRedactStringSlice(copyBOM.Items[idx].EvidenceRefs, "evidence", config.Has(RedactionProofRefs))
		copyBOM.Items[idx].GraphRefs = sanitizeGraphRefsWithConfig(copyBOM.Items[idx].GraphRefs, config)
		copyBOM.Items[idx].Reachability = sanitizeReachabilityWithConfig(copyBOM.Items[idx].Reachability, config)
		copyBOM.Items[idx].ReachableServers = sanitizeReachabilityWithConfig(copyBOM.Items[idx].ReachableServers, config)
		copyBOM.Items[idx].ReachableTools = sanitizeReachabilityWithConfig(copyBOM.Items[idx].ReachableTools, config)
		copyBOM.Items[idx].ReachableEndpoints = sanitizeReachabilityWithConfig(copyBOM.Items[idx].ReachableEndpoints, config)
		copyBOM.Items[idx].ReachableTargets = sanitizeReachabilityWithConfig(copyBOM.Items[idx].ReachableTargets, config)
		copyBOM.Items[idx].ReachableAPIs = sanitizeReachabilityWithConfig(copyBOM.Items[idx].ReachableAPIs, config)
		copyBOM.Items[idx].ReachableAgents = sanitizeReachabilityWithConfig(copyBOM.Items[idx].ReachableAgents, config)
		if copyBOM.Items[idx].CredentialProvenance != nil {
			copyBOM.Items[idx].CredentialProvenance = agginventory.CloneCredentialProvenance(copyBOM.Items[idx].CredentialProvenance)
			copyBOM.Items[idx].CredentialProvenance.Subject = maybeRedactCredentialSubject(copyBOM.Items[idx].CredentialProvenance.Subject, config)
			copyBOM.Items[idx].CredentialProvenance.EvidenceBasis = cloneStrings(copyBOM.Items[idx].CredentialProvenance.EvidenceBasis)
			copyBOM.Items[idx].CredentialProvenance.EvidenceLocation = maybeRedactLocationLike(copyBOM.Items[idx].CredentialProvenance.EvidenceLocation, config)
		}
		if copyBOM.Items[idx].CredentialAuthority != nil {
			copyBOM.Items[idx].CredentialAuthority = agginventory.CloneCredentialAuthority(copyBOM.Items[idx].CredentialAuthority)
			copyBOM.Items[idx].CredentialAuthority.ReasonCodes = cloneStrings(copyBOM.Items[idx].CredentialAuthority.ReasonCodes)
		}
		copyBOM.Items[idx].EndpointRefGroupProjection = sanitizeEndpointRefGroupProjectionWithConfig(copyBOM.Items[idx].EndpointRefGroupProjection, config)
		copyBOM.Items[idx].MutableEndpointSemantics = sanitizeMutableEndpointSemanticsWithConfig(copyBOM.Items[idx].MutableEndpointSemantics, config)
		copyBOM.Items[idx].Credentials = redactCredentialsWithConfig(copyBOM.Items[idx].Credentials, config)
		copyBOM.Items[idx].ActionLineage = sanitizeActionLineageWithConfig(copyBOM.Items[idx].ActionLineage, config)
		copyBOM.Items[idx].IntroducedBy = sanitizeIntroducedByWithConfig(copyBOM.Items[idx].IntroducedBy, config)
		copyBOM.Items[idx].AgenticDeliverySystemChange = sanitizeAgenticDeliverySystemChangeWithConfig(copyBOM.Items[idx].AgenticDeliverySystemChange, config)
		copyBOM.Items[idx].RuntimeProvider = maybeRedactProviderContext(copyBOM.Items[idx].RuntimeProvider, config)
		copyBOM.Items[idx].RuntimeHost = maybeRedactProviderContext(copyBOM.Items[idx].RuntimeHost, config)
		copyBOM.Items[idx].RuntimeKind = maybeRedactProviderContext(copyBOM.Items[idx].RuntimeKind, config)
		copyBOM.Items[idx].ModelProvider = maybeRedactProviderContext(copyBOM.Items[idx].ModelProvider, config)
		copyBOM.Items[idx].ModelVersion = maybeRedactProviderContext(copyBOM.Items[idx].ModelVersion, config)
		copyBOM.Items[idx].ExecutionEnvironment = maybeRedactProviderContext(copyBOM.Items[idx].ExecutionEnvironment, config)
		copyBOM.Items[idx].StateLocationRefs = maybeRedactLocationLikeSlice(copyBOM.Items[idx].StateLocationRefs, config)
		copyBOM.Items[idx].StateDigestRefs = maybeRedactStringSlice(copyBOM.Items[idx].StateDigestRefs, "digest", config.Has(RedactionProofRefs))
		copyBOM.Items[idx].AgentIdentity = sanitizeAgentIdentityWithConfig(copyBOM.Items[idx].AgentIdentity, config)
		copyBOM.Items[idx].DecisionPrecedent = sanitizeDecisionPrecedentWithConfig(copyBOM.Items[idx].DecisionPrecedent, config)
		copyBOM.Items[idx].DeliveryControlContext = sanitizeDeliveryControlContextWithConfig(copyBOM.Items[idx].DeliveryControlContext, config)
		copyBOM.Items[idx].ReviewAuditContext = sanitizeReviewAuditContextWithConfig(copyBOM.Items[idx].ReviewAuditContext, config)
		copyBOM.Items[idx].ResolvedAppendixRefs = maybeRedactLocationLikeSlice(copyBOM.Items[idx].ResolvedAppendixRefs, config)
		copyBOM.Items[idx].ReopenEvidenceRefs = maybeRedactEvidenceRefSlice(copyBOM.Items[idx].ReopenEvidenceRefs, config)
		copyBOM.Items[idx].HighStakesPresets = sanitizeHighStakesPresetsWithConfig(copyBOM.Items[idx].HighStakesPresets, config)
		copyBOM.Items[idx].EvidenceDecisions = sanitizeEvidenceDecisionsWithConfig(copyBOM.Items[idx].EvidenceDecisions, config)
		copyBOM.Items[idx].ProductionContext = sanitizeProductionContextWithConfig(copyBOM.Items[idx].ProductionContext, config)
		copyBOM.Items[idx].EvidencePacketRefs = maybeRedactStringSlice(copyBOM.Items[idx].EvidencePacketRefs, "packet", config.Has(RedactionPaths) || config.Has(RedactionProofRefs))
		copyBOM.Items[idx].DecisionTraceRefs = maybeRedactStringSlice(copyBOM.Items[idx].DecisionTraceRefs, "proof", config.Has(RedactionProofRefs))
	}
	copyBOM.focusSourceItems = append([]AgentActionBOMItem(nil), copyBOM.Items...)
	return &copyBOM
}

func sanitizeReviewAuditContextWithConfig(in *risk.ReviewAuditContext, config RedactionConfig) *risk.ReviewAuditContext {
	if in == nil {
		return nil
	}
	out := risk.CloneReviewAuditContext(in)
	out.Owner = maybeRedactOwner(out.Owner, config)
	out.Source = maybeRedactCompositeLabel(out.Source, config)
	out.Rationale = maybeRedactCompositeLabel(out.Rationale, config)
	out.EvidenceRefs = maybeRedactEvidenceRefSlice(out.EvidenceRefs, config)
	return out
}

func sanitizePrimaryViewWithContractRefs(in *AgentActionBOMPrimaryView, config RedactionConfig, proposedContractRefMap map[string]string, compositionIDMap map[string]string, compositionProjectionMap map[string]risk.ComposedActionPath) *AgentActionBOMPrimaryView {
	if in == nil {
		return nil
	}
	out := *in
	out.PathID = maybeRedactPathID(in.PathID, config)
	out.PathMap = AgentActionBOMPrimaryPathMap{
		Tool:       maybeRedactCompositeLabel(in.PathMap.Tool, config),
		RepoPR:     maybeRedactCompositeLabel(in.PathMap.RepoPR, config),
		Workflow:   maybeRedactLocationLike(in.PathMap.Workflow, config),
		Credential: maybeRedactCompositeLabel(in.PathMap.Credential, config),
		Action:     strings.TrimSpace(in.PathMap.Action),
		Target:     maybeRedactCompositeLabel(in.PathMap.Target, config),
	}
	out.TodayPath = risk.CloneGovernedPathView(in.TodayPath)
	out.RecommendedGovernedPath = risk.CloneGovernedPathView(in.RecommendedGovernedPath)
	out.RecommendedActionContract = risk.CloneRecommendedActionContract(in.RecommendedActionContract)
	out.AgenticDeliverySystemChange = sanitizeAgenticDeliverySystemChangeWithConfig(in.AgenticDeliverySystemChange, config)
	out.RuntimeProvider = maybeRedactProviderContext(in.RuntimeProvider, config)
	out.RuntimeHost = maybeRedactProviderContext(in.RuntimeHost, config)
	out.RuntimeKind = maybeRedactProviderContext(in.RuntimeKind, config)
	out.ModelProvider = maybeRedactProviderContext(in.ModelProvider, config)
	out.ModelVersion = maybeRedactProviderContext(in.ModelVersion, config)
	out.ExecutionEnvironment = maybeRedactProviderContext(in.ExecutionEnvironment, config)
	out.AgentIdentity = sanitizeAgentIdentityWithConfig(in.AgentIdentity, config)
	out.DecisionPrecedent = sanitizeDecisionPrecedentWithConfig(in.DecisionPrecedent, config)
	out.DeliveryControlContext = sanitizeDeliveryControlContextWithConfig(in.DeliveryControlContext, config)
	out.WorkflowChainRefs = maybeRedactStringSlice(in.WorkflowChainRefs, "chain", config.Has(RedactionPaths) || config.Has(RedactionGraphRefs))
	out.CompositionID = remapPrimaryViewCompositionID(in.CompositionID, compositionIDMap, config.Has(RedactionPaths) || config.Has(RedactionRepos))
	out.CompositionIDs = remapCompositionRefs(in.CompositionIDs, compositionIDMap)
	if composition := primaryViewSanitizedComposition(in, compositionProjectionMap); composition != nil {
		applyPrimaryViewCompositionProjection(&out, *composition)
	} else {
		out.CompositionStageMap = sanitizePrimaryViewCompositionStagesWithConfig(in.CompositionStageMap, config)
		out.CredentialSummary = maybeRedactCompositeLabel(in.CredentialSummary, config)
		out.TargetSummary = maybeRedactCompositeLabel(in.TargetSummary, config)
		if config.Has(RedactionPaths) || config.Has(RedactionRepos) {
			out.ExpectedOutcome = redactValue("outcome", in.ExpectedOutcome, 8)
		} else {
			out.ExpectedOutcome = strings.TrimSpace(in.ExpectedOutcome)
		}
		if config.Has(RedactionPaths) || config.Has(RedactionRepos) || config.Has(RedactionProofRefs) || config.Has(RedactionOwners) {
			out.ProposedActionContract = sanitizeProposedActionContractPublic(in.ProposedActionContract)
		} else {
			out.ProposedActionContract = risk.CloneProposedActionContract(in.ProposedActionContract)
		}
		if out.ProposedActionContract != nil && strings.TrimSpace(out.CompositionID) != "" && (config.Has(RedactionPaths) || config.Has(RedactionRepos)) {
			out.ProposedActionContract.CompositionRef = out.CompositionID
			risk.RefreshProposedActionContractIdentity(out.ProposedActionContract)
		}
		out.ClosureRequirements = sanitizeClosureRequirementsWithConfig(in.ClosureRequirements, config)
	}
	if strings.TrimSpace(out.CompositionID) != "" {
		out.CompositionIDs = uniqueSortedStrings(append(out.CompositionIDs, out.CompositionID))
	}
	out.ProposedActionContractRefs = remapProposedActionContractRefs(in.ProposedActionContractRefs, proposedContractRefMap)
	if out.ProposedActionContract != nil {
		out.ProposedActionContractRefs = sanitizeProposedActionContractRefs(out.ProposedActionContract, out.ProposedActionContractRefs)
	}
	out.GraphRefs = sanitizeGraphRefsWithConfig(in.GraphRefs, config)
	out.ProofRefs = maybeRedactStringSlice(in.ProofRefs, "proof", config.Has(RedactionProofRefs))
	out.EvidencePacketRefs = maybeRedactStringSlice(in.EvidencePacketRefs, "packet", config.Has(RedactionPaths) || config.Has(RedactionProofRefs))
	out.DecisionTraceRefs = maybeRedactStringSlice(in.DecisionTraceRefs, "proof", config.Has(RedactionProofRefs))
	out.AppendixRefs = cloneStrings(in.AppendixRefs)
	out.UnresolvedEvidence = cloneStrings(in.UnresolvedEvidence)
	out.RecommendedNextActions = cloneStrings(in.RecommendedNextActions)
	out.CoverageReasons = cloneStrings(in.CoverageReasons)
	return &out
}

func sanitizePrimaryViewCompositionStagesWithConfig(in []AgentActionBOMCompositionStage, config RedactionConfig) []AgentActionBOMCompositionStage {
	if len(in) == 0 {
		return nil
	}
	stageIDMap := map[string]string{}
	out := make([]AgentActionBOMCompositionStage, 0, len(in))
	for _, stage := range in {
		copyStage := stage
		if config.Has(RedactionPaths) || config.Has(RedactionRepos) {
			copyStage.StageID = remapStageID(copyStage.StageID, stageIDMap)
		}
		copyStage.PathID = maybeRedactPathID(copyStage.PathID, config)
		copyStage.Location = maybeRedactLocationLike(copyStage.Location, config)
		out = append(out, copyStage)
	}
	return out
}

func sanitizeAgenticDeliverySystemChangeWithConfig(in *risk.AgenticDeliverySystemChange, config RedactionConfig) *risk.AgenticDeliverySystemChange {
	if in == nil {
		return nil
	}
	out := risk.CloneAgenticDeliverySystemChange(in)
	out.ChangeID = maybeRedactPathID(out.ChangeID, config)
	out.ChangedArtifact = maybeRedactLocationLike(out.ChangedArtifact, config)
	out.ReachableTargets = maybeRedactStringSlice(out.ReachableTargets, "target", config.Has(RedactionPaths) || config.Has(RedactionRepos))
	out.EvidenceRefs = maybeRedactStringSlice(out.EvidenceRefs, "evidence", config.Has(RedactionProofRefs))
	return out
}

func sanitizeAgentIdentityWithConfig(in *risk.AgentIdentity, config RedactionConfig) *risk.AgentIdentity {
	if in == nil {
		return nil
	}
	out := risk.CloneAgentIdentity(in)
	out.IdentityKey = maybeRedactPathID(out.IdentityKey, config)
	out.AgentID = maybeRedactPathID(out.AgentID, config)
	out.HumanOwner = maybeRedactOwner(out.HumanOwner, config)
	out.RuntimeProvider = maybeRedactProviderContext(out.RuntimeProvider, config)
	out.RuntimeKind = maybeRedactProviderContext(out.RuntimeKind, config)
	out.ModelProvider = maybeRedactProviderContext(out.ModelProvider, config)
	out.CredentialUsed = maybeRedactCredentialSubject(out.CredentialUsed, config)
	out.Scope = maybeRedactCompositeLabel(out.Scope, config)
	return out
}

func sanitizeDecisionPrecedentWithConfig(in *risk.DecisionPrecedent, config RedactionConfig) *risk.DecisionPrecedent {
	if in == nil {
		return nil
	}
	out := risk.CloneDecisionPrecedent(in)
	out.PrecedentKey = maybeRedactPathID(out.PrecedentKey, config)
	out.DecisionTraceRef = maybeRedactPathID(out.DecisionTraceRef, config)
	out.EvidenceRefs = maybeRedactStringSlice(out.EvidenceRefs, "evidence", config.Has(RedactionProofRefs))
	return out
}

func sanitizeDeliveryControlContextWithConfig(in *risk.DeliveryControlContext, config RedactionConfig) *risk.DeliveryControlContext {
	if in == nil {
		return nil
	}
	out := risk.CloneDeliveryControlContext(in)
	out.ResolverRefs = maybeRedactLocationLikeSlice(out.ResolverRefs, config)
	out.EvalConfigRefs = maybeRedactLocationLikeSlice(out.EvalConfigRefs, config)
	out.SandboxGates = maybeRedactLocationLikeSlice(out.SandboxGates, config)
	out.TestGates = maybeRedactCompositeLabelSlice(out.TestGates, config)
	return out
}

func sanitizeProductionContextWithConfig(in *risk.ProductionContext, config RedactionConfig) *risk.ProductionContext {
	if in == nil {
		return nil
	}
	out := risk.CloneProductionContext(in)
	out.SurfaceLabel = maybeRedactCompositeLabel(out.SurfaceLabel, config)
	out.Owner = maybeRedactOwner(out.Owner, config)
	out.MutableEndpointOperations = maybeRedactCompositeLabelSlice(out.MutableEndpointOperations, config)
	out.EvidenceRefs = maybeRedactStringSlice(out.EvidenceRefs, "evidence", config.Has(RedactionProofRefs) || config.Has(RedactionPaths) || config.Has(RedactionRepos))
	return out
}

func sanitizeHighStakesPresetsWithConfig(in []risk.HighStakesPreset, config RedactionConfig) []risk.HighStakesPreset {
	if len(in) == 0 {
		return nil
	}
	out := risk.CloneHighStakesPresets(in)
	for idx := range out {
		out[idx].EvidenceRefs = maybeRedactEvidenceRefSlice(out[idx].EvidenceRefs, config)
	}
	return out
}

func sanitizeSecurityTestRecipesWithConfig(in []controlbacklog.SecurityTestRecipe, config RedactionConfig) []controlbacklog.SecurityTestRecipe {
	if len(in) == 0 {
		return nil
	}
	out := make([]controlbacklog.SecurityTestRecipe, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.EvidenceRefs = maybeRedactEvidenceRefSlice(copyItem.EvidenceRefs, config)
		out = append(out, copyItem)
	}
	return out
}

func sanitizeEvidenceDecisionsWithConfig(in []evidencepolicy.Decision, config RedactionConfig) []evidencepolicy.Decision {
	if len(in) == 0 {
		return nil
	}
	out := make([]evidencepolicy.Decision, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.SelectedEvidenceRefs = maybeRedactStringSlice(copyItem.SelectedEvidenceRefs, "evidence", config.Has(RedactionProofRefs) || config.Has(RedactionPaths) || config.Has(RedactionRepos))
		if evidenceDecisionRequiresOwnerRedaction(copyItem) {
			copyItem.SelectedValue = maybeRedactOwner(copyItem.SelectedValue, config)
			copyItem.SelectedIssuer = maybeRedactOwner(copyItem.SelectedIssuer, config)
		} else {
			copyItem.SelectedValue = strings.TrimSpace(copyItem.SelectedValue)
			copyItem.SelectedIssuer = strings.TrimSpace(copyItem.SelectedIssuer)
		}
		if len(copyItem.RejectedCandidates) > 0 {
			copyItem.RejectedCandidates = make([]evidencepolicy.Candidate, 0, len(copyItem.RejectedCandidates))
			for _, candidate := range item.RejectedCandidates {
				copyCandidate := candidate
				copyCandidate.EvidenceRefs = maybeRedactStringSlice(copyCandidate.EvidenceRefs, "evidence", config.Has(RedactionProofRefs) || config.Has(RedactionPaths) || config.Has(RedactionRepos))
				if evidenceCandidateRequiresOwnerRedaction(copyItem, copyCandidate) {
					copyCandidate.Value = maybeRedactOwner(copyCandidate.Value, config)
					copyCandidate.Issuer = maybeRedactOwner(copyCandidate.Issuer, config)
				} else {
					copyCandidate.Value = strings.TrimSpace(copyCandidate.Value)
					copyCandidate.Issuer = strings.TrimSpace(copyCandidate.Issuer)
				}
				copyItem.RejectedCandidates = append(copyItem.RejectedCandidates, copyCandidate)
			}
		}
		out = append(out, copyItem)
	}
	return out
}

func maybeRedactEvidenceRefSlice(values []string, config RedactionConfig) []string {
	return maybeRedactStringSlice(values, "evidence", config.Has(RedactionProofRefs) || config.Has(RedactionPaths) || config.Has(RedactionRepos))
}

func maybeRedactCorrelationRefSlice(values []string, config RedactionConfig) []string {
	if config.Has(RedactionProofRefs) || config.Has(RedactionPaths) || config.Has(RedactionRepos) {
		return redactStringSlice(values, "evidence")
	}
	if !config.Has(RedactionGraphRefs) {
		return cloneStrings(values)
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if isGraphCorrelationRef(value) {
			out = append(out, redactValue("correlation", value, 8))
			continue
		}
		out = append(out, value)
	}
	return out
}

func isGraphCorrelationRef(value string) bool {
	return strings.HasPrefix(strings.TrimSpace(value), "graph_edge:")
}

func evidenceDecisionRequiresOwnerRedaction(in evidencepolicy.Decision) bool {
	if evidenceFieldIsOwnerLike(in.Field) || evidenceTokenIsOwnerLike(in.SelectedSourceType) || evidenceTokenIsOwnerLike(in.SelectedStatus) {
		return true
	}
	for _, candidate := range in.RejectedCandidates {
		if evidenceFieldIsOwnerLike(candidate.Field) || evidenceTokenIsOwnerLike(candidate.SourceType) || evidenceTokenIsOwnerLike(candidate.Status) {
			return true
		}
	}
	return false
}

func evidenceCandidateRequiresOwnerRedaction(decision evidencepolicy.Decision, candidate evidencepolicy.Candidate) bool {
	return evidenceDecisionRequiresOwnerRedaction(decision) || evidenceFieldIsOwnerLike(candidate.Field) || evidenceTokenIsOwnerLike(candidate.SourceType) || evidenceTokenIsOwnerLike(candidate.Status)
}

func evidenceFieldIsOwnerLike(value string) bool {
	return strings.EqualFold(strings.TrimSpace(value), evidencepolicy.FieldOwner)
}

func evidenceTokenIsOwnerLike(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == evidencepolicy.FieldOwner || strings.Contains(normalized, "owner")
}

func maybeRedactProviderContext(value string, config RedactionConfig) string {
	if config.Has(RedactionProviders) {
		return redactValue("provider", strings.TrimSpace(value), 8)
	}
	return strings.TrimSpace(value)
}

func maybeRedactLocationLikeSlice(values []string, config RedactionConfig) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, maybeRedactLocationLike(value, config))
	}
	return out
}

func maybeRedactCompositeLabelSlice(values []string, config RedactionConfig) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, maybeRedactCompositeLabel(value, config))
	}
	return out
}

func sanitizeGovernanceDispositionWithConfig(in *controlbacklog.GovernanceDisposition, config RedactionConfig) *controlbacklog.GovernanceDisposition {
	if in == nil {
		return nil
	}
	copyItem := *in
	copyItem.Issuer = maybeRedactOwner(copyItem.Issuer, config)
	copyItem.EvidenceRefs = maybeRedactStringSlice(copyItem.EvidenceRefs, "evidence", config.Has(RedactionProofRefs))
	return &copyItem
}

func sanitizeLifecycleQueueWithConfig(in *governancequeue.Item, config RedactionConfig) *governancequeue.Item {
	if in == nil {
		return nil
	}
	copyItem := *in
	copyItem.AgentID = maybeRedactPathID(copyItem.AgentID, config)
	copyItem.Repo = maybeRedactRepo(copyItem.Repo, config)
	copyItem.Path = maybeRedactLocationLike(copyItem.Path, config)
	copyItem.Owner = maybeRedactOwner(copyItem.Owner, config)
	copyItem.EvidenceRefs = maybeRedactStringSlice(copyItem.EvidenceRefs, "evidence", config.Has(RedactionProofRefs))
	copyItem.SourceConflicts = maybeRedactStringSlice(copyItem.SourceConflicts, "owner", config.Has(RedactionOwners))
	return &copyItem
}

func sanitizeReachabilityWithConfig(in []AgentActionBOMReachability, config RedactionConfig) []AgentActionBOMReachability {
	if len(in) == 0 {
		return nil
	}
	out := make([]AgentActionBOMReachability, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.EvidenceRefs = maybeRedactStringSlice(copyItem.EvidenceRefs, "evidence", config.Has(RedactionProofRefs))
		switch strings.TrimSpace(copyItem.Surface) {
		case "reachable_endpoint", "reachable_target":
			if config.Has(RedactionPaths) {
				copyItem.Name = redactValue("endpoint", copyItem.Name, 8)
			}
		}
		out = append(out, copyItem)
	}
	return out
}

func sanitizeClosureRequirementsWithConfig(in []risk.ClosureRequirement, config RedactionConfig) []risk.ClosureRequirement {
	if len(in) == 0 {
		return nil
	}
	out := risk.CloneClosureRequirements(in)
	for idx := range out {
		out[idx].ClosureRefs = maybeRedactStringSlice(out[idx].ClosureRefs, "evidence", config.Has(RedactionProofRefs) || config.Has(RedactionGraphRefs) || config.Has(RedactionProviders))
	}
	return out
}

func sanitizeClosureActionsWithConfig(in []risk.ClosureAction, config RedactionConfig) []risk.ClosureAction {
	if len(in) == 0 {
		return nil
	}
	out := risk.CloneClosureActions(in)
	for idx := range out {
		out[idx].ID = maybeRedactPathID(out[idx].ID, config)
		out[idx].Title = maybeRedactCompositeLabel(out[idx].Title, config)
		out[idx].Guidance = maybeRedactCompositeLabel(out[idx].Guidance, config)
		out[idx].ProviderEvidenceClass = maybeRedactCompositeLabel(out[idx].ProviderEvidenceClass, config)
	}
	return out
}

func sanitizeActionLineageWithConfig(in *risk.ActionLineage, config RedactionConfig) *risk.ActionLineage {
	if in == nil {
		return nil
	}
	copyLineage := risk.CloneActionLineage(in)
	for idx := range copyLineage.Segments {
		if config.Has(RedactionGraphRefs) {
			copyLineage.Segments[idx].SegmentID = redactValue("segment", copyLineage.Segments[idx].SegmentID, 8)
			copyLineage.Segments[idx].NodeIDs = redactStringSlice(copyLineage.Segments[idx].NodeIDs, "node")
			copyLineage.Segments[idx].EdgeIDs = redactStringSlice(copyLineage.Segments[idx].EdgeIDs, "edge")
			copyLineage.Segments[idx].EvidenceRefs = redactStringSlice(copyLineage.Segments[idx].EvidenceRefs, "evidence")
		} else {
			copyLineage.Segments[idx].NodeIDs = cloneStrings(copyLineage.Segments[idx].NodeIDs)
			copyLineage.Segments[idx].EdgeIDs = cloneStrings(copyLineage.Segments[idx].EdgeIDs)
			copyLineage.Segments[idx].EvidenceRefs = cloneStrings(copyLineage.Segments[idx].EvidenceRefs)
		}
		copyLineage.Segments[idx].Label = maybeRedactCompositeLabel(copyLineage.Segments[idx].Label, config)
	}
	return copyLineage
}

func sanitizeScanQualityWithConfig(in *scanquality.Report, config RedactionConfig) *scanquality.Report {
	if in == nil {
		return nil
	}
	copyReport := cloneScanQualityReport(in)
	for idx := range copyReport.SuppressedPaths {
		copyReport.SuppressedPaths[idx].Org = maybeRedactOrg(copyReport.SuppressedPaths[idx].Org, config)
		copyReport.SuppressedPaths[idx].Repo = maybeRedactRepo(copyReport.SuppressedPaths[idx].Repo, config)
		copyReport.SuppressedPaths[idx].Path = maybeRedactLocationLike(copyReport.SuppressedPaths[idx].Path, config)
	}
	for idx := range copyReport.ParseErrors {
		copyReport.ParseErrors[idx].Org = maybeRedactOrg(copyReport.ParseErrors[idx].Org, config)
		copyReport.ParseErrors[idx].Repo = maybeRedactRepo(copyReport.ParseErrors[idx].Repo, config)
		copyReport.ParseErrors[idx].Path = maybeRedactLocationLike(copyReport.ParseErrors[idx].Path, config)
	}
	for idx := range copyReport.Detectors {
		copyReport.Detectors[idx].Org = maybeRedactOrg(copyReport.Detectors[idx].Org, config)
		copyReport.Detectors[idx].Repo = maybeRedactRepo(copyReport.Detectors[idx].Repo, config)
	}
	for idx := range copyReport.DetectorErrors {
		copyReport.DetectorErrors[idx].Org = maybeRedactOrg(copyReport.DetectorErrors[idx].Org, config)
		copyReport.DetectorErrors[idx].Repo = maybeRedactRepo(copyReport.DetectorErrors[idx].Repo, config)
	}
	return copyReport
}

func sanitizeControlProofStatusWithConfig(in []ControlProofStatus, rawPaths []risk.ActionPath, sanitizedPaths []risk.ActionPath, config RedactionConfig) []ControlProofStatus {
	if len(in) == 0 {
		return nil
	}
	pathIDMap := map[string]string{}
	for idx := range rawPaths {
		rawPathID := strings.TrimSpace(rawPaths[idx].PathID)
		if rawPathID == "" {
			continue
		}
		sanitizedPathID := maybeRedactPathID(rawPathID, config)
		if idx < len(sanitizedPaths) && strings.TrimSpace(sanitizedPaths[idx].PathID) != "" {
			sanitizedPathID = strings.TrimSpace(sanitizedPaths[idx].PathID)
		}
		pathIDMap[rawPathID] = sanitizedPathID
	}

	out := make([]ControlProofStatus, 0, len(in))
	for _, item := range in {
		copyItem := item
		linkedPathID := strings.TrimSpace(copyItem.LinkedActionPathID)
		if sanitizedPathID, ok := pathIDMap[linkedPathID]; ok {
			copyItem.LinkedActionPathID = sanitizedPathID
		} else {
			copyItem.LinkedActionPathID = maybeRedactPathID(linkedPathID, config)
		}
		copyItem.Repo = maybeRedactRepo(copyItem.Repo, config)
		copyItem.Path = maybeRedactLocationLike(copyItem.Path, config)
		copyItem.ExistingProof = maybeRedactStringSlice(copyItem.ExistingProof, "proof", config.Has(RedactionProofRefs))
		copyItem.MissingProof = maybeRedactStringSlice(copyItem.MissingProof, "proof", config.Has(RedactionProofRefs))
		copyItem.RecordIDs = maybeRedactStringSlice(copyItem.RecordIDs, "proof", config.Has(RedactionProofRefs))
		out = append(out, copyItem)
	}
	return out
}

func sanitizeGraphRefsWithConfig(in AgentActionBOMGraphRefs, config RedactionConfig) AgentActionBOMGraphRefs {
	if !config.Has(RedactionGraphRefs) {
		return AgentActionBOMGraphRefs{
			NodeIDs: cloneStrings(in.NodeIDs),
			EdgeIDs: cloneStrings(in.EdgeIDs),
		}
	}
	return AgentActionBOMGraphRefs{
		NodeIDs: redactStringSlice(in.NodeIDs, "node"),
		EdgeIDs: redactStringSlice(in.EdgeIDs, "edge"),
	}
}

func maybeRedactLocationLike(value string, config RedactionConfig) string {
	value = maybeRedactFilesystemValue(value, config)
	if config.Has(RedactionPaths) {
		return redactValue("loc", value, 8)
	}
	return strings.TrimSpace(value)
}

func maybeRedactProofChainPath(value string, config RedactionConfig) string {
	if config.Has(RedactionProofRefs) {
		return "redacted://proof-chain.json"
	}
	return maybeRedactLocationLike(value, config)
}

func maybeRedactRepo(value string, config RedactionConfig) string {
	if config.Has(RedactionRepos) {
		return redactValue("repo", value, 6)
	}
	return strings.TrimSpace(value)
}

func maybeRedactOrg(value string, config RedactionConfig) string {
	if config.Has(RedactionRepos) {
		return redactValue("org", value, 6)
	}
	return strings.TrimSpace(value)
}

func maybeRedactOwner(value string, config RedactionConfig) string {
	if config.Has(RedactionOwners) {
		return redactValue("owner", value, 8)
	}
	return strings.TrimSpace(value)
}

func maybeRedactCredentialSubject(value string, config RedactionConfig) string {
	if config.Has(RedactionCredentialSubjects) {
		return redactValue("credential", value, 8)
	}
	return strings.TrimSpace(value)
}

func maybeRedactAuthor(value string, config RedactionConfig) string {
	if config.Has(RedactionAuthors) {
		return redactValue("author", value, 8)
	}
	return strings.TrimSpace(value)
}

func maybeRedactProvider(value string, config RedactionConfig) string {
	if config.Has(RedactionProviders) {
		return redactValue("provider", value, 8)
	}
	return strings.TrimSpace(value)
}

func maybeRedactPathID(value string, config RedactionConfig) string {
	if config.Has(RedactionPaths) {
		return redactValue("path", value, 8)
	}
	return strings.TrimSpace(value)
}

func maybeRedactFindingKey(value string, config RedactionConfig) string {
	if shouldRedactFindingKeys(config) {
		return redactValue("finding", value, 12)
	}
	return strings.TrimSpace(value)
}

func maybeRedactCompositeLabel(value string, config RedactionConfig) string {
	if config.Has(RedactionOwners) || config.Has(RedactionRepos) || config.Has(RedactionPaths) || config.Has(RedactionCredentialSubjects) || config.Has(RedactionAuthors) || config.Has(RedactionProviders) {
		return redactValue("label", value, 8)
	}
	return strings.TrimSpace(value)
}

func maybeRedactStringSlice(values []string, prefix string, selected bool) []string {
	if !selected {
		return cloneStrings(values)
	}
	return redactStringSlice(values, prefix)
}

func shouldRedactFindingKeys(config RedactionConfig) bool {
	return config.Has(RedactionRepos) || config.Has(RedactionPaths) || config.Has(RedactionProofRefs)
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}
