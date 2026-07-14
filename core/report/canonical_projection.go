package report

import (
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const (
	maxBOMOutputEvidenceRefs       = 64
	maxBOMOutputEndpointOperations = 32
	maxBOMOutputReachabilityItems  = 32
)

func FinalizeSummaryForShareProfile(summary Summary) Summary {
	return FinalizeSummaryForOutput(summary)
}

func FinalizeSummaryForSerialization(summary Summary) Summary {
	summary = FinalizeSummaryForShareProfile(summary)
	attachSummaryOutputMetadata(&summary)
	return summary
}

func FinalizeSummaryForOutput(summary Summary) Summary {
	summary.ActionPaths = risk.StripCanonicalProjectionDetails(summary.ActionPaths)
	summary.ActionPathToControlFirst = risk.StripActionPathToControlFirstCanonicalProjectionDetails(summary.ActionPathToControlFirst)
	summary.ControlPathGraph = aggattack.StripCanonicalProjectionDetails(summary.ControlPathGraph)
	summary.ControlBacklog = controlbacklog.StripCanonicalProjectionDetails(summary.ControlBacklog)
	summary.AgentActionBOM = stripAgentActionBOMCanonicalProjectionDetails(backfillAgentActionBOMCanonicalProjectionRefs(summary.AgentActionBOM))
	summary.ActionSurfaceRegistry = stripActionSurfaceRegistryCanonicalProjectionDetails(summary.ActionSurfaceRegistry)
	if summary.AssessmentSummary != nil {
		copySummary := *summary.AssessmentSummary
		copySummary.TopPathToControlFirst = stripAssessmentActionPath(summary.AssessmentSummary.TopPathToControlFirst)
		copySummary.TopExecutionIdentityBacked = stripAssessmentActionPath(summary.AssessmentSummary.TopExecutionIdentityBacked)
		summary.AssessmentSummary = &copySummary
	}
	return summary
}

func stripActionSurfaceRegistryCanonicalProjectionDetails(in []ActionSurfaceRegistryEntry) []ActionSurfaceRegistryEntry {
	if len(in) == 0 {
		return nil
	}
	out := make([]ActionSurfaceRegistryEntry, 0, len(in))
	for _, item := range in {
		copyItem := item
		copyItem.EndpointRefGroupProjection = agginventory.BackfillMutableEndpointGroupProjection(copyItem.EndpointRefGroupProjection, copyItem.MutableEndpointSemanticRefs, copyItem.MutableEndpointSemantics)
		if len(copyItem.MutableEndpointSemanticRefs) > 0 {
			copyItem.MutableEndpointSemanticRefs = agginventory.BoundedMutableEndpointSemanticRefs(copyItem.MutableEndpointSemanticRefs, copyItem.MutableEndpointSemantics)
			copyItem.MutableEndpointSemantics = nil
		}
		if copyItem.CredentialAuthorityRef != "" {
			copyItem.CredentialAuthority = nil
		}
		out = append(out, copyItem)
	}
	return out
}

func backfillAgentActionBOMCanonicalProjectionRefs(in *AgentActionBOM) *AgentActionBOM {
	if in == nil {
		return nil
	}
	copyBOM := *in
	copyBOM.Items = append([]AgentActionBOMItem(nil), in.Items...)
	for idx := range copyBOM.Items {
		item := &copyBOM.Items[idx]
		item.EndpointRefGroupProjection = agginventory.BackfillMutableEndpointGroupProjection(item.EndpointRefGroupProjection, item.MutableEndpointSemanticRefs, item.MutableEndpointSemantics)
		if len(item.MutableEndpointSemanticRefs) == 0 && len(item.MutableEndpointSemantics) > 0 {
			item.MutableEndpointSemanticRefs = agginventory.CanonicalMutableEndpointRefs(item.MutableEndpointSemantics)
		}
		if item.CredentialAuthorityRef == "" && item.CredentialAuthority != nil {
			item.CredentialAuthorityRef = agginventory.CanonicalCredentialAuthorityRef(item.CredentialAuthority)
		}
		if len(item.AuthorityBindingRefs) == 0 && len(item.AuthorityBindings) > 0 {
			item.AuthorityBindingRefs = agginventory.CanonicalAuthorityBindingRefs(item.AuthorityBindings)
		}
	}
	return &copyBOM
}

func stripAgentActionBOMCanonicalProjectionDetails(in *AgentActionBOM) *AgentActionBOM {
	if in == nil {
		return nil
	}
	copyBOM := *in
	copyBOM.Items = append([]AgentActionBOMItem(nil), in.Items...)
	for idx := range copyBOM.Items {
		item := &copyBOM.Items[idx]
		item.EndpointRefGroupProjection = agginventory.BackfillMutableEndpointGroupProjection(item.EndpointRefGroupProjection, item.MutableEndpointSemanticRefs, item.MutableEndpointSemantics)
		if len(item.MutableEndpointSemanticRefs) > 0 {
			item.MutableEndpointSemanticRefs = agginventory.BoundedMutableEndpointSemanticRefs(item.MutableEndpointSemanticRefs, item.MutableEndpointSemantics)
			item.MutableEndpointSemantics = nil
		}
		if item.CredentialAuthorityRef != "" {
			item.CredentialAuthority = nil
		}
		if len(item.AuthorityBindingRefs) > 0 {
			item.AuthorityBindings = nil
		}
		stripAgentActionBOMItemOutputEvidenceDetails(item)
	}
	copyBOM.EvidenceRefs = boundedBOMEvidenceRefs(copyBOM.EvidenceRefs)
	return &copyBOM
}

func stripAgentActionBOMItemOutputEvidenceDetails(item *AgentActionBOMItem) {
	if item == nil {
		return
	}
	item.ControlEvidenceRefs = boundedBOMEvidenceRefs(item.ControlEvidenceRefs)
	item.ConstraintEvidenceRefs = boundedBOMEvidenceRefs(item.ConstraintEvidenceRefs)
	item.TargetClassEvidenceRefs = boundedBOMEvidenceRefs(item.TargetClassEvidenceRefs)
	item.ActionPathTypeEvidenceRefs = boundedBOMEvidenceRefs(item.ActionPathTypeEvidenceRefs)
	item.AutonomyTierEvidenceRefs = boundedBOMEvidenceRefs(item.AutonomyTierEvidenceRefs)
	item.RiskClassificationValidationRefs = boundedBOMEvidenceRefs(item.RiskClassificationValidationRefs)
	item.StateLocationRefs = boundedBOMEvidenceRefs(item.StateLocationRefs)
	item.StateDigestRefs = boundedBOMEvidenceRefs(item.StateDigestRefs)
	item.EvidencePacketRefs = boundedBOMEvidenceRefs(item.EvidencePacketRefs)
	item.PolicyEvidenceRefs = boundedBOMEvidenceRefs(item.PolicyEvidenceRefs)
	item.PolicyRefs = boundedBOMEvidenceRefs(item.PolicyRefs)
	item.ProofRefs = boundedBOMEvidenceRefs(item.ProofRefs)
	item.RuntimeSessionRefs = boundedBOMEvidenceRefs(item.RuntimeSessionRefs)
	item.RuntimeEvidenceRefs = boundedBOMEvidenceRefs(item.RuntimeEvidenceRefs)
	item.AttackPathRefs = boundedBOMEvidenceRefs(item.AttackPathRefs)
	item.SourceFindingKeys = boundedBOMEvidenceRefs(item.SourceFindingKeys)
	item.WorkflowChainRefs = boundedBOMEvidenceRefs(item.WorkflowChainRefs)
	item.DecisionTraceRefs = boundedBOMEvidenceRefs(item.DecisionTraceRefs)
	item.CompositionIDs = boundedBOMEvidenceRefs(item.CompositionIDs)
	item.ProposedActionContractRefs = boundedBOMEvidenceRefs(item.ProposedActionContractRefs)
	item.OccurrenceRefs = boundedBOMEvidenceRefs(item.OccurrenceRefs)
	item.MatchedProductionTargets = boundedBOMEvidenceRefs(item.MatchedProductionTargets)
	item.EvidenceRefs = boundedBOMEvidenceRefs(item.EvidenceRefs)

	item.EvidenceDecisions = append([]evidencepolicy.Decision(nil), item.EvidenceDecisions...)
	for idx := range item.EvidenceDecisions {
		item.EvidenceDecisions[idx] = cloneBOMEvidenceDecision(item.EvidenceDecisions[idx])
		item.EvidenceDecisions[idx].SelectedEvidenceRefs = boundedBOMEvidenceRefs(item.EvidenceDecisions[idx].SelectedEvidenceRefs)
		for candidateIdx := range item.EvidenceDecisions[idx].RejectedCandidates {
			item.EvidenceDecisions[idx].RejectedCandidates[candidateIdx].EvidenceRefs = boundedBOMEvidenceRefs(item.EvidenceDecisions[idx].RejectedCandidates[candidateIdx].EvidenceRefs)
		}
	}
	item.Contradictions = append([]evidencepolicy.Contradiction(nil), item.Contradictions...)
	for idx := range item.Contradictions {
		item.Contradictions[idx].EvidenceRefs = boundedBOMEvidenceRefs(item.Contradictions[idx].EvidenceRefs)
	}
	item.HighStakesPresets = risk.CloneHighStakesPresets(item.HighStakesPresets)
	for idx := range item.HighStakesPresets {
		item.HighStakesPresets[idx].EvidenceRefs = boundedBOMEvidenceRefs(item.HighStakesPresets[idx].EvidenceRefs)
	}
	item.ClosureRequirements = risk.CloneClosureRequirements(item.ClosureRequirements)
	for idx := range item.ClosureRequirements {
		item.ClosureRequirements[idx].ClosureRefs = boundedBOMEvidenceRefs(item.ClosureRequirements[idx].ClosureRefs)
	}
	if item.ProductionContext != nil {
		item.ProductionContext = risk.CloneProductionContext(item.ProductionContext)
		item.ProductionContext.EvidenceRefs = boundedBOMEvidenceRefs(item.ProductionContext.EvidenceRefs)
		item.ProductionContext.MutableEndpointOperations = boundedBOMStrings(item.ProductionContext.MutableEndpointOperations, maxBOMOutputEndpointOperations)
	}
	if item.AgenticDeliverySystemChange != nil {
		item.AgenticDeliverySystemChange = risk.CloneAgenticDeliverySystemChange(item.AgenticDeliverySystemChange)
		item.AgenticDeliverySystemChange.EvidenceRefs = boundedBOMEvidenceRefs(item.AgenticDeliverySystemChange.EvidenceRefs)
		item.AgenticDeliverySystemChange.ReachableTargets = boundedBOMStrings(item.AgenticDeliverySystemChange.ReachableTargets, maxBOMOutputEndpointOperations)
	}
	if item.DecisionPrecedent != nil {
		item.DecisionPrecedent = risk.CloneDecisionPrecedent(item.DecisionPrecedent)
		item.DecisionPrecedent.EvidenceRefs = boundedBOMEvidenceRefs(item.DecisionPrecedent.EvidenceRefs)
	}
	if item.GovernanceDisposition != nil {
		item.GovernanceDisposition = cloneGovernanceDisposition(item.GovernanceDisposition)
		item.GovernanceDisposition.EvidenceRefs = boundedBOMEvidenceRefs(item.GovernanceDisposition.EvidenceRefs)
	}
	if item.LifecycleQueue != nil {
		item.LifecycleQueue = cloneLifecycleQueue(item.LifecycleQueue)
		item.LifecycleQueue.EvidenceRefs = boundedBOMEvidenceRefs(item.LifecycleQueue.EvidenceRefs)
	}
	if item.ActionLineage != nil {
		item.ActionLineage = risk.CloneActionLineage(item.ActionLineage)
		for idx := range item.ActionLineage.Segments {
			item.ActionLineage.Segments[idx].EvidenceRefs = boundedBOMEvidenceRefs(item.ActionLineage.Segments[idx].EvidenceRefs)
		}
	}
	item.Reachability = boundedBOMReachability(item.Reachability)
	for idx := range item.Reachability {
		item.Reachability[idx].EvidenceRefs = boundedBOMEvidenceRefs(item.Reachability[idx].EvidenceRefs)
	}
	item.ReachableServers = boundedBOMReachability(item.ReachableServers)
	for idx := range item.ReachableServers {
		item.ReachableServers[idx].EvidenceRefs = boundedBOMEvidenceRefs(item.ReachableServers[idx].EvidenceRefs)
	}
	item.ReachableTools = boundedBOMReachability(item.ReachableTools)
	for idx := range item.ReachableTools {
		item.ReachableTools[idx].EvidenceRefs = boundedBOMEvidenceRefs(item.ReachableTools[idx].EvidenceRefs)
	}
	item.ReachableEndpoints = boundedBOMReachability(item.ReachableEndpoints)
	for idx := range item.ReachableEndpoints {
		item.ReachableEndpoints[idx].EvidenceRefs = boundedBOMEvidenceRefs(item.ReachableEndpoints[idx].EvidenceRefs)
	}
	item.ReachableTargets = boundedBOMReachability(item.ReachableTargets)
	for idx := range item.ReachableTargets {
		item.ReachableTargets[idx].EvidenceRefs = boundedBOMEvidenceRefs(item.ReachableTargets[idx].EvidenceRefs)
	}
	item.ReachableAPIs = boundedBOMReachability(item.ReachableAPIs)
	for idx := range item.ReachableAPIs {
		item.ReachableAPIs[idx].EvidenceRefs = boundedBOMEvidenceRefs(item.ReachableAPIs[idx].EvidenceRefs)
	}
	item.ReachableAgents = boundedBOMReachability(item.ReachableAgents)
	for idx := range item.ReachableAgents {
		item.ReachableAgents[idx].EvidenceRefs = boundedBOMEvidenceRefs(item.ReachableAgents[idx].EvidenceRefs)
	}
}

func cloneBOMEvidenceDecision(in evidencepolicy.Decision) evidencepolicy.Decision {
	out := in
	out.SelectedEvidenceRefs = append([]string(nil), in.SelectedEvidenceRefs...)
	out.ReasonCodes = append([]string(nil), in.ReasonCodes...)
	out.ConflictReasonCodes = append([]string(nil), in.ConflictReasonCodes...)
	if len(in.RejectedCandidates) > 0 {
		out.RejectedCandidates = make([]evidencepolicy.Candidate, 0, len(in.RejectedCandidates))
		for _, item := range in.RejectedCandidates {
			copyItem := item
			copyItem.EvidenceRefs = append([]string(nil), item.EvidenceRefs...)
			copyItem.ReasonCodes = append([]string(nil), item.ReasonCodes...)
			out.RejectedCandidates = append(out.RejectedCandidates, copyItem)
		}
	}
	return out
}

func boundedBOMEvidenceRefs(values []string) []string {
	return boundedBOMStrings(values, maxBOMOutputEvidenceRefs)
}

func boundedBOMReachability(values []AgentActionBOMReachability) []AgentActionBOMReachability {
	if len(values) == 0 {
		return nil
	}
	limit := maxBOMOutputReachabilityItems
	if len(values) < limit {
		limit = len(values)
	}
	out := make([]AgentActionBOMReachability, 0, limit)
	for _, item := range values[:limit] {
		copyItem := item
		copyItem.Capabilities = uniqueSortedStrings(copyItem.Capabilities)
		copyItem.EvidenceRefs = boundedBOMEvidenceRefs(copyItem.EvidenceRefs)
		out = append(out, copyItem)
	}
	return out
}

func boundedBOMStrings(values []string, limit int) []string {
	values = uniqueSortedStrings(values)
	if limit <= 0 || len(values) <= limit {
		return values
	}
	return append([]string(nil), values[:limit]...)
}

func firstAssessmentPath(in *risk.ActionPath) risk.ActionPath {
	if in == nil {
		return risk.ActionPath{}
	}
	return *in
}

func stripAssessmentActionPath(in *risk.ActionPath) *risk.ActionPath {
	if in == nil {
		return nil
	}
	choice := risk.StripActionPathToControlFirstCanonicalProjectionDetails(&risk.ActionPathToControlFirst{
		Summary: risk.ActionPathSummary{},
		Path:    firstAssessmentPath(in),
	})
	if choice == nil {
		return nil
	}
	path := choice.Path
	if path.PathID == "" && path.Org == "" && path.Repo == "" && path.ToolType == "" && path.Location == "" {
		return nil
	}
	return &path
}

func attachSummaryOutputMetadata(summary *Summary) {
	if summary == nil {
		return
	}
	summary.ArtifactBudget = &ArtifactBudget{
		MaxActionPaths:         defaultMaxActionPaths,
		MaxComposedActionPaths: defaultMaxComposedActionPaths,
		MaxBacklogItems:        defaultMaxBacklogItems,
		MaxGraphNodes:          defaultMaxGraphNodes,
		MaxGraphEdges:          defaultMaxGraphEdges,
		MaxWorkflowChains:      defaultMaxWorkflowChains,
		MaxExposureGroups:      defaultMaxExposureGroups,
		MaxAgentActionBOM:      defaultMaxAgentActionBOM,
		MarkdownLineCap:        defaultMarkdownLineCap,
		MarkdownLeadLineCap:    defaultBOMLeadLineCap,
		MarkdownLeadSectionCap: defaultBOMLeadSectionCap,
	}
	summary.AppendixAvailable = len(summary.Sections) > 0 || len(summary.ActionPaths) > 0 || summary.AgentActionBOM != nil
	summary.FocusedBundleAvailable = summary.AgentActionBOM != nil && len(summary.AgentActionBOM.Items) > 0
	summary.FullExportAvailable = false
}
