package report

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
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
		copyItem.ConfigSource = maybeRedactLocationLike(copyItem.ConfigSource, config)
		copyItem.AttackPathRefs = maybeRedactStringSlice(copyItem.AttackPathRefs, "attack", config.Has(RedactionGraphRefs))
		copyItem.SourceFindingKeys = maybeRedactStringSlice(copyItem.SourceFindingKeys, "finding", shouldRedactFindingKeys(config))
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
		copyItem.MutableEndpointSemantics = sanitizeMutableEndpointSemanticsWithConfig(copyItem.MutableEndpointSemantics, config)
		copyItem.Credentials = redactCredentialsWithConfig(copyItem.Credentials, config)
		copyItem.ClosureRequirements = sanitizeClosureRequirementsWithConfig(copyItem.ClosureRequirements, config)
		copyItem.EvidenceCompleteness = risk.CloneEvidenceCompleteness(copyItem.EvidenceCompleteness)
		copyItem.ActionLineage = sanitizeActionLineageWithConfig(copyItem.ActionLineage, config)
		copyItem.IntroducedBy = sanitizeIntroducedByWithConfig(copyItem.IntroducedBy, config)
		copyItem.EvidencePacketRefs = maybeRedactStringSlice(copyItem.EvidencePacketRefs, "packet", config.Has(RedactionPaths) || config.Has(RedactionProofRefs))
		copyItem.MatchedProductionTargets = cloneStrings(copyItem.MatchedProductionTargets)
		out = append(out, copyItem)
	}
	return out
}

func sanitizeActionPathToControlFirstWithConfig(in *risk.ActionPathToControlFirst, config RedactionConfig) *risk.ActionPathToControlFirst {
	if in == nil {
		return nil
	}
	copySummary := in.Summary
	paths := sanitizeActionPathsWithConfig([]risk.ActionPath{in.Path}, config)
	if len(paths) == 0 {
		return &risk.ActionPathToControlFirst{Summary: copySummary}
	}
	return &risk.ActionPathToControlFirst{
		Summary: copySummary,
		Path:    paths[0],
	}
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
		copyItem.PathIDs = maybeRedactStringSlice(copyItem.PathIDs, "path", config.Has(RedactionPaths))
		copyItem.GraphRefs = sanitizeGraphRefsWithConfig(copyItem.GraphRefs, config)
		if copyItem.CredentialAuthority != nil {
			copyItem.CredentialAuthority = agginventory.CloneCredentialAuthority(copyItem.CredentialAuthority)
			copyItem.CredentialAuthority.ReasonCodes = cloneStrings(copyItem.CredentialAuthority.ReasonCodes)
		}
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

func sanitizeAssessmentSummaryWithConfig(in *AssessmentSummary, config RedactionConfig) *AssessmentSummary {
	if in == nil {
		return nil
	}
	copySummary := *in
	if in.TopPathToControlFirst != nil {
		paths := sanitizeActionPathsWithConfig([]risk.ActionPath{*in.TopPathToControlFirst}, config)
		if len(paths) == 1 {
			copySummary.TopPathToControlFirst = &paths[0]
		}
	}
	if in.TopExecutionIdentityBacked != nil {
		paths := sanitizeActionPathsWithConfig([]risk.ActionPath{*in.TopExecutionIdentityBacked}, config)
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
		copyGraph.Nodes[idx].MutableEndpointSemantics = sanitizeMutableEndpointSemanticsWithConfig(copyGraph.Nodes[idx].MutableEndpointSemantics, config)
		copyGraph.Nodes[idx].SourceRefs = cloneStrings(copyGraph.Nodes[idx].SourceRefs)
		copyGraph.Nodes[idx].SourceFindingKeys = maybeRedactStringSlice(copyGraph.Nodes[idx].SourceFindingKeys, "finding", shouldRedactFindingKeys(config))
		if copyGraph.Nodes[idx].CredentialAuthority != nil {
			copyGraph.Nodes[idx].CredentialAuthority = agginventory.CloneCredentialAuthority(copyGraph.Nodes[idx].CredentialAuthority)
			copyGraph.Nodes[idx].CredentialAuthority.ReasonCodes = cloneStrings(copyGraph.Nodes[idx].CredentialAuthority.ReasonCodes)
		}
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
		copyBacklog.Items[idx].LinkedFindingIDs = maybeRedactStringSlice(copyBacklog.Items[idx].LinkedFindingIDs, "finding", shouldRedactFindingKeys(config))
		copyBacklog.Items[idx].LinkedActionPathID = maybeRedactPathID(copyBacklog.Items[idx].LinkedActionPathID, config)
		copyBacklog.Items[idx].LinkedControlPathNodeIDs = maybeRedactStringSlice(copyBacklog.Items[idx].LinkedControlPathNodeIDs, "node", config.Has(RedactionGraphRefs))
		copyBacklog.Items[idx].LinkedControlPathEdgeIDs = maybeRedactStringSlice(copyBacklog.Items[idx].LinkedControlPathEdgeIDs, "edge", config.Has(RedactionGraphRefs))
		copyBacklog.Items[idx].OwnershipEvidence = cloneStrings(copyBacklog.Items[idx].OwnershipEvidence)
		copyBacklog.Items[idx].OwnershipConflicts = maybeRedactStringSlice(copyBacklog.Items[idx].OwnershipConflicts, "owner", config.Has(RedactionOwners))
		copyBacklog.Items[idx].ClosureRequirements = sanitizeClosureRequirementsWithConfig(copyBacklog.Items[idx].ClosureRequirements, config)
		copyBacklog.Items[idx].EvidenceCompleteness = risk.CloneEvidenceCompleteness(copyBacklog.Items[idx].EvidenceCompleteness)
		copyBacklog.Items[idx].GovernanceDisposition = sanitizeGovernanceDispositionWithConfig(copyBacklog.Items[idx].GovernanceDisposition, config)
		copyBacklog.Items[idx].LifecycleQueue = sanitizeLifecycleQueueWithConfig(copyBacklog.Items[idx].LifecycleQueue, config)
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
	copyBOM.EvidenceRefs = maybeRedactStringSlice(in.EvidenceRefs, "evidence", config.Has(RedactionProofRefs))
	copyBOM.ProofRefs = maybeRedactStringSlice(in.ProofRefs, "proof", config.Has(RedactionProofRefs))
	copyBOM.GraphRefs = sanitizeGraphRefsWithConfig(in.GraphRefs, config)
	copyBOM.Summary.PrimaryView = sanitizePrimaryViewWithConfig(in.Summary.PrimaryView, config)
	copyBOM.Items = append([]AgentActionBOMItem(nil), in.Items...)
	for idx := range copyBOM.Items {
		copyBOM.Items[idx].PathID = maybeRedactPathID(copyBOM.Items[idx].PathID, config)
		copyBOM.Items[idx].Org = maybeRedactOrg(copyBOM.Items[idx].Org, config)
		copyBOM.Items[idx].Repo = maybeRedactRepo(copyBOM.Items[idx].Repo, config)
		copyBOM.Items[idx].Location = maybeRedactLocationLike(copyBOM.Items[idx].Location, config)
		copyBOM.Items[idx].Owner = maybeRedactOwner(copyBOM.Items[idx].Owner, config)
		copyBOM.Items[idx].ConfigSource = maybeRedactLocationLike(copyBOM.Items[idx].ConfigSource, config)
		copyBOM.Items[idx].ProofRefs = maybeRedactStringSlice(copyBOM.Items[idx].ProofRefs, "proof", config.Has(RedactionProofRefs))
		copyBOM.Items[idx].RuntimeSessionRefs = maybeRedactStringSlice(copyBOM.Items[idx].RuntimeSessionRefs, "session", config.Has(RedactionPaths) || config.Has(RedactionProofRefs))
		for itemIdx := range copyBOM.Items[idx].ObservedChangedFiles {
			copyBOM.Items[idx].ObservedChangedFiles[itemIdx] = maybeRedactLocationLike(copyBOM.Items[idx].ObservedChangedFiles[itemIdx], config)
		}
		copyBOM.Items[idx].RuntimeEvidenceRefs = cloneStrings(copyBOM.Items[idx].RuntimeEvidenceRefs)
		copyBOM.Items[idx].PolicyRefs = cloneStrings(copyBOM.Items[idx].PolicyRefs)
		copyBOM.Items[idx].PolicyEvidenceRefs = cloneStrings(copyBOM.Items[idx].PolicyEvidenceRefs)
		copyBOM.Items[idx].ClosureRequirements = sanitizeClosureRequirementsWithConfig(copyBOM.Items[idx].ClosureRequirements, config)
		copyBOM.Items[idx].EvidenceCompleteness = risk.CloneEvidenceCompleteness(copyBOM.Items[idx].EvidenceCompleteness)
		copyBOM.Items[idx].GovernanceDisposition = sanitizeGovernanceDispositionWithConfig(copyBOM.Items[idx].GovernanceDisposition, config)
		copyBOM.Items[idx].LifecycleQueue = sanitizeLifecycleQueueWithConfig(copyBOM.Items[idx].LifecycleQueue, config)
		copyBOM.Items[idx].AttackPathRefs = maybeRedactStringSlice(copyBOM.Items[idx].AttackPathRefs, "attack", config.Has(RedactionGraphRefs))
		copyBOM.Items[idx].SourceFindingKeys = maybeRedactStringSlice(copyBOM.Items[idx].SourceFindingKeys, "finding", shouldRedactFindingKeys(config))
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
		copyBOM.Items[idx].MutableEndpointSemantics = sanitizeMutableEndpointSemanticsWithConfig(copyBOM.Items[idx].MutableEndpointSemantics, config)
		copyBOM.Items[idx].Credentials = redactCredentialsWithConfig(copyBOM.Items[idx].Credentials, config)
		copyBOM.Items[idx].ActionLineage = sanitizeActionLineageWithConfig(copyBOM.Items[idx].ActionLineage, config)
		copyBOM.Items[idx].IntroducedBy = sanitizeIntroducedByWithConfig(copyBOM.Items[idx].IntroducedBy, config)
		copyBOM.Items[idx].EvidencePacketRefs = maybeRedactStringSlice(copyBOM.Items[idx].EvidencePacketRefs, "packet", config.Has(RedactionPaths) || config.Has(RedactionProofRefs))
	}
	return &copyBOM
}

func sanitizePrimaryViewWithConfig(in *AgentActionBOMPrimaryView, config RedactionConfig) *AgentActionBOMPrimaryView {
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
	out.WorkflowChainRefs = maybeRedactStringSlice(in.WorkflowChainRefs, "chain", config.Has(RedactionPaths) || config.Has(RedactionGraphRefs))
	out.GraphRefs = sanitizeGraphRefsWithConfig(in.GraphRefs, config)
	out.ProofRefs = maybeRedactStringSlice(in.ProofRefs, "proof", config.Has(RedactionProofRefs))
	out.EvidencePacketRefs = maybeRedactStringSlice(in.EvidencePacketRefs, "packet", config.Has(RedactionPaths) || config.Has(RedactionProofRefs))
	out.AppendixRefs = cloneStrings(in.AppendixRefs)
	out.UnresolvedEvidence = cloneStrings(in.UnresolvedEvidence)
	return &out
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
