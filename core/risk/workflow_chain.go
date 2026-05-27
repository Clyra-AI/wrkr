package risk

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func BuildWorkflowChains(paths []ActionPath, graph *aggattack.ControlPathGraph) *agentresolver.WorkflowChainArtifact {
	if len(paths) == 0 {
		return nil
	}

	graphRefsByPath := workflowChainGraphRefsByPath(graph)
	inputs := make([]agentresolver.WorkflowChainInput, 0, len(paths))
	for _, path := range paths {
		refs := graphRefsByPath[strings.TrimSpace(path.PathID)]
		inputs = append(inputs, agentresolver.WorkflowChainInput{
			PathID:                    strings.TrimSpace(path.PathID),
			Org:                       strings.TrimSpace(path.Org),
			Repo:                      strings.TrimSpace(path.Repo),
			AgentID:                   strings.TrimSpace(path.AgentID),
			ToolFamilyID:              strings.TrimSpace(path.ToolFamilyID),
			ToolInstanceID:            strings.TrimSpace(path.ToolInstanceID),
			ToolType:                  strings.TrimSpace(path.ToolType),
			Location:                  strings.TrimSpace(path.Location),
			Purpose:                   strings.TrimSpace(path.Purpose),
			PurposeSource:             strings.TrimSpace(path.PurposeSource),
			OperationalOwner:          strings.TrimSpace(path.OperationalOwner),
			CredentialAccess:          path.CredentialAccess,
			CredentialProvenance:      agginventory.CloneCredentialProvenance(path.CredentialProvenance),
			CredentialAuthority:       agginventory.CloneCredentialAuthority(path.CredentialAuthority),
			ApprovalEvidenceState:     strings.TrimSpace(path.ApprovalEvidenceState),
			ProofEvidenceState:        strings.TrimSpace(path.ProofEvidenceState),
			RuntimeEvidenceState:      strings.TrimSpace(path.RuntimeEvidenceState),
			TargetEvidenceState:       strings.TrimSpace(path.TargetEvidenceState),
			ControlResolutionState:    strings.TrimSpace(path.ControlResolutionState),
			DeploymentStatus:          strings.TrimSpace(path.DeploymentStatus),
			DeliveryChainStatus:       strings.TrimSpace(path.DeliveryChainStatus),
			TargetClass:               strings.TrimSpace(path.TargetClass),
			IntroducedBy:              path.IntroducedBy,
			AutonomyTier:              strings.TrimSpace(path.AutonomyTier),
			DelegationReadinessState:  strings.TrimSpace(path.DelegationReadinessState),
			RecommendedControl:        strings.TrimSpace(path.RecommendedControl),
			MatchedProductionTargets:  dedupeSortedStrings(path.MatchedProductionTargets),
			EvidenceCompletenessLabel: evidenceCompletenessProjectionLabel(path.EvidenceCompleteness),
			GraphNodeRefs:             refs.NodeIDs,
			GraphEdgeRefs:             refs.EdgeIDs,
			ProofRefs:                 dedupeSortedStrings(path.PolicyEvidenceRefs),
			EvidenceRefs:              workflowChainEvidenceRefs(path),
			SourceFindingKeys:         dedupeSortedStrings(path.SourceFindingKeys),
		})
	}
	return agentresolver.BuildWorkflowChains(inputs)
}

func DecorateWorkflowChainRefs(paths []ActionPath, artifact *agentresolver.WorkflowChainArtifact) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	refsByPath := agentresolver.WorkflowChainRefsByPath(artifact)
	out := make([]ActionPath, 0, len(paths))
	for _, path := range paths {
		copyPath := path
		copyPath.WorkflowChainRefs = dedupeSortedStrings(refsByPath[strings.TrimSpace(path.PathID)])
		out = append(out, copyPath)
	}
	return out
}

type workflowChainGraphRefs struct {
	NodeIDs []string
	EdgeIDs []string
}

func workflowChainGraphRefsByPath(graph *aggattack.ControlPathGraph) map[string]workflowChainGraphRefs {
	byPath := map[string]workflowChainGraphRefs{}
	if graph == nil {
		return byPath
	}
	for _, node := range graph.Nodes {
		pathID := strings.TrimSpace(node.PathID)
		if pathID == "" {
			continue
		}
		current := byPath[pathID]
		current.NodeIDs = dedupeSortedStrings(append(current.NodeIDs, strings.TrimSpace(node.NodeID)))
		byPath[pathID] = current
	}
	for _, edge := range graph.Edges {
		pathID := strings.TrimSpace(edge.PathID)
		if pathID == "" {
			continue
		}
		current := byPath[pathID]
		current.EdgeIDs = dedupeSortedStrings(append(current.EdgeIDs, strings.TrimSpace(edge.EdgeID)))
		byPath[pathID] = current
	}
	return byPath
}

func workflowChainEvidenceRefs(path ActionPath) []string {
	values := append([]string(nil), path.ControlEvidenceRefs...)
	values = append(values, path.PolicyEvidenceRefs...)
	values = append(values, path.TargetClassEvidenceRefs...)
	if path.IntroducedBy != nil {
		values = append(values, path.IntroducedBy.ChangedFile)
		values = append(values, path.IntroducedBy.ProviderURL)
	}
	return dedupeSortedStrings(values)
}
