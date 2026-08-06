package risk

import (
	"context"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/attribution"
)

func BuildWorkflowChains(paths []ActionPath, graph *aggattack.ControlPathGraph) *agentresolver.WorkflowChainArtifact {
	artifact, _ := BuildWorkflowChainsContext(context.Background(), paths, graph)
	return artifact
}

// BuildWorkflowChainsContext builds bounded workflow-chain evidence while honoring scan cancellation.
func BuildWorkflowChainsContext(ctx context.Context, paths []ActionPath, graph *aggattack.ControlPathGraph) (*agentresolver.WorkflowChainArtifact, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	graphRefsByPath, err := workflowChainGraphRefsByPathContext(ctx, graph)
	if err != nil {
		return nil, err
	}
	inputs := make([]agentresolver.WorkflowChainInput, 0, len(paths))
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
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
			ProofRefs:                 boundedOutputEvidenceRefs(path.PolicyEvidenceRefs),
			EvidenceRefs:              workflowChainEvidenceRefs(path),
			SourceFindingKeys:         boundedOutputEvidenceRefs(path.SourceFindingKeys),
		})
	}
	return agentresolver.BuildWorkflowChainsContext(ctx, inputs)
}

func DecorateWorkflowChainRefs(paths []ActionPath, artifact *agentresolver.WorkflowChainArtifact) []ActionPath {
	decorated, _ := DecorateWorkflowChainRefsContext(context.Background(), paths, artifact)
	return decorated
}

func DecorateWorkflowChainRefsContext(ctx context.Context, paths []ActionPath, artifact *agentresolver.WorkflowChainArtifact) ([]ActionPath, error) {
	if len(paths) == 0 {
		return nil, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	refsByPath := agentresolver.WorkflowChainRefsByPath(artifact)
	out := make([]ActionPath, 0, len(paths))
	for _, path := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		copyPath := path
		copyPath.WorkflowChainRefs = dedupeSortedStrings(refsByPath[strings.TrimSpace(path.PathID)])
		out = append(out, copyPath)
	}
	return out, nil
}

type workflowChainGraphRefs struct {
	NodeIDs []string
	EdgeIDs []string
}

func workflowChainGraphRefsByPath(graph *aggattack.ControlPathGraph) map[string]workflowChainGraphRefs {
	refs, _ := workflowChainGraphRefsByPathContext(context.Background(), graph)
	return refs
}

func workflowChainGraphRefsByPathContext(ctx context.Context, graph *aggattack.ControlPathGraph) (map[string]workflowChainGraphRefs, error) {
	byPath := map[string]workflowChainGraphRefs{}
	if graph == nil {
		return byPath, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for _, node := range graph.Nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pathID := strings.TrimSpace(node.PathID)
		if pathID == "" {
			continue
		}
		current := byPath[pathID]
		current.NodeIDs = append(current.NodeIDs, strings.TrimSpace(node.NodeID))
		byPath[pathID] = current
	}
	for _, edge := range graph.Edges {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pathID := strings.TrimSpace(edge.PathID)
		if pathID == "" {
			continue
		}
		current := byPath[pathID]
		current.EdgeIDs = append(current.EdgeIDs, strings.TrimSpace(edge.EdgeID))
		byPath[pathID] = current
	}
	for pathID, refs := range byPath {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		refs.NodeIDs = dedupeSortedStrings(refs.NodeIDs)
		refs.EdgeIDs = dedupeSortedStrings(refs.EdgeIDs)
		byPath[pathID] = refs
	}
	return byPath, nil
}

func workflowChainEvidenceRefs(path ActionPath) []string {
	values := append([]string(nil), path.ControlEvidenceRefs...)
	values = append(values, path.PolicyEvidenceRefs...)
	values = append(values, path.TargetClassEvidenceRefs...)
	if path.IntroducedBy != nil {
		values = append(values, attribution.EvidenceRefs(path.IntroducedBy)...)
	}
	return boundedOutputEvidenceRefs(values)
}
