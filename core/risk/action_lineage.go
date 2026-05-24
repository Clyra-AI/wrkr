package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
)

type ActionLineage struct {
	Segments []ActionLineageSegment `json:"segments,omitempty"`
}

type ActionLineageSegment struct {
	SegmentID    string   `json:"segment_id"`
	Kind         string   `json:"kind"`
	Label        string   `json:"label,omitempty"`
	Status       string   `json:"status,omitempty"`
	NodeIDs      []string `json:"node_ids,omitempty"`
	EdgeIDs      []string `json:"edge_ids,omitempty"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

func CloneActionLineage(in *ActionLineage) *ActionLineage {
	if in == nil {
		return nil
	}
	out := &ActionLineage{Segments: make([]ActionLineageSegment, 0, len(in.Segments))}
	for _, segment := range in.Segments {
		out.Segments = append(out.Segments, ActionLineageSegment{
			SegmentID:    strings.TrimSpace(segment.SegmentID),
			Kind:         strings.TrimSpace(segment.Kind),
			Label:        strings.TrimSpace(segment.Label),
			Status:       strings.TrimSpace(segment.Status),
			NodeIDs:      append([]string(nil), segment.NodeIDs...),
			EdgeIDs:      append([]string(nil), segment.EdgeIDs...),
			EvidenceRefs: append([]string(nil), segment.EvidenceRefs...),
		})
	}
	return out
}

func DecorateActionLineage(paths []ActionPath, graph *aggattack.ControlPathGraph) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	index := newControlPathLineageIndex(graph)
	out := make([]ActionPath, 0, len(paths))
	for _, path := range paths {
		copyPath := path
		copyPath.ActionLineage = buildActionLineage(path, index)
		out = append(out, copyPath)
	}
	return out
}

type controlPathLineageIndex struct {
	nodesByPath map[string][]aggattack.ControlPathNode
	edgesByPath map[string][]aggattack.ControlPathEdge
}

func newControlPathLineageIndex(graph *aggattack.ControlPathGraph) controlPathLineageIndex {
	index := controlPathLineageIndex{
		nodesByPath: map[string][]aggattack.ControlPathNode{},
		edgesByPath: map[string][]aggattack.ControlPathEdge{},
	}
	if graph == nil {
		return index
	}
	for _, node := range graph.Nodes {
		pathID := strings.TrimSpace(node.PathID)
		if pathID == "" {
			continue
		}
		index.nodesByPath[pathID] = append(index.nodesByPath[pathID], node)
	}
	for _, edge := range graph.Edges {
		pathID := strings.TrimSpace(edge.PathID)
		if pathID == "" {
			continue
		}
		index.edgesByPath[pathID] = append(index.edgesByPath[pathID], edge)
	}
	return index
}

func buildActionLineage(path ActionPath, index controlPathLineageIndex) *ActionLineage {
	pathID := strings.TrimSpace(path.PathID)
	nodes := index.nodesByPath[pathID]
	edges := index.edgesByPath[pathID]
	approvalNodeIDs := matchingNodeIDs(nodes, "governance_control", "approval")
	proofNodeIDs := matchingNodeIDs(nodes, "governance_control", "proof")
	segments := []ActionLineageSegment{
		newLineageSegment(pathID, "repo", path.Repo, statusForPresence(path.Repo), matchingNodeIDs(nodes, "repo", ""), matchingEdgeIDs(edges, "workflow_in_repo"), []string{path.Repo}),
		newLineageSegment(pathID, "workflow", path.Location, statusForPresence(path.Location), matchingNodeIDs(nodes, "workflow", ""), matchingEdgeIDs(edges, "path_executes_workflow"), []string{path.Location}),
		newLineageSegment(pathID, "agent", firstNonEmpty(path.AgentID, path.ToolType), statusForPresence(firstNonEmpty(path.AgentID, path.ToolType)), matchingNodeIDs(nodes, "agent", ""), matchingEdgeIDs(edges, "agent_controls_path"), []string{path.AgentID}),
		newLineageSegment(pathID, "action", actionLineageLabel(path), actionLineageStatus(path), matchingNodeIDs(nodes, "action_capability", ""), matchingEdgeIDs(edges, "path_enables_action"), append([]string(nil), path.ActionReasons...)),
		newLineageSegment(pathID, "credential", credentialLineageLabel(path), credentialLineageStatus(path), matchingNodeIDs(nodes, "credential", ""), matchingEdgeIDs(edges, "execution_uses_credential"), credentialLineageEvidence(path)),
		newLineageSegment(pathID, "target", targetLineageLabel(path), targetLineageStatus(path), matchingNodeIDs(nodes, "target", ""), matchingEdgeIDs(edges, "path_targets_surface"), append([]string(nil), path.MatchedProductionTargets...)),
		newLineageSegment(pathID, "owner", path.OperationalOwner, ownerLineageStatus(path), nil, nil, append([]string(nil), path.OwnershipEvidence...)),
		newLineageSegment(pathID, "approval", approvalLineageLabel(path), approvalLineageStatus(path), approvalNodeIDs, matchingEdgeIDsForNodeIDs(edges, "path_governed_by", approvalNodeIDs), append([]string(nil), path.ApprovalGapReasons...)),
		newLineageSegment(pathID, "proof", proofLineageLabel(path), proofLineageStatus(path), proofNodeIDs, matchingEdgeIDsForNodeIDs(edges, "path_governed_by", proofNodeIDs), append([]string(nil), path.PolicyEvidenceRefs...)),
	}
	return &ActionLineage{Segments: segments}
}

func newLineageSegment(pathID, kind, label, status string, nodeIDs, edgeIDs, evidenceRefs []string) ActionLineageSegment {
	label = strings.TrimSpace(label)
	status = strings.TrimSpace(status)
	raw := strings.Join([]string{strings.TrimSpace(pathID), strings.TrimSpace(kind), label, status}, "|")
	return ActionLineageSegment{
		SegmentID:    "als-" + stableShortHash(raw),
		Kind:         strings.TrimSpace(kind),
		Label:        label,
		Status:       status,
		NodeIDs:      dedupeSortedStrings(nodeIDs),
		EdgeIDs:      dedupeSortedStrings(edgeIDs),
		EvidenceRefs: dedupeSortedStrings(evidenceRefs),
	}
}

func stableShortHash(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:6])
}

func matchingNodeIDs(nodes []aggattack.ControlPathNode, kind string, lineageSegment string) []string {
	out := []string{}
	for _, node := range nodes {
		if strings.TrimSpace(node.Kind) != strings.TrimSpace(kind) {
			continue
		}
		if strings.TrimSpace(lineageSegment) != "" && strings.TrimSpace(node.LineageSegment) != strings.TrimSpace(lineageSegment) {
			continue
		}
		out = append(out, strings.TrimSpace(node.NodeID))
	}
	sort.Strings(out)
	return out
}

func matchingEdgeIDs(edges []aggattack.ControlPathEdge, kind string) []string {
	out := []string{}
	for _, edge := range edges {
		if strings.TrimSpace(edge.Kind) == strings.TrimSpace(kind) {
			out = append(out, strings.TrimSpace(edge.EdgeID))
		}
	}
	sort.Strings(out)
	return out
}

func matchingEdgeIDsForNodeIDs(edges []aggattack.ControlPathEdge, kind string, nodeIDs []string) []string {
	if len(nodeIDs) == 0 {
		return nil
	}
	nodeSet := map[string]struct{}{}
	for _, nodeID := range nodeIDs {
		trimmed := strings.TrimSpace(nodeID)
		if trimmed == "" {
			continue
		}
		nodeSet[trimmed] = struct{}{}
	}
	if len(nodeSet) == 0 {
		return nil
	}
	out := []string{}
	for _, edge := range edges {
		if strings.TrimSpace(edge.Kind) != strings.TrimSpace(kind) {
			continue
		}
		if _, ok := nodeSet[strings.TrimSpace(edge.ToNodeID)]; ok {
			out = append(out, strings.TrimSpace(edge.EdgeID))
		}
	}
	sort.Strings(out)
	return out
}

func statusForPresence(value string) string {
	if strings.TrimSpace(value) == "" {
		return "missing"
	}
	return "present"
}

func actionLineageLabel(path ActionPath) string {
	if len(path.ActionClasses) > 0 {
		values := append([]string(nil), path.ActionClasses...)
		for _, item := range pathMutableEndpointSemantics(path) {
			values = append(values, strings.TrimSpace(item.Semantic))
		}
		return strings.Join(dedupeSortedStrings(values), ",")
	}
	if operations := pathMutableEndpointOperations(path); len(operations) > 0 {
		return strings.Join(operations, ",")
	}
	if len(path.WritePathClasses) > 0 {
		return strings.Join(path.WritePathClasses, ",")
	}
	if path.WriteCapable {
		return "write_capable"
	}
	return "read_only"
}

func actionLineageStatus(path ActionPath) string {
	if len(path.ActionClasses) > 0 || len(path.WritePathClasses) > 0 || path.WriteCapable || path.PullRequestWrite || path.MergeExecute || path.DeployWrite || path.ProductionWrite || pathHasAnyMutableEndpoint(path) {
		return "present"
	}
	return "missing"
}

func credentialLineageLabel(path ActionPath) string {
	if path.CredentialAuthority != nil && strings.TrimSpace(path.CredentialAuthority.CredentialKind) != "" {
		return strings.TrimSpace(path.CredentialAuthority.CredentialKind)
	}
	if path.CredentialProvenance != nil && strings.TrimSpace(path.CredentialProvenance.CredentialKind) != "" {
		return strings.TrimSpace(path.CredentialProvenance.CredentialKind)
	}
	if path.CredentialAccess {
		return "credential_access"
	}
	return ""
}

func credentialLineageStatus(path ActionPath) string {
	if path.CredentialAuthority != nil {
		if path.CredentialAuthority.CredentialPresent {
			if path.CredentialAuthority.CredentialUsableByPath {
				return "present"
			}
			return "referenced_only"
		}
	}
	if path.CredentialAccess || path.CredentialProvenance != nil {
		return "present"
	}
	return "missing"
}

func credentialLineageEvidence(path ActionPath) []string {
	refs := []string{}
	if path.CredentialAuthority != nil {
		refs = append(refs, path.CredentialAuthority.ReasonCodes...)
	}
	if path.CredentialProvenance != nil {
		refs = append(refs, path.CredentialProvenance.EvidenceBasis...)
	}
	return refs
}

func targetLineageLabel(path ActionPath) string {
	if len(path.MatchedProductionTargets) > 0 {
		return strings.Join(path.MatchedProductionTargets, ",")
	}
	if operations := pathMutableEndpointOperations(path); len(operations) > 0 {
		return strings.Join(operations, ",")
	}
	if path.ProductionWrite {
		return "unknown_production_target"
	}
	return ""
}

func targetLineageStatus(path ActionPath) string {
	if len(path.MatchedProductionTargets) > 0 || path.ProductionWrite || pathHasAnyMutableEndpoint(path) {
		return "present"
	}
	return "missing"
}

func ownerLineageStatus(path ActionPath) string {
	if actionPathHasWeakOwnership(path) || strings.TrimSpace(path.OperationalOwner) == "" {
		return "missing"
	}
	return "present"
}

func approvalLineageLabel(path ActionPath) string {
	if path.ApprovalGap {
		return BuyerEvidenceStateLabel("approval", path.ApprovalEvidenceState)
	}
	if strings.TrimSpace(path.PolicyCoverageStatus) == PolicyCoverageStatusRuntimeProven {
		return "runtime-backed approval evidence"
	}
	return "approval evidence present"
}

func approvalLineageStatus(path ActionPath) string {
	if path.ApprovalGap {
		return "missing"
	}
	return "present"
}

func proofLineageLabel(path ActionPath) string {
	if strings.TrimSpace(path.PolicyCoverageStatus) != "" {
		return BuyerEvidenceStateLabel("proof", path.ProofEvidenceState)
	}
	if path.GaitCoverage != nil {
		return BuyerEvidenceStateLabel("proof", path.ProofEvidenceState)
	}
	return BuyerEvidenceStateLabel("proof", path.ProofEvidenceState)
}

func proofLineageStatus(path ActionPath) string {
	switch strings.TrimSpace(path.PolicyCoverageStatus) {
	case PolicyCoverageStatusMatched, PolicyCoverageStatusDeclared, PolicyCoverageStatusRuntimeProven:
		return "present"
	case PolicyCoverageStatusStale, PolicyCoverageStatusConflict, PolicyCoverageStatusNone, "":
		if path.GaitCoverage != nil && strings.TrimSpace(path.GaitCoverage.ProofVerification.Status) == "present" {
			return "present"
		}
		return "missing"
	default:
		return "missing"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
