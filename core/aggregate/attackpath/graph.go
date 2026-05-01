package attackpath

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/model"
)

type Node struct {
	NodeID       string `json:"node_id"`
	Org          string `json:"org"`
	Repo         string `json:"repo"`
	Kind         string `json:"kind"`
	FindingType  string `json:"finding_type"`
	ToolType     string `json:"tool_type"`
	Location     string `json:"location"`
	CanonicalKey string `json:"canonical_key"`
}

type Edge struct {
	EdgeID       string `json:"edge_id"`
	Org          string `json:"org"`
	Repo         string `json:"repo"`
	FromNodeID   string `json:"from_node_id"`
	ToNodeID     string `json:"to_node_id"`
	Rationale    string `json:"rationale"`
	SourceLink   string `json:"source_link"`
	SourceDetail string `json:"source_detail"`
}

type Graph struct {
	Org   string `json:"org"`
	Repo  string `json:"repo"`
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

func Build(findings []model.Finding) []Graph {
	type repoGroup struct {
		org      string
		repo     string
		findings []model.Finding
	}
	byRepo := map[string]repoGroup{}
	for _, finding := range findings {
		repo := strings.TrimSpace(finding.Repo)
		if repo == "" {
			continue
		}
		org := fallbackOrg(finding.Org)
		key := org + "::" + repo
		group := byRepo[key]
		group.org = org
		group.repo = repo
		group.findings = append(group.findings, finding)
		byRepo[key] = group
	}

	keys := make([]string, 0, len(byRepo))
	for key := range byRepo {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]Graph, 0, len(keys))
	for _, key := range keys {
		group := byRepo[key]
		graph := buildRepoGraph(group.org, group.repo, group.findings)
		if len(graph.Nodes) == 0 || len(graph.Edges) == 0 {
			continue
		}
		out = append(out, graph)
	}
	return out
}

func buildRepoGraph(org string, repo string, findings []model.Finding) Graph {
	entryNodes := make([]Node, 0)
	pivotNodes := make([]Node, 0)
	targetNodes := make([]Node, 0)

	nodeSet := map[string]Node{}
	edgeSet := map[string]Edge{}
	addNode := func(node Node) {
		if _, exists := nodeSet[node.NodeID]; exists {
			return
		}
		nodeSet[node.NodeID] = node
		switch node.Kind {
		case "entry":
			entryNodes = append(entryNodes, node)
		case "pivot":
			pivotNodes = append(pivotNodes, node)
		case "target":
			targetNodes = append(targetNodes, node)
		}
	}
	addEdge := func(edge Edge) {
		if _, exists := edgeSet[edge.EdgeID]; exists {
			return
		}
		edgeSet[edge.EdgeID] = edge
	}
	for _, finding := range findings {
		kind := nodeKind(finding)
		if kind == "" {
			continue
		}
		node := Node{
			NodeID:       nodeID(kind, finding),
			Org:          org,
			Repo:         repo,
			Kind:         kind,
			FindingType:  strings.TrimSpace(finding.FindingType),
			ToolType:     strings.TrimSpace(finding.ToolType),
			Location:     strings.TrimSpace(finding.Location),
			CanonicalKey: canonicalFindingKey(finding),
		}
		addNode(node)
		if strings.TrimSpace(finding.FindingType) == "agent_framework" {
			syntheticNodes, syntheticEdges := agentRelationshipNodesAndEdges(org, repo, node, finding)
			for _, synthetic := range syntheticNodes {
				addNode(synthetic)
			}
			for _, synthetic := range syntheticEdges {
				addEdge(synthetic)
			}
		}
		if strings.TrimSpace(finding.FindingType) == "ci_autonomy" || strings.TrimSpace(finding.FindingType) == "compiled_action" {
			syntheticNodes, syntheticEdges := workflowRelationshipNodesAndEdges(org, repo, node, finding)
			for _, synthetic := range syntheticNodes {
				addNode(synthetic)
			}
			for _, synthetic := range syntheticEdges {
				addEdge(synthetic)
			}
		}
	}

	sortNodes(entryNodes)
	sortNodes(pivotNodes)
	sortNodes(targetNodes)

	edges := make([]Edge, 0, len(edgeSet))
	for _, edge := range edgeSet {
		edges = append(edges, edge)
	}
	if len(entryNodes) > 0 && len(pivotNodes) > 0 {
		for _, entry := range entryNodes {
			for _, pivot := range pivotNodes {
				addEdge(newEdge(org, repo, entry, pivot, "entry_to_pivot"))
			}
		}
		for _, pivot := range pivotNodes {
			for _, target := range targetNodes {
				addEdge(newEdge(org, repo, pivot, target, "pivot_to_target"))
			}
		}
	} else {
		for _, entry := range entryNodes {
			for _, target := range targetNodes {
				addEdge(newEdge(org, repo, entry, target, "entry_to_target"))
			}
		}
	}
	edges = edges[:0]
	for _, edge := range edgeSet {
		edges = append(edges, edge)
	}

	sort.Slice(edges, func(i, j int) bool {
		if edges[i].FromNodeID != edges[j].FromNodeID {
			return edges[i].FromNodeID < edges[j].FromNodeID
		}
		if edges[i].ToNodeID != edges[j].ToNodeID {
			return edges[i].ToNodeID < edges[j].ToNodeID
		}
		return edges[i].Rationale < edges[j].Rationale
	})

	nodes := append([]Node{}, entryNodes...)
	nodes = append(nodes, pivotNodes...)
	nodes = append(nodes, targetNodes...)
	return Graph{Org: org, Repo: repo, Nodes: nodes, Edges: edges}
}

func nodeKind(finding model.Finding) string {
	switch strings.TrimSpace(finding.FindingType) {
	case "agent_framework":
		return "entry"
	case "a2a_agent_card", "webmcp_declaration", "prompt_channel_hidden_text", "prompt_channel_override", "prompt_channel_untrusted_context":
		return "entry"
	case "ci_autonomy", "mcp_server", "compiled_action", "skill", "skill_metrics":
		return "pivot"
	case "secret_presence", "policy_violation":
		return "target"
	}
	for _, permission := range finding.Permissions {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		if normalized == "filesystem.write" || normalized == "db.write" || normalized == "production.write" {
			return "target"
		}
	}
	return ""
}

func nodeID(kind string, finding model.Finding) string {
	parts := []string{
		kind,
		strings.TrimSpace(finding.FindingType),
		strings.TrimSpace(finding.ToolType),
		strings.TrimSpace(finding.Location),
	}
	if identityComponent := findingIdentityComponent(finding); identityComponent != "" {
		parts = append(parts, identityComponent)
	}
	return strings.Join(parts, "::")
}

func canonicalFindingKey(finding model.Finding) string {
	parts := []string{
		strings.TrimSpace(finding.FindingType),
		strings.TrimSpace(finding.RuleID),
		strings.TrimSpace(finding.ToolType),
		strings.TrimSpace(finding.Location),
		strings.TrimSpace(finding.Repo),
		fallbackOrg(finding.Org),
	}
	if identityComponent := findingIdentityComponent(finding); identityComponent != "" {
		parts = append(parts[:4], append([]string{identityComponent}, parts[4:]...)...)
	}
	return strings.Join(parts, "|")
}

func newEdge(org string, repo string, from Node, to Node, rationale string) Edge {
	edgeID := fmt.Sprintf("%s::%s::%s::%s", from.NodeID, to.NodeID, rationale, repo)
	return Edge{
		EdgeID:       edgeID,
		Org:          org,
		Repo:         repo,
		FromNodeID:   from.NodeID,
		ToNodeID:     to.NodeID,
		Rationale:    rationale,
		SourceLink:   from.CanonicalKey,
		SourceDetail: to.CanonicalKey,
	}
}

func sortNodes(nodes []Node) {
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Kind != nodes[j].Kind {
			return nodes[i].Kind < nodes[j].Kind
		}
		if nodes[i].FindingType != nodes[j].FindingType {
			return nodes[i].FindingType < nodes[j].FindingType
		}
		if nodes[i].ToolType != nodes[j].ToolType {
			return nodes[i].ToolType < nodes[j].ToolType
		}
		if nodes[i].Location != nodes[j].Location {
			return nodes[i].Location < nodes[j].Location
		}
		return nodes[i].NodeID < nodes[j].NodeID
	})
}

func findingIdentityComponent(finding model.Finding) string {
	if strings.TrimSpace(finding.FindingType) != "agent_framework" {
		return ""
	}
	symbol := ""
	for _, evidence := range finding.Evidence {
		key := strings.ToLower(strings.TrimSpace(evidence.Key))
		if key == "symbol" || key == "name" || key == "agent_name" {
			symbol = strings.TrimSpace(evidence.Value)
			break
		}
	}
	startLine := 0
	endLine := 0
	if finding.LocationRange != nil {
		startLine = finding.LocationRange.StartLine
		endLine = finding.LocationRange.EndLine
	}
	if symbol == "" && startLine == 0 && endLine == 0 {
		return ""
	}
	return identity.AgentInstanceID(finding.ToolType, finding.Location, symbol, startLine, endLine)
}

func agentRelationshipNodesAndEdges(org string, repo string, agentNode Node, finding model.Finding) ([]Node, []Edge) {
	pivots := make([]Node, 0)
	targets := make([]Node, 0)
	edges := make([]Edge, 0)
	agentKey := strings.TrimSpace(agentNode.CanonicalKey)

	tools := splitEvidenceList(finding, "bound_tools")
	dataSources := splitEvidenceList(finding, "data_sources")
	authSurfaces := splitEvidenceList(finding, "auth_surfaces")
	deploymentArtifacts := splitEvidenceList(finding, "deployment_artifacts")

	for _, tool := range tools {
		pivot := syntheticNode(org, repo, "pivot", "agent_tool_binding", tool, finding.Location, agentKey+"|tool:"+tool)
		pivots = append(pivots, pivot)
		edges = append(edges, newEdge(org, repo, agentNode, pivot, "agent_to_tool_binding"))
	}
	for _, dataSource := range dataSources {
		target := syntheticNode(org, repo, "target", "agent_data_binding", dataSource, finding.Location, agentKey+"|data:"+dataSource)
		targets = append(targets, target)
		if len(pivots) == 0 {
			edges = append(edges, newEdge(org, repo, agentNode, target, "agent_to_data_binding"))
			continue
		}
		for _, pivot := range pivots {
			edges = append(edges, newEdge(org, repo, pivot, target, "tool_to_data_binding"))
		}
	}
	for _, authSurface := range authSurfaces {
		target := syntheticNode(org, repo, "target", "agent_auth_surface", authSurface, finding.Location, agentKey+"|auth:"+authSurface)
		targets = append(targets, target)
		if len(pivots) == 0 {
			edges = append(edges, newEdge(org, repo, agentNode, target, "agent_to_auth_surface"))
			continue
		}
		for _, pivot := range pivots {
			edges = append(edges, newEdge(org, repo, pivot, target, "tool_to_auth_surface"))
		}
	}
	for _, artifact := range deploymentArtifacts {
		target := syntheticNode(org, repo, "target", "agent_deploy_artifact", artifact, finding.Location, agentKey+"|deploy:"+artifact)
		targets = append(targets, target)
		if len(pivots) == 0 {
			edges = append(edges, newEdge(org, repo, agentNode, target, "agent_to_deploy_artifact"))
			continue
		}
		for _, pivot := range pivots {
			edges = append(edges, newEdge(org, repo, pivot, target, "tool_to_deploy_artifact"))
		}
	}

	nodes := append([]Node{}, pivots...)
	nodes = append(nodes, targets...)
	return nodes, edges
}

func syntheticNode(org, repo, kind, findingType, toolType, location, canonicalKey string) Node {
	node := Node{
		Org:          org,
		Repo:         repo,
		Kind:         kind,
		FindingType:  strings.TrimSpace(findingType),
		ToolType:     strings.TrimSpace(toolType),
		Location:     strings.TrimSpace(location),
		CanonicalKey: strings.TrimSpace(canonicalKey),
	}
	node.NodeID = nodeID(kind, model.Finding{
		FindingType: node.FindingType,
		ToolType:    node.ToolType,
		Location:    node.Location,
	})
	return node
}

func workflowRelationshipNodesAndEdges(org string, repo string, workflowNode Node, finding model.Finding) ([]Node, []Edge) {
	type capabilityTarget struct {
		findingType string
		rationale   string
	}
	targetsByCapability := map[string]capabilityTarget{
		"pull_request.write": {findingType: "workflow_pull_request", rationale: "workflow_to_pull_request"},
		"merge.execute":      {findingType: "workflow_merge_capability", rationale: "workflow_to_merge"},
		"deploy.write":       {findingType: "workflow_deploy_capability", rationale: "workflow_to_deploy"},
	}

	nodes := make([]Node, 0, len(finding.Permissions))
	edges := make([]Edge, 0, len(finding.Permissions))
	seen := map[string]struct{}{}
	for _, permission := range finding.Permissions {
		capability := strings.ToLower(strings.TrimSpace(permission))
		target, ok := targetsByCapability[capability]
		if !ok {
			continue
		}
		if _, exists := seen[capability]; exists {
			continue
		}
		seen[capability] = struct{}{}
		node := syntheticNode(org, repo, "target", target.findingType, capability, finding.Location, workflowNode.CanonicalKey+"|workflow:"+capability)
		nodes = append(nodes, node)
		edges = append(edges, newEdge(org, repo, workflowNode, node, target.rationale))
	}
	return nodes, edges
}

func splitEvidenceList(finding model.Finding, key string) []string {
	needle := strings.ToLower(strings.TrimSpace(key))
	set := map[string]struct{}{}
	for _, item := range finding.Evidence {
		if strings.ToLower(strings.TrimSpace(item.Key)) != needle {
			continue
		}
		for _, part := range strings.Split(item.Value, ",") {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			set[trimmed] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return strings.TrimSpace(org)
}

const ControlPathGraphVersion = "1"

const (
	ControlPathNodeControlPath       = "control_path"
	ControlPathNodeAgent             = "agent"
	ControlPathNodeExecutionIdentity = "execution_identity"
	ControlPathNodeCredential        = "credential"
	ControlPathNodeTool              = "tool"
	ControlPathNodeWorkflow          = "workflow"
	ControlPathNodeRepo              = "repo"
	ControlPathNodeGovernanceControl = "governance_control"
	ControlPathNodeTarget            = "target"
	ControlPathNodeActionCapability  = "action_capability"
)

type ControlPathInput struct {
	PathID                   string
	AgentID                  string
	Org                      string
	Repo                     string
	ToolType                 string
	Location                 string
	ExecutionIdentity        string
	ExecutionIdentityType    string
	ExecutionIdentitySource  string
	ExecutionIdentityStatus  string
	CredentialAccess         bool
	CredentialProvenance     *agginventory.CredentialProvenance
	GovernanceControls       []agginventory.GovernanceControlMapping
	MatchedProductionTargets []string
	WritePathClasses         []string
	PullRequestWrite         bool
	MergeExecute             bool
	DeployWrite              bool
	ProductionWrite          bool
	ApprovalGap              bool
	AttackPathRefs           []string
	SourceFindingKeys        []string
}

type ControlPathGraph struct {
	Version string                  `json:"version"`
	Summary ControlPathGraphSummary `json:"summary"`
	Nodes   []ControlPathNode       `json:"nodes"`
	Edges   []ControlPathEdge       `json:"edges"`
}

type ControlPathGraphSummary struct {
	TotalNodes int                     `json:"total_nodes"`
	TotalEdges int                     `json:"total_edges"`
	NodeKinds  []ControlPathKindRollup `json:"node_kinds"`
	EdgeKinds  []ControlPathKindRollup `json:"edge_kinds"`
}

type ControlPathKindRollup struct {
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

type ControlPathNode struct {
	NodeID            string   `json:"node_id"`
	PathID            string   `json:"path_id"`
	Kind              string   `json:"kind"`
	Org               string   `json:"org"`
	Repo              string   `json:"repo"`
	Label             string   `json:"label,omitempty"`
	ToolType          string   `json:"tool_type,omitempty"`
	Location          string   `json:"location,omitempty"`
	AgentID           string   `json:"agent_id,omitempty"`
	Status            string   `json:"status,omitempty"`
	EvidenceRefs      []string `json:"evidence_refs,omitempty"`
	SourceRefs        []string `json:"source_refs,omitempty"`
	AttackPathRefs    []string `json:"attack_path_refs,omitempty"`
	SourceFindingKeys []string `json:"source_finding_keys,omitempty"`
}

type ControlPathEdge struct {
	EdgeID            string   `json:"edge_id"`
	PathID            string   `json:"path_id"`
	Kind              string   `json:"kind"`
	FromNodeID        string   `json:"from_node_id"`
	ToNodeID          string   `json:"to_node_id"`
	EvidenceRefs      []string `json:"evidence_refs,omitempty"`
	SourceRefs        []string `json:"source_refs,omitempty"`
	AttackPathRefs    []string `json:"attack_path_refs,omitempty"`
	SourceFindingKeys []string `json:"source_finding_keys,omitempty"`
}

func BuildControlPathGraph(paths []ControlPathInput) *ControlPathGraph {
	if len(paths) == 0 {
		return nil
	}

	ordered := append([]ControlPathInput(nil), paths...)
	sort.Slice(ordered, func(i, j int) bool {
		if strings.TrimSpace(ordered[i].Org) != strings.TrimSpace(ordered[j].Org) {
			return strings.TrimSpace(ordered[i].Org) < strings.TrimSpace(ordered[j].Org)
		}
		if strings.TrimSpace(ordered[i].Repo) != strings.TrimSpace(ordered[j].Repo) {
			return strings.TrimSpace(ordered[i].Repo) < strings.TrimSpace(ordered[j].Repo)
		}
		return strings.TrimSpace(ordered[i].PathID) < strings.TrimSpace(ordered[j].PathID)
	})

	nodes := make([]ControlPathNode, 0, len(ordered)*8)
	edges := make([]ControlPathEdge, 0, len(ordered)*8)
	nodeCounts := map[string]int{}
	edgeCounts := map[string]int{}
	for _, path := range ordered {
		pathNodes, pathEdges := buildControlPath(path)
		nodes = append(nodes, pathNodes...)
		edges = append(edges, pathEdges...)
		for _, node := range pathNodes {
			nodeCounts[node.Kind]++
		}
		for _, edge := range pathEdges {
			edgeCounts[edge.Kind]++
		}
	}

	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].PathID != nodes[j].PathID {
			return nodes[i].PathID < nodes[j].PathID
		}
		if nodes[i].Kind != nodes[j].Kind {
			return nodes[i].Kind < nodes[j].Kind
		}
		return nodes[i].NodeID < nodes[j].NodeID
	})
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].PathID != edges[j].PathID {
			return edges[i].PathID < edges[j].PathID
		}
		if edges[i].Kind != edges[j].Kind {
			return edges[i].Kind < edges[j].Kind
		}
		return edges[i].EdgeID < edges[j].EdgeID
	})

	return &ControlPathGraph{
		Version: ControlPathGraphVersion,
		Summary: ControlPathGraphSummary{
			TotalNodes: len(nodes),
			TotalEdges: len(edges),
			NodeKinds:  summarizeControlPathKinds(nodeCounts),
			EdgeKinds:  summarizeControlPathKinds(edgeCounts),
		},
		Nodes: nodes,
		Edges: edges,
	}
}

func buildControlPath(path ControlPathInput) ([]ControlPathNode, []ControlPathEdge) {
	pathID := strings.TrimSpace(path.PathID)
	if pathID == "" {
		return nil, nil
	}
	org := fallbackOrg(path.Org)
	repo := controlValue(path.Repo, "unknown_repo")
	location := controlValue(path.Location, "unknown_workflow")
	toolType := controlValue(path.ToolType, "unknown_tool")

	pathNode := newControlPathNode(pathID, ControlPathNodeControlPath, org, repo, "control_path", toolType, location, strings.TrimSpace(path.AgentID), pathStatus(path), controlEvidenceRefs(path), controlSourceRefs(repo, location), path.AttackPathRefs, path.SourceFindingKeys)
	nodes := []ControlPathNode{pathNode}
	edges := make([]ControlPathEdge, 0, 16)

	agentNode := newControlPathNode(pathID, ControlPathNodeAgent, org, repo, controlValue(path.AgentID, "unknown_agent"), toolType, location, strings.TrimSpace(path.AgentID), "", controlEvidenceRefs(path), controlSourceRefs(repo, location), path.AttackPathRefs, path.SourceFindingKeys)
	nodes = append(nodes, agentNode)
	edges = append(edges, newControlPathEdge(pathID, "agent_controls_path", agentNode.NodeID, pathNode.NodeID, controlEvidenceRefs(path), controlSourceRefs(repo, location), path.AttackPathRefs, path.SourceFindingKeys))

	toolNode := newControlPathNode(pathID, ControlPathNodeTool, org, repo, toolType, toolType, location, strings.TrimSpace(path.AgentID), "", controlEvidenceRefs(path), controlSourceRefs(repo, location), path.AttackPathRefs, path.SourceFindingKeys)
	nodes = append(nodes, toolNode)
	edges = append(edges, newControlPathEdge(pathID, "path_uses_tool", pathNode.NodeID, toolNode.NodeID, controlEvidenceRefs(path), controlSourceRefs(repo, location), path.AttackPathRefs, path.SourceFindingKeys))

	workflowNode := newControlPathNode(pathID, ControlPathNodeWorkflow, org, repo, location, toolType, location, strings.TrimSpace(path.AgentID), "", controlEvidenceRefs(path), controlSourceRefs(repo, location), path.AttackPathRefs, path.SourceFindingKeys)
	nodes = append(nodes, workflowNode)
	edges = append(edges, newControlPathEdge(pathID, "path_executes_workflow", pathNode.NodeID, workflowNode.NodeID, controlEvidenceRefs(path), controlSourceRefs(repo, location), path.AttackPathRefs, path.SourceFindingKeys))

	repoNode := newControlPathNode(pathID, ControlPathNodeRepo, org, repo, repo, toolType, "", strings.TrimSpace(path.AgentID), "", controlEvidenceRefs(path), []string{repo}, path.AttackPathRefs, path.SourceFindingKeys)
	nodes = append(nodes, repoNode)
	edges = append(edges, newControlPathEdge(pathID, "workflow_in_repo", workflowNode.NodeID, repoNode.NodeID, controlEvidenceRefs(path), []string{repo}, path.AttackPathRefs, path.SourceFindingKeys))

	execLabel := "unknown_execution_identity"
	if strings.TrimSpace(path.ExecutionIdentityStatus) == "known" && strings.TrimSpace(path.ExecutionIdentity) != "" {
		execLabel = strings.TrimSpace(path.ExecutionIdentity)
	}
	execStatus := controlValue(path.ExecutionIdentityStatus, "unknown")
	execEvidence := append(controlEvidenceRefs(path), "execution_identity_source:"+controlValue(path.ExecutionIdentitySource, "unknown"))
	execNode := newControlPathNode(pathID, ControlPathNodeExecutionIdentity, org, repo, execLabel, toolType, location, strings.TrimSpace(path.AgentID), execStatus, execEvidence, controlSourceRefs(repo, location), path.AttackPathRefs, path.SourceFindingKeys)
	nodes = append(nodes, execNode)
	edges = append(edges, newControlPathEdge(pathID, "path_runs_as", pathNode.NodeID, execNode.NodeID, execEvidence, controlSourceRefs(repo, location), path.AttackPathRefs, path.SourceFindingKeys))

	credentialNode := controlCredentialNode(pathID, path, org, repo, toolType, location)
	if credentialNode != nil {
		nodes = append(nodes, *credentialNode)
		edges = append(edges, newControlPathEdge(pathID, "execution_uses_credential", execNode.NodeID, credentialNode.NodeID, credentialNode.EvidenceRefs, credentialNode.SourceRefs, path.AttackPathRefs, path.SourceFindingKeys))
	}

	for _, item := range actionCapabilityLabels(path) {
		actionNode := newControlPathNode(pathID, ControlPathNodeActionCapability, org, repo, item, toolType, location, strings.TrimSpace(path.AgentID), "", append(controlEvidenceRefs(path), "capability:"+item), controlSourceRefs(repo, location), path.AttackPathRefs, path.SourceFindingKeys)
		nodes = append(nodes, actionNode)
		edges = append(edges, newControlPathEdge(pathID, "path_enables_action", pathNode.NodeID, actionNode.NodeID, actionNode.EvidenceRefs, actionNode.SourceRefs, path.AttackPathRefs, path.SourceFindingKeys))
	}

	for _, target := range controlTargets(path) {
		targetNode := newControlPathNode(pathID, ControlPathNodeTarget, org, repo, target, toolType, location, strings.TrimSpace(path.AgentID), "", append(controlEvidenceRefs(path), "target:"+target), controlSourceRefs(repo, location), path.AttackPathRefs, path.SourceFindingKeys)
		nodes = append(nodes, targetNode)
		edges = append(edges, newControlPathEdge(pathID, "path_targets_surface", pathNode.NodeID, targetNode.NodeID, targetNode.EvidenceRefs, targetNode.SourceRefs, path.AttackPathRefs, path.SourceFindingKeys))
	}

	for _, control := range controlMappings(path.GovernanceControls) {
		controlNode := newControlPathNode(pathID, ControlPathNodeGovernanceControl, org, repo, control.Control, toolType, location, strings.TrimSpace(path.AgentID), controlValue(control.Status, "unknown"), append(controlEvidenceRefs(path), "governance_control:"+control.Control), controlSourceRefs(repo, location), path.AttackPathRefs, path.SourceFindingKeys)
		nodes = append(nodes, controlNode)
		edges = append(edges, newControlPathEdge(pathID, "path_governed_by", pathNode.NodeID, controlNode.NodeID, controlNode.EvidenceRefs, controlNode.SourceRefs, path.AttackPathRefs, path.SourceFindingKeys))
	}

	return nodes, edges
}

func controlCredentialNode(pathID string, path ControlPathInput, org string, repo string, toolType string, location string) *ControlPathNode {
	provenance := agginventory.NormalizeCredentialProvenance(path.CredentialProvenance)
	if provenance == nil && !path.CredentialAccess {
		return nil
	}
	label := "unknown_credential"
	status := "unknown"
	evidenceRefs := controlEvidenceRefs(path)
	if provenance != nil {
		label = provenance.Type
		if strings.TrimSpace(provenance.Subject) != "" {
			label = provenance.Type + ":" + strings.TrimSpace(provenance.Subject)
		}
		status = controlValue(provenance.Scope, "unknown")
		for _, item := range provenance.EvidenceBasis {
			evidenceRefs = append(evidenceRefs, "credential_basis:"+item)
		}
	} else if path.CredentialAccess {
		label = "credential_access"
	}
	evidenceRefs = uniqueSortedStrings(evidenceRefs)
	node := newControlPathNode(pathID, ControlPathNodeCredential, org, repo, label, toolType, location, strings.TrimSpace(path.AgentID), status, evidenceRefs, controlSourceRefs(repo, location), path.AttackPathRefs, path.SourceFindingKeys)
	return &node
}

func newControlPathNode(pathID string, kind string, org string, repo string, label string, toolType string, location string, agentID string, status string, evidenceRefs []string, sourceRefs []string, attackPathRefs []string, sourceFindingKeys []string) ControlPathNode {
	label = strings.TrimSpace(label)
	rawID := strings.Join([]string{pathID, kind, label, strings.TrimSpace(toolType), strings.TrimSpace(location), strings.TrimSpace(agentID), strings.TrimSpace(status)}, "|")
	return ControlPathNode{
		NodeID:            controlPathStableID("cpg-node", rawID),
		PathID:            strings.TrimSpace(pathID),
		Kind:              strings.TrimSpace(kind),
		Org:               fallbackOrg(org),
		Repo:              strings.TrimSpace(repo),
		Label:             label,
		ToolType:          strings.TrimSpace(toolType),
		Location:          strings.TrimSpace(location),
		AgentID:           strings.TrimSpace(agentID),
		Status:            strings.TrimSpace(status),
		EvidenceRefs:      uniqueSortedStrings(evidenceRefs),
		SourceRefs:        uniqueSortedStrings(sourceRefs),
		AttackPathRefs:    uniqueSortedStrings(attackPathRefs),
		SourceFindingKeys: uniqueSortedStrings(sourceFindingKeys),
	}
}

func newControlPathEdge(pathID string, kind string, fromNodeID string, toNodeID string, evidenceRefs []string, sourceRefs []string, attackPathRefs []string, sourceFindingKeys []string) ControlPathEdge {
	rawID := strings.Join([]string{strings.TrimSpace(pathID), strings.TrimSpace(kind), strings.TrimSpace(fromNodeID), strings.TrimSpace(toNodeID)}, "|")
	return ControlPathEdge{
		EdgeID:            controlPathStableID("cpg-edge", rawID),
		PathID:            strings.TrimSpace(pathID),
		Kind:              strings.TrimSpace(kind),
		FromNodeID:        strings.TrimSpace(fromNodeID),
		ToNodeID:          strings.TrimSpace(toNodeID),
		EvidenceRefs:      uniqueSortedStrings(evidenceRefs),
		SourceRefs:        uniqueSortedStrings(sourceRefs),
		AttackPathRefs:    uniqueSortedStrings(attackPathRefs),
		SourceFindingKeys: uniqueSortedStrings(sourceFindingKeys),
	}
}

func summarizeControlPathKinds(counts map[string]int) []ControlPathKindRollup {
	if len(counts) == 0 {
		return nil
	}
	kinds := make([]string, 0, len(counts))
	for kind := range counts {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	out := make([]ControlPathKindRollup, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, ControlPathKindRollup{Kind: kind, Count: counts[kind]})
	}
	return out
}

func controlPathStableID(prefix string, raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return strings.TrimSpace(prefix) + "-" + hex.EncodeToString(sum[:6])
}

func controlValue(value string, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return strings.TrimSpace(fallback)
	}
	return strings.TrimSpace(value)
}

func controlEvidenceRefs(path ControlPathInput) []string {
	values := []string{"path_id:" + strings.TrimSpace(path.PathID)}
	if strings.TrimSpace(path.AgentID) != "" {
		values = append(values, "agent_id:"+strings.TrimSpace(path.AgentID))
	}
	if path.CredentialAccess {
		values = append(values, "credential_access=true")
	}
	if path.ApprovalGap {
		values = append(values, "approval_gap=true")
	}
	return uniqueSortedStrings(values)
}

func controlSourceRefs(repo string, location string) []string {
	return uniqueSortedStrings([]string{strings.TrimSpace(repo), strings.TrimSpace(location)})
}

func controlTargets(path ControlPathInput) []string {
	values := uniqueSortedStrings(path.MatchedProductionTargets)
	if len(values) == 0 && path.ProductionWrite {
		return []string{"unknown_production_target"}
	}
	return values
}

func controlMappings(values []agginventory.GovernanceControlMapping) []agginventory.GovernanceControlMapping {
	if len(values) == 0 {
		return nil
	}
	out := append([]agginventory.GovernanceControlMapping(nil), values...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Control != out[j].Control {
			return out[i].Control < out[j].Control
		}
		return out[i].Status < out[j].Status
	})
	return out
}

func actionCapabilityLabels(path ControlPathInput) []string {
	values := make([]string, 0, 8)
	if path.PullRequestWrite {
		values = append(values, "pull_request_write")
	}
	if path.MergeExecute {
		values = append(values, "merge_execute")
	}
	if path.DeployWrite {
		values = append(values, "deploy_write")
	}
	if path.ProductionWrite {
		values = append(values, "production_write")
	}
	for _, class := range path.WritePathClasses {
		trimmed := strings.TrimSpace(class)
		if trimmed == "" {
			continue
		}
		values = append(values, "write_path_class:"+trimmed)
	}
	if len(values) == 0 {
		values = append(values, "read_only")
	}
	return uniqueSortedStrings(values)
}

func pathStatus(path ControlPathInput) string {
	switch {
	case path.ProductionWrite:
		return "production_write"
	case path.DeployWrite:
		return "deploy_write"
	case path.MergeExecute:
		return "merge_execute"
	case path.PullRequestWrite:
		return "pull_request_write"
	case path.CredentialAccess:
		return "credential_access"
	default:
		return "observed"
	}
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
