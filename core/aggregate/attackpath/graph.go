package attackpath

import (
	"fmt"
	"sort"
	"strings"

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
