package attackpath

import (
	"fmt"
	"sort"
	"strings"

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
		if _, exists := nodeSet[node.NodeID]; exists {
			continue
		}
		nodeSet[node.NodeID] = node
		switch kind {
		case "entry":
			entryNodes = append(entryNodes, node)
		case "pivot":
			pivotNodes = append(pivotNodes, node)
		case "target":
			targetNodes = append(targetNodes, node)
		}
	}

	sortNodes(entryNodes)
	sortNodes(pivotNodes)
	sortNodes(targetNodes)

	edges := make([]Edge, 0)
	if len(entryNodes) > 0 && len(pivotNodes) > 0 {
		for _, entry := range entryNodes {
			for _, pivot := range pivotNodes {
				edges = append(edges, newEdge(org, repo, entry, pivot, "entry_to_pivot"))
			}
		}
		for _, pivot := range pivotNodes {
			for _, target := range targetNodes {
				edges = append(edges, newEdge(org, repo, pivot, target, "pivot_to_target"))
			}
		}
	} else {
		for _, entry := range entryNodes {
			for _, target := range targetNodes {
				edges = append(edges, newEdge(org, repo, entry, target, "entry_to_target"))
			}
		}
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
	return strings.Join([]string{
		kind,
		strings.TrimSpace(finding.FindingType),
		strings.TrimSpace(finding.ToolType),
		strings.TrimSpace(finding.Location),
	}, "::")
}

func canonicalFindingKey(finding model.Finding) string {
	return strings.Join([]string{
		strings.TrimSpace(finding.FindingType),
		strings.TrimSpace(finding.RuleID),
		strings.TrimSpace(finding.ToolType),
		strings.TrimSpace(finding.Location),
		strings.TrimSpace(finding.Repo),
		fallbackOrg(finding.Org),
	}, "|")
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
		return nodes[i].Location < nodes[j].Location
	})
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return strings.TrimSpace(org)
}
