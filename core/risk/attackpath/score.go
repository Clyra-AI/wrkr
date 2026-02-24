package attackpath

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
)

type ScoredPath struct {
	PathID          string   `json:"path_id"`
	Org             string   `json:"org"`
	Repo            string   `json:"repo"`
	PathScore       float64  `json:"path_score"`
	EntryNodeID     string   `json:"entry_node_id"`
	PivotNodeID     string   `json:"pivot_node_id,omitempty"`
	TargetNodeID    string   `json:"target_node_id"`
	EntryExposure   float64  `json:"entry_exposure"`
	PivotPrivilege  float64  `json:"pivot_privilege"`
	TargetImpact    float64  `json:"target_impact"`
	EdgeRationale   []string `json:"edge_rationale"`
	Explain         []string `json:"explain"`
	SourceFindings  []string `json:"source_findings"`
	GenerationModel string   `json:"generation_model"`
}

func Score(graphs []aggattack.Graph) []ScoredPath {
	paths := make([]ScoredPath, 0)
	for _, graph := range graphs {
		paths = append(paths, scoreGraph(graph)...)
	}
	sortScoredPaths(paths)
	return paths
}

func scoreGraph(graph aggattack.Graph) []ScoredPath {
	nodeByID := map[string]aggattack.Node{}
	outEdgesByFrom := map[string][]aggattack.Edge{}
	for _, node := range graph.Nodes {
		nodeByID[node.NodeID] = node
	}
	for _, edge := range graph.Edges {
		outEdgesByFrom[edge.FromNodeID] = append(outEdgesByFrom[edge.FromNodeID], edge)
	}
	for key := range outEdgesByFrom {
		sort.Slice(outEdgesByFrom[key], func(i, j int) bool {
			if outEdgesByFrom[key][i].ToNodeID != outEdgesByFrom[key][j].ToNodeID {
				return outEdgesByFrom[key][i].ToNodeID < outEdgesByFrom[key][j].ToNodeID
			}
			return outEdgesByFrom[key][i].Rationale < outEdgesByFrom[key][j].Rationale
		})
	}

	paths := make([]ScoredPath, 0)
	for _, node := range graph.Nodes {
		if node.Kind != "entry" {
			continue
		}
		firstHop := outEdgesByFrom[node.NodeID]
		for _, edge := range firstHop {
			nextNode := nodeByID[edge.ToNodeID]
			if nextNode.Kind == "target" {
				paths = append(paths, buildPath(graph, node, aggattack.Node{}, nextNode, []aggattack.Edge{edge}))
				continue
			}
			if nextNode.Kind != "pivot" {
				continue
			}
			secondHop := outEdgesByFrom[nextNode.NodeID]
			for _, edge2 := range secondHop {
				target := nodeByID[edge2.ToNodeID]
				if target.Kind != "target" {
					continue
				}
				paths = append(paths, buildPath(graph, node, nextNode, target, []aggattack.Edge{edge, edge2}))
			}
		}
	}
	return dedupePaths(paths)
}

func buildPath(graph aggattack.Graph, entry aggattack.Node, pivot aggattack.Node, target aggattack.Node, edges []aggattack.Edge) ScoredPath {
	entryExposure := entryExposure(entry)
	pivotPrivilege := pivotPrivilege(pivot)
	targetImpact := targetImpact(target)
	score := entryExposure + pivotPrivilege + targetImpact
	if score > 10 {
		score = 10
	}

	reasons := []string{
		fmt.Sprintf("entry_exposure=%.2f", entryExposure),
		fmt.Sprintf("pivot_privilege=%.2f", pivotPrivilege),
		fmt.Sprintf("target_impact=%.2f", targetImpact),
	}
	edgeRationale := make([]string, 0, len(edges))
	sourceFindings := []string{entry.CanonicalKey, target.CanonicalKey}
	if pivot.NodeID != "" {
		sourceFindings = append(sourceFindings, pivot.CanonicalKey)
	}
	for _, edge := range edges {
		edgeRationale = append(edgeRationale, edge.Rationale)
	}
	sort.Strings(edgeRationale)
	sourceFindings = uniqueSorted(sourceFindings)
	pathID := pathID(graph.Org, graph.Repo, entry.NodeID, pivot.NodeID, target.NodeID)

	return ScoredPath{
		PathID:          pathID,
		Org:             graph.Org,
		Repo:            graph.Repo,
		PathScore:       round2(score),
		EntryNodeID:     entry.NodeID,
		PivotNodeID:     pivot.NodeID,
		TargetNodeID:    target.NodeID,
		EntryExposure:   round2(entryExposure),
		PivotPrivilege:  round2(pivotPrivilege),
		TargetImpact:    round2(targetImpact),
		EdgeRationale:   edgeRationale,
		Explain:         reasons,
		SourceFindings:  sourceFindings,
		GenerationModel: "wrkr_attack_path_v1",
	}
}

func entryExposure(node aggattack.Node) float64 {
	switch strings.TrimSpace(node.FindingType) {
	case "a2a_agent_card", "webmcp_declaration":
		return 3.4
	case "prompt_channel_untrusted_context":
		return 3.0
	case "prompt_channel_override", "prompt_channel_hidden_text":
		return 2.6
	default:
		return 2.2
	}
}

func pivotPrivilege(node aggattack.Node) float64 {
	switch strings.TrimSpace(node.FindingType) {
	case "ci_autonomy":
		return 3.4
	case "compiled_action":
		return 3.0
	case "mcp_server":
		return 2.7
	case "skill", "skill_metrics":
		return 2.4
	default:
		if strings.TrimSpace(node.NodeID) == "" {
			return 1.1
		}
		return 2.0
	}
}

func targetImpact(node aggattack.Node) float64 {
	switch strings.TrimSpace(node.FindingType) {
	case "secret_presence":
		return 3.5
	case "policy_violation":
		return 3.2
	default:
		return 2.2
	}
}

func pathID(org, repo, entry, pivot, target string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{org, repo, entry, pivot, target}, "|")))
	return "ap-" + hex.EncodeToString(sum[:6])
}

func dedupePaths(in []ScoredPath) []ScoredPath {
	seen := map[string]ScoredPath{}
	for _, item := range in {
		existing, exists := seen[item.PathID]
		if !exists || item.PathScore > existing.PathScore {
			seen[item.PathID] = item
		}
	}
	out := make([]ScoredPath, 0, len(seen))
	for _, item := range seen {
		out = append(out, item)
	}
	sortScoredPaths(out)
	return out
}

func sortScoredPaths(paths []ScoredPath) {
	sort.Slice(paths, func(i, j int) bool {
		if paths[i].PathScore != paths[j].PathScore {
			return paths[i].PathScore > paths[j].PathScore
		}
		if paths[i].Org != paths[j].Org {
			return paths[i].Org < paths[j].Org
		}
		if paths[i].Repo != paths[j].Repo {
			return paths[i].Repo < paths[j].Repo
		}
		return paths[i].PathID < paths[j].PathID
	})
}

func uniqueSorted(in []string) []string {
	set := map[string]struct{}{}
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func round2(in float64) float64 {
	return float64(int(in*100+0.5)) / 100
}
