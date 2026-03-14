package attackpath

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
)

func TestBuildGraphDeterministic(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{FindingType: "prompt_channel_untrusted_context", ToolType: "prompt_channel", Location: ".github/workflows/release.yml", Repo: "repo", Org: "acme"},
		{FindingType: "ci_autonomy", ToolType: "ci_agent", Location: ".github/workflows/release.yml", Repo: "repo", Org: "acme"},
		{FindingType: "secret_presence", ToolType: "secret", Location: ".env", Repo: "repo", Org: "acme"},
	}

	first := Build(findings)
	if len(first) != 1 {
		t.Fatalf("expected one graph, got %d", len(first))
	}
	if len(first[0].Nodes) == 0 || len(first[0].Edges) == 0 {
		t.Fatalf("expected non-empty graph: %#v", first[0])
	}

	for i := 0; i < 32; i++ {
		next := Build(findings)
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("non-deterministic graph output at run %d", i+1)
		}
	}
}

func TestBuildGraphSkipsReposWithoutComposableNodes(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{FindingType: "policy_check", ToolType: "policy", Location: "WRKR-001", Repo: "repo", Org: "acme"},
		{FindingType: "tool_config", ToolType: "codex", Location: "AGENTS.md", Repo: "repo", Org: "acme"},
	}
	graphs := Build(findings)
	if len(graphs) != 0 {
		t.Fatalf("expected zero graphs, got %#v", graphs)
	}
}

func TestAttackGraph_IncludesAgentToolDataDeployEdges(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "agent_framework",
			ToolType:    "langchain",
			Location:    "agents/release.py",
			Repo:        "repo",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "bound_tools", Value: "deploy.write,search.read"},
				{Key: "data_sources", Value: "warehouse.events"},
				{Key: "auth_surfaces", Value: "token"},
				{Key: "deployment_artifacts", Value: ".github/workflows/release.yml"},
			},
		},
	}

	graphs := Build(findings)
	if len(graphs) != 1 {
		t.Fatalf("expected one graph, got %d", len(graphs))
	}

	graph := graphs[0]
	requiredNodeIDs := []string{
		"entry::agent_framework::langchain::agents/release.py",
		"pivot::agent_tool_binding::deploy.write::agents/release.py",
		"pivot::agent_tool_binding::search.read::agents/release.py",
		"target::agent_auth_surface::token::agents/release.py",
		"target::agent_data_binding::warehouse.events::agents/release.py",
		"target::agent_deploy_artifact::.github/workflows/release.yml::agents/release.py",
	}
	for _, want := range requiredNodeIDs {
		if !hasNode(graph.Nodes, want) {
			t.Fatalf("expected node %s in graph: %#v", want, graph.Nodes)
		}
	}
	requiredRationales := []string{
		"agent_to_tool_binding",
		"tool_to_auth_surface",
		"tool_to_data_binding",
		"tool_to_deploy_artifact",
	}
	for _, want := range requiredRationales {
		if !hasEdgeRationale(graph.Edges, want) {
			t.Fatalf("expected rationale %s in graph edges: %#v", want, graph.Edges)
		}
	}
}

func TestAttackPathNodeEdgeIDs_AreDeterministic(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "agent_framework",
			ToolType:    "crewai",
			Location:    "crews/release.py",
			Repo:        "repo",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "bound_tools", Value: "deploy.write"},
				{Key: "data_sources", Value: "warehouse.events"},
				{Key: "deployment_artifacts", Value: "Dockerfile"},
			},
		},
	}

	first := Build(findings)
	for i := 0; i < 32; i++ {
		next := Build(findings)
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("non-deterministic agent graph output at run %d", i+1)
		}
	}
}

func TestAttackGraph_SeparatesSameFileAgentsByInstanceIdentity(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType:   "agent_framework",
			ToolType:      "crewai",
			Location:      "agents/crew.py",
			LocationRange: &model.LocationRange{StartLine: 4, EndLine: 9},
			Repo:          "repo",
			Org:           "acme",
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "research_agent"},
				{Key: "bound_tools", Value: "search.read"},
			},
		},
		{
			FindingType:   "agent_framework",
			ToolType:      "crewai",
			Location:      "agents/crew.py",
			LocationRange: &model.LocationRange{StartLine: 11, EndLine: 16},
			Repo:          "repo",
			Org:           "acme",
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "publisher_agent"},
				{Key: "bound_tools", Value: "deploy.write"},
			},
		},
	}

	graphs := Build(findings)
	if len(graphs) != 1 {
		t.Fatalf("expected one graph, got %d", len(graphs))
	}
	graph := graphs[0]
	entryCount := 0
	for _, node := range graph.Nodes {
		if strings.HasPrefix(node.NodeID, "entry::agent_framework::crewai::agents/crew.py::") {
			entryCount++
		}
	}
	if entryCount != 2 {
		t.Fatalf("expected two distinct same-file agent entry nodes, got %#v", graph.Nodes)
	}
}

func hasNode(nodes []Node, want string) bool {
	for _, node := range nodes {
		if node.NodeID == want {
			return true
		}
	}
	return false
}

func hasEdgeRationale(edges []Edge, want string) bool {
	for _, edge := range edges {
		if edge.Rationale == want {
			return true
		}
	}
	return false
}
