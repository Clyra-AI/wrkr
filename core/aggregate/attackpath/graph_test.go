package attackpath

import (
	"reflect"
	"strings"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
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

func TestAttackGraph_IncludesWorkflowDeliveryCapabilityEdges(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "prompt_channel_override",
			ToolType:    "prompt_channel",
			Location:    "AGENTS.md",
			Repo:        "repo",
			Org:         "acme",
		},
		{
			FindingType: "ci_autonomy",
			ToolType:    "ci_agent",
			Location:    ".github/workflows/release.yml",
			Repo:        "repo",
			Org:         "acme",
			Permissions: []string{"pull_request.write", "merge.execute", "deploy.write"},
		},
	}

	graphs := Build(findings)
	if len(graphs) != 1 {
		t.Fatalf("expected one graph, got %d", len(graphs))
	}
	graph := graphs[0]
	for _, want := range []string{
		"target::workflow_pull_request::pull_request.write::.github/workflows/release.yml",
		"target::workflow_merge_capability::merge.execute::.github/workflows/release.yml",
		"target::workflow_deploy_capability::deploy.write::.github/workflows/release.yml",
	} {
		if !hasNode(graph.Nodes, want) {
			t.Fatalf("expected workflow capability node %s in graph: %#v", want, graph.Nodes)
		}
	}
	for _, want := range []string{"workflow_to_pull_request", "workflow_to_merge", "workflow_to_deploy"} {
		if !hasEdgeRationale(graph.Edges, want) {
			t.Fatalf("expected workflow rationale %s in graph edges: %#v", want, graph.Edges)
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

func TestControlPathGraphStableIDs(t *testing.T) {
	t.Parallel()

	inputs := []ControlPathInput{{
		PathID:                   "apc-a1b2c3d4e5f6",
		AgentID:                  "wrkr:compiled_action:acme",
		Org:                      "acme",
		Repo:                     "acme/payments",
		ToolType:                 "compiled_action",
		Location:                 ".github/workflows/release.yml",
		CredentialAccess:         true,
		PullRequestWrite:         true,
		MergeExecute:             true,
		DeployWrite:              true,
		ProductionWrite:          true,
		WritePathClasses:         []string{agginventory.WritePathPullRequestWrite, agginventory.WritePathDeployWrite},
		MatchedProductionTargets: []string{"cluster:prod"},
		GovernanceControls: []agginventory.GovernanceControlMapping{{
			Control: agginventory.GovernanceControlApproval,
			Status:  agginventory.ControlStatusGap,
		}},
	}}

	first := BuildControlPathGraph(inputs)
	second := BuildControlPathGraph(inputs)
	if first == nil || second == nil {
		t.Fatal("expected control_path_graph output")
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic control_path_graph\nfirst=%+v\nsecond=%+v", first, second)
	}
}

func TestControlPathGraphLinksIdentityCredentialToolWorkflowTargetAction(t *testing.T) {
	t.Parallel()

	graph := BuildControlPathGraph([]ControlPathInput{{
		PathID:                  "apc-graphpath01",
		AgentID:                 "wrkr:compiled_action:acme",
		Org:                     "acme",
		Repo:                    "acme/payments",
		ToolType:                "compiled_action",
		Location:                ".github/workflows/release.yml",
		ExecutionIdentity:       "release-app",
		ExecutionIdentityType:   "github_app",
		ExecutionIdentitySource: "workflow_static_signal",
		ExecutionIdentityStatus: "known",
		CredentialAccess:        true,
		CredentialProvenance: &agginventory.CredentialProvenance{
			Type:           agginventory.CredentialProvenanceStaticSecret,
			Subject:        "RELEASE_TOKEN",
			Scope:          agginventory.CredentialScopeWorkflow,
			Confidence:     "high",
			EvidenceBasis:  []string{"workflow_secret_refs"},
			RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceStaticSecret),
		},
		GovernanceControls: []agginventory.GovernanceControlMapping{{
			Control: agginventory.GovernanceControlApproval,
			Status:  agginventory.ControlStatusGap,
		}},
		MatchedProductionTargets: []string{"cluster:prod"},
		WritePathClasses:         []string{agginventory.WritePathPullRequestWrite, agginventory.WritePathDeployWrite},
		PullRequestWrite:         true,
		DeployWrite:              true,
		ProductionWrite:          true,
	}})
	if graph == nil {
		t.Fatal("expected control_path_graph")
	}

	requiredKinds := []string{
		ControlPathNodeControlPath,
		ControlPathNodeAgent,
		ControlPathNodeExecutionIdentity,
		ControlPathNodeCredential,
		ControlPathNodeTool,
		ControlPathNodeWorkflow,
		ControlPathNodeRepo,
		ControlPathNodeGovernanceControl,
		ControlPathNodeTarget,
		ControlPathNodeActionCapability,
	}
	for _, want := range requiredKinds {
		if !hasControlPathNodeKind(graph.Nodes, want) {
			t.Fatalf("expected node kind %s in %+v", want, graph.Nodes)
		}
	}
	for _, want := range []string{
		"agent_controls_path",
		"path_runs_as",
		"execution_uses_credential",
		"path_uses_tool",
		"path_executes_workflow",
		"workflow_in_repo",
		"path_governed_by",
		"path_targets_surface",
		"path_enables_action",
	} {
		if !hasControlPathEdgeKind(graph.Edges, want) {
			t.Fatalf("expected edge kind %s in %+v", want, graph.Edges)
		}
	}
}

func hasControlPathNodeKind(nodes []ControlPathNode, want string) bool {
	for _, node := range nodes {
		if node.Kind == want {
			return true
		}
	}
	return false
}

func hasControlPathEdgeKind(edges []ControlPathEdge, want string) bool {
	for _, edge := range edges {
		if edge.Kind == want {
			return true
		}
	}
	return false
}
