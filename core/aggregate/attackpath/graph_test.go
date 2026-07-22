package attackpath

import (
	"fmt"
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

func TestControlPathGraphCompositionEvidenceRefsRemainDeterministic(t *testing.T) {
	t.Parallel()
	input := ControlPathInput{
		PathID: "apc-composition", AgentID: "wrkr:codex:acme", Org: "acme", Repo: "acme/release", ToolType: "codex", Location: ".github/workflows/release.yml",
		PolicyRefs: []string{"policy:z", "policy:a"}, AttackPathRefs: []string{"atk:z", "atk:a"}, SourceFindingKeys: []string{"finding:z", "finding:a"}, MatchedProductionTargets: []string{"prod:cluster"}, DeployWrite: true, ProductionWrite: true,
	}
	first := BuildControlPathGraph([]ControlPathInput{input})
	input.PolicyRefs = []string{"policy:a", "policy:z"}
	input.AttackPathRefs = []string{"atk:a", "atk:z"}
	input.SourceFindingKeys = []string{"finding:a", "finding:z"}
	second := BuildControlPathGraph([]ControlPathInput{input})
	if first == nil || second == nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("composition correlation evidence ordering changed graph identity: first=%+v second=%+v", first, second)
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
		return
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

func TestControlPathGraphCarriesPurposeVersionAndAuthorityRefs(t *testing.T) {
	t.Parallel()

	graph := BuildControlPathGraph([]ControlPathInput{{
		PathID:               "apc-meta",
		AgentID:              "wrkr:mcp:acme",
		Org:                  "acme",
		Repo:                 "acme/platform",
		ToolType:             "mcp",
		Location:             ".cursor/mcp.json",
		Purpose:              "registry sync",
		PurposeSource:        "server_description",
		PurposeConfidence:    "high",
		Version:              "1.2.3",
		VersionSource:        "command_or_arg",
		ConfigFingerprint:    "cfg-abc123",
		ConfigSource:         ".cursor/mcp.json#server:registry",
		CredentialAccess:     true,
		CredentialAuthority:  &agginventory.CredentialAuthority{CredentialPresent: true, CredentialUsableByPath: true, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
		CredentialProvenance: &agginventory.CredentialProvenance{Type: agginventory.CredentialProvenanceStaticSecret, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
	}})
	if graph == nil {
		t.Fatal("expected control_path_graph")
		return
	}

	nodes := graph.Nodes
	var toolNode, credentialNode *ControlPathNode
	for idx := range nodes {
		switch nodes[idx].Kind {
		case ControlPathNodeTool:
			toolNode = &nodes[idx]
		case ControlPathNodeCredential:
			credentialNode = &nodes[idx]
		}
	}
	if toolNode == nil || toolNode.Purpose != "registry sync" || toolNode.Version != "1.2.3" || toolNode.ConfigFingerprint != "cfg-abc123" {
		t.Fatalf("expected tool node metadata, got %+v", toolNode)
	}
	if credentialNode == nil || credentialNode.CredentialAuthorityRef == "" {
		t.Fatalf("expected credential authority on graph node, got %+v", credentialNode)
	}
	if credentialNode.CredentialAuthority != nil {
		t.Fatalf("expected graph node to omit embedded credential authority by default, got %+v", credentialNode)
	}
}

func TestBuildControlPathGraphUsesBoundedEndpointProjection(t *testing.T) {
	t.Parallel()

	semantics := make([]agginventory.MutableEndpointSemantic, 0, 48)
	for idx := 0; idx < 48; idx++ {
		semantics = append(semantics, agginventory.MutableEndpointSemantic{
			Semantic:     agginventory.EndpointSemanticRefund,
			Confidence:   "high",
			Surface:      "openapi",
			Operation:    fmt.Sprintf("POST /v1/refunds/%03d/issue", idx),
			EvidenceRefs: []string{fmt.Sprintf("finding:%03d", idx)},
		})
	}
	input := ControlPathInput{
		PathID:                      "apc-dense",
		AgentID:                     "wrkr:openapi:acme",
		Org:                         "acme",
		Repo:                        "acme/payments",
		ToolType:                    "openapi",
		Location:                    "openapi/payments.yaml",
		EndpointRefGroupProjection:  agginventory.BuildMutableEndpointGroupProjection(nil, semantics),
		MutableEndpointSemanticRefs: agginventory.CanonicalMutableEndpointRefs(semantics),
		MutableEndpointSemantics:    semantics,
	}
	graph := BuildControlPathGraph([]ControlPathInput{input})
	if graph == nil || len(graph.Nodes) == 0 {
		t.Fatalf("expected graph nodes, got %+v", graph)
	}
	var grouped *ControlPathNode
	for idx := range graph.Nodes {
		node := &graph.Nodes[idx]
		if node.EndpointRefCount > len(node.MutableEndpointSemanticRefs) {
			grouped = node
			break
		}
	}
	if grouped == nil {
		t.Fatalf("expected at least one grouped endpoint node, got %+v", graph.Nodes)
		return
	}
	if grouped.EndpointRefGroupID == "" || len(grouped.EndpointRouteGroups) == 0 || len(grouped.EndpointOperationCounts) == 0 {
		t.Fatalf("expected grouped endpoint metadata, got %+v", grouped)
	}
	if len(grouped.MutableEndpointSemanticRefs) > 8 {
		t.Fatalf("expected bounded endpoint refs on graph node, got %+v", grouped)
	}
	if len(grouped.MutableEndpointSemantics) > 0 {
		t.Fatalf("expected graph node to omit embedded endpoint payload clones by default, got %+v", grouped)
	}
	targetCount := 0
	for _, node := range graph.Nodes {
		if node.Kind == ControlPathNodeTarget {
			targetCount++
			if strings.HasPrefix(node.Label, "POST /v1/refunds/") {
				t.Fatalf("expected endpoint operations to be grouped before target-node emission, got %s", node.Label)
			}
		}
	}
	if targetCount > maxControlPathTargetsPerPath {
		t.Fatalf("expected bounded target nodes, got %d nodes in %+v", targetCount, graph.Nodes)
	}
	if !hasControlPathNodeLabel(graph.Nodes, ControlPathNodeTarget, "endpoint_class:refund:48") {
		t.Fatalf("expected grouped endpoint target label, got %+v", graph.Nodes)
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

func hasControlPathNodeLabel(nodes []ControlPathNode, kind string, label string) bool {
	for _, node := range nodes {
		if node.Kind == kind && node.Label == label {
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
