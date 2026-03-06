package attackpath

import (
	"reflect"
	"testing"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
)

func TestScoreDeterministicOrdering(t *testing.T) {
	t.Parallel()

	graphs := []aggattack.Graph{
		{
			Org:  "acme",
			Repo: "repo",
			Nodes: []aggattack.Node{
				{NodeID: "entry::prompt_channel_untrusted_context::prompt_channel::.github/workflows/release.yml", Kind: "entry", FindingType: "prompt_channel_untrusted_context", CanonicalKey: "entry"},
				{NodeID: "pivot::ci_autonomy::ci_agent::.github/workflows/release.yml", Kind: "pivot", FindingType: "ci_autonomy", CanonicalKey: "pivot"},
				{NodeID: "target::secret_presence::secret::.env", Kind: "target", FindingType: "secret_presence", CanonicalKey: "target"},
			},
			Edges: []aggattack.Edge{
				{FromNodeID: "entry::prompt_channel_untrusted_context::prompt_channel::.github/workflows/release.yml", ToNodeID: "pivot::ci_autonomy::ci_agent::.github/workflows/release.yml", Rationale: "entry_to_pivot"},
				{FromNodeID: "pivot::ci_autonomy::ci_agent::.github/workflows/release.yml", ToNodeID: "target::secret_presence::secret::.env", Rationale: "pivot_to_target"},
			},
		},
	}

	first := Score(graphs)
	if len(first) != 1 {
		t.Fatalf("expected one scored path, got %d", len(first))
	}
	if first[0].PathScore <= 0 {
		t.Fatalf("expected positive path score, got %.2f", first[0].PathScore)
	}

	for i := 0; i < 32; i++ {
		next := Score(graphs)
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("non-deterministic path scoring at run %d", i+1)
		}
	}
}

func TestScoreIncludesAgentRelationshipRationales(t *testing.T) {
	t.Parallel()

	graphs := []aggattack.Graph{
		{
			Org:  "acme",
			Repo: "repo",
			Nodes: []aggattack.Node{
				{NodeID: "entry::agent_framework::langchain::agents/release.py", Kind: "entry", FindingType: "agent_framework", CanonicalKey: "agent"},
				{NodeID: "pivot::agent_tool_binding::deploy.write::agents/release.py", Kind: "pivot", FindingType: "agent_tool_binding", ToolType: "deploy.write", CanonicalKey: "tool"},
				{NodeID: "target::agent_deploy_artifact::.github/workflows/release.yml::agents/release.py", Kind: "target", FindingType: "agent_deploy_artifact", CanonicalKey: "deploy"},
			},
			Edges: []aggattack.Edge{
				{FromNodeID: "entry::agent_framework::langchain::agents/release.py", ToNodeID: "pivot::agent_tool_binding::deploy.write::agents/release.py", Rationale: "agent_to_tool_binding"},
				{FromNodeID: "pivot::agent_tool_binding::deploy.write::agents/release.py", ToNodeID: "target::agent_deploy_artifact::.github/workflows/release.yml::agents/release.py", Rationale: "tool_to_deploy_artifact"},
			},
		},
	}

	paths := Score(graphs)
	if len(paths) != 1 {
		t.Fatalf("expected one agent scored path, got %d", len(paths))
	}
	if paths[0].PathScore <= 0 {
		t.Fatalf("expected positive path score, got %.2f", paths[0].PathScore)
	}
	reasonSet := map[string]bool{}
	for _, reason := range paths[0].Explain {
		reasonSet[reason] = true
	}
	for _, reason := range []string{"edge_rationale=agent_to_tool_binding", "edge_rationale=tool_to_deploy_artifact"} {
		if !reasonSet[reason] {
			t.Fatalf("expected agent edge rationale %s, got %v", reason, paths[0].Explain)
		}
	}
}
