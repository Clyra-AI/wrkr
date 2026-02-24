package attackpath

import (
	"reflect"
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
