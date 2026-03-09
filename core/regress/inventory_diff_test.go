package regress

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestCompareInventoryUsesDeterministicFindingDiff(t *testing.T) {
	t.Parallel()

	baseline := state.Snapshot{
		Findings: []source.Finding{
			{FindingType: "mcp_server", ToolType: "mcp", Location: ".mcp.json", Repo: "local-machine", Org: "local", Evidence: []model.Evidence{{Key: "server", Value: "alpha"}}},
			{FindingType: "secret_presence", ToolType: "secret", Location: "process:env", Repo: "local-machine", Org: "local", Permissions: []string{"env.read"}},
		},
	}
	current := state.Snapshot{
		Findings: []source.Finding{
			{FindingType: "mcp_server", ToolType: "mcp", Location: ".mcp.json", Repo: "local-machine", Org: "local", Evidence: []model.Evidence{{Key: "server", Value: "beta"}}},
			{FindingType: "secret_presence", ToolType: "secret", Location: "process:env", Repo: "local-machine", Org: "local", Permissions: []string{"env.read", "env.write"}},
		},
	}

	result := CompareInventory(baseline, current)
	if !result.Drift {
		t.Fatal("expected inventory drift")
	}
	if result.AddedCount != 1 || result.RemovedCount != 1 || result.ChangedCount != 1 {
		t.Fatalf("unexpected counts: %+v", result)
	}
}
