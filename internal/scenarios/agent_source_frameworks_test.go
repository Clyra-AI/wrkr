package scenarios

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestScenarioAgentSourceFrameworksReleaseGate(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRootWithoutTag(t)
	scanRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "agent-source-frameworks", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", scanRoot, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	inventory, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory payload, got %T", payload["inventory"])
	}
	agents, ok := inventory["agents"].([]any)
	if !ok {
		t.Fatalf("expected inventory.agents array, got %T", inventory["agents"])
	}

	frameworks := map[string]int{}
	for _, raw := range agents {
		agent, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("unexpected agent payload %T", raw)
		}
		frameworks[agent["framework"].(string)]++
	}
	for _, framework := range []string{"crewai", "langchain", "mcp_client", "openai_agents", "custom_agent"} {
		if frameworks[framework] == 0 {
			t.Fatalf("expected release-gate fixture to produce framework %q, got %v", framework, frameworks)
		}
	}
}
