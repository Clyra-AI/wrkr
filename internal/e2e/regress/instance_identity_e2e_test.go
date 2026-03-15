package regresse2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestE2ERegressInitPersistsAgentInstanceIDForSameFileAgents(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	baselinePath := filepath.Join(tmp, "baseline.json")

	findings := []model.Finding{
		{
			FindingType:   "tool_config",
			ToolType:      "agentframework",
			Location:      ".wrkr/agents/research.yaml",
			LocationRange: &model.LocationRange{StartLine: 12, EndLine: 24},
			Org:           "acme",
			Repo:          "backend",
			Evidence:      []model.Evidence{{Key: "symbol", Value: "research_agent"}},
		},
		{
			FindingType:   "tool_config",
			ToolType:      "agentframework",
			Location:      ".wrkr/agents/research.yaml",
			LocationRange: &model.LocationRange{StartLine: 30, EndLine: 42},
			Org:           "acme",
			Repo:          "backend",
			Evidence:      []model.Evidence{{Key: "symbol", Value: "ops_agent"}},
		},
	}
	if err := state.Save(statePath, state.Snapshot{
		Version:  state.SnapshotVersion,
		Target:   source.Target{Mode: "path", Value: "current"},
		Findings: findings,
		Identities: []manifest.IdentityRecord{
			{
				AgentID:       identity.AgentID(identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "research_agent", 12, 24), "acme"),
				ToolID:        identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "research_agent", 12, 24),
				Org:           "acme",
				Status:        identity.StateUnderReview,
				ApprovalState: "missing",
				Present:       true,
			},
			{
				AgentID:       identity.AgentID(identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "ops_agent", 30, 42), "acme"),
				ToolID:        identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "ops_agent", 30, 42),
				Org:           "acme",
				Status:        identity.StateUnderReview,
				ApprovalState: "missing",
				Present:       true,
			},
		},
	}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	var initOut bytes.Buffer
	var initErr bytes.Buffer
	if code := cli.Run([]string{"regress", "init", "--baseline", statePath, "--output", baselinePath, "--json"}, &initOut, &initErr); code != 0 {
		t.Fatalf("regress init failed: %d (%s)", code, initErr.String())
	}

	payload, err := os.ReadFile(baselinePath)
	if err != nil {
		t.Fatalf("read baseline: %v", err)
	}
	var baseline struct {
		Tools []struct {
			AgentInstanceID string `json:"agent_instance_id"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(payload, &baseline); err != nil {
		t.Fatalf("parse baseline payload: %v", err)
	}
	if len(baseline.Tools) != 2 {
		t.Fatalf("expected two baseline tools, got %+v", baseline.Tools)
	}
	if baseline.Tools[0].AgentInstanceID == "" || baseline.Tools[1].AgentInstanceID == "" {
		t.Fatalf("expected additive agent_instance_id fields in baseline payload, got %+v", baseline.Tools)
	}
	if baseline.Tools[0].AgentInstanceID == baseline.Tools[1].AgentInstanceID {
		t.Fatalf("expected distinct agent_instance_id values in baseline payload, got %+v", baseline.Tools)
	}
}
