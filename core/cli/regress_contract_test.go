package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestRegressRunJSONCarriesAgentInstanceIDInReasons(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	baselinePath := filepath.Join(tmp, "baseline.json")
	if err := os.WriteFile(baselinePath, []byte("{\"version\":\"v1\",\"tools\":[]}\n"), 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	instanceID := identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "ops_agent", 30, 42)
	if err := state.Save(statePath, state.Snapshot{
		Version: state.SnapshotVersion,
		Findings: []model.Finding{{
			FindingType:   "tool_config",
			ToolType:      "agentframework",
			Location:      ".wrkr/agents/research.yaml",
			LocationRange: &model.LocationRange{StartLine: 30, EndLine: 42},
			Org:           "acme",
			Repo:          "backend",
			Evidence:      []model.Evidence{{Key: "symbol", Value: "ops_agent"}},
		}},
		Identities: []manifest.IdentityRecord{{
			AgentID:       identity.AgentID(instanceID, "acme"),
			ToolID:        instanceID,
			Org:           "acme",
			Status:        identity.StateUnderReview,
			ApprovalState: "missing",
			Present:       true,
		}},
	}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"regress", "run", "--baseline", baselinePath, "--state", statePath, "--json"}, &out, &errOut)
	if code != 5 {
		t.Fatalf("expected drift exit 5, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse regress run payload: %v", err)
	}
	reasons, ok := payload["reasons"].([]any)
	if !ok || len(reasons) != 1 {
		t.Fatalf("expected one regress reason, got %v", payload["reasons"])
	}
	reason, ok := reasons[0].(map[string]any)
	if !ok {
		t.Fatalf("expected regress reason object, got %T", reasons[0])
	}
	if reason["agent_instance_id"] != instanceID {
		t.Fatalf("expected additive agent_instance_id=%q, got %v", instanceID, reason["agent_instance_id"])
	}
}
