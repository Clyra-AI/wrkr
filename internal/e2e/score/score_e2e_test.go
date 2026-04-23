package scoree2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestE2EScoreJSONAndExplainContracts(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir repo fixture: %v", err)
	}

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	var scoreOut bytes.Buffer
	var scoreErr bytes.Buffer
	if code := cli.Run([]string{"score", "--state", statePath, "--json"}, &scoreOut, &scoreErr); code != 0 {
		t.Fatalf("score --json failed: %d (%s)", code, scoreErr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(scoreOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse score payload: %v", err)
	}
	for _, key := range []string{"score", "grade", "breakdown", "weighted_breakdown", "weights", "trend_delta"} {
		if _, present := payload[key]; !present {
			t.Fatalf("missing score key %q in %v", key, payload)
		}
	}

	scoreOut.Reset()
	scoreErr.Reset()
	if code := cli.Run([]string{"score", "--state", statePath, "--explain"}, &scoreOut, &scoreErr); code != 0 {
		t.Fatalf("score --explain failed: %d (%s)", code, scoreErr.String())
	}
	if !strings.Contains(scoreOut.String(), "wrkr score") {
		t.Fatalf("expected explain output, got %q", scoreOut.String())
	}
}

func TestE2EScoreJSONFailsClosedOnMalformedStateWithCachedScore(t *testing.T) {
	t.Parallel()

	statePath := filepath.Join(t.TempDir(), "state.json")
	payload := []byte(`{
  "version": "v1",
  "findings": "bad",
  "posture_score": {
    "score": 82.5,
    "grade": "B",
    "breakdown": {
      "policy_pass_rate": 90,
      "approval_coverage": 80,
      "severity_distribution": 70,
      "profile_compliance": 60,
      "drift_rate": 50
    },
    "weighted_breakdown": {
      "policy_pass_rate": 27,
      "approval_coverage": 16,
      "severity_distribution": 14,
      "profile_compliance": 12,
      "drift_rate": 10
    },
    "weights": {
      "policy_pass_rate": 30,
      "approval_coverage": 20,
      "severity_distribution": 20,
      "profile_compliance": 20,
      "drift_rate": 10
    },
    "trend_delta": 1.5
  }
}`)
	if err := os.WriteFile(statePath, payload, 0o600); err != nil {
		t.Fatalf("write malformed state: %v", err)
	}

	var scoreOut bytes.Buffer
	var scoreErr bytes.Buffer
	if code := cli.Run([]string{"score", "--state", statePath, "--json"}, &scoreOut, &scoreErr); code != 1 {
		t.Fatalf("expected runtime failure, got %d stdout=%q stderr=%q", code, scoreOut.String(), scoreErr.String())
	}
	if scoreOut.Len() != 0 {
		t.Fatalf("expected no stdout on malformed state failure, got %q", scoreOut.String())
	}

	var payloadOut map[string]any
	if err := json.Unmarshal(scoreErr.Bytes(), &payloadOut); err != nil {
		t.Fatalf("parse score error payload: %v", err)
	}
	errObject, ok := payloadOut["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object payload, got %v", payloadOut)
	}
	if errObject["code"] != "runtime_failure" {
		t.Fatalf("unexpected error code: %v", errObject["code"])
	}
}

func TestE2EScoreReflectsIdentityApproveWithoutRescan(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	repoRoot := mustFindRepoRoot(t)
	statePath := filepath.Join(tmp, "state.json")
	reposPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}
	agentID := firstInventoryAgentID(t, scanOut.Bytes())

	var scoreOut bytes.Buffer
	var scoreErr bytes.Buffer
	if code := cli.Run([]string{"score", "--state", statePath, "--json"}, &scoreOut, &scoreErr); code != 0 {
		t.Fatalf("initial score failed: %d (%s)", code, scoreErr.String())
	}
	before := parseJSONMap(t, scoreOut.Bytes())
	beforeBreakdown, ok := before["breakdown"].(map[string]any)
	if !ok {
		t.Fatalf("expected initial breakdown, got %v", before)
	}
	beforeCoverage, ok := beforeBreakdown["approval_coverage"].(float64)
	if !ok {
		t.Fatalf("expected initial approval_coverage, got %v", beforeBreakdown)
	}

	var approveOut bytes.Buffer
	var approveErr bytes.Buffer
	if code := cli.Run([]string{"identity", "approve", agentID, "--approver", "@maria", "--scope", "read-only", "--expires", "90d", "--state", statePath, "--json"}, &approveOut, &approveErr); code != 0 {
		t.Fatalf("identity approve failed: %d (%s)", code, approveErr.String())
	}

	scoreOut.Reset()
	scoreErr.Reset()
	if code := cli.Run([]string{"score", "--state", statePath, "--json"}, &scoreOut, &scoreErr); code != 0 {
		t.Fatalf("post-approve score failed: %d (%s)", code, scoreErr.String())
	}
	after := parseJSONMap(t, scoreOut.Bytes())
	afterBreakdown, ok := after["breakdown"].(map[string]any)
	if !ok {
		t.Fatalf("expected post-approve breakdown, got %v", after)
	}
	afterCoverage, ok := afterBreakdown["approval_coverage"].(float64)
	if !ok {
		t.Fatalf("expected post-approve approval_coverage, got %v", afterBreakdown)
	}
	if afterCoverage <= beforeCoverage {
		t.Fatalf("expected approval coverage to increase after approval, before=%.2f after=%.2f", beforeCoverage, afterCoverage)
	}
}

func firstInventoryAgentID(t *testing.T, payload []byte) string {
	t.Helper()
	parsed := parseJSONMap(t, payload)
	inventoryPayload, ok := parsed["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory payload, got %v", parsed["inventory"])
	}
	tools, ok := inventoryPayload["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatalf("expected inventory tools, got %v", inventoryPayload["tools"])
	}
	firstTool, ok := tools[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected tool payload: %T", tools[0])
	}
	agentID, _ := firstTool["agent_id"].(string)
	if agentID == "" {
		t.Fatalf("expected agent_id in tool payload: %v", firstTool)
	}
	return agentID
}

func parseJSONMap(t *testing.T, payload []byte) map[string]any {
	t.Helper()
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("parse json payload: %v", err)
	}
	return parsed
}

func mustFindRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	current := wd
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(current, "go.mod")); err == nil {
			return current
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	t.Fatalf("could not locate repository root from %s", wd)
	return ""
}
