package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestScoreJSONUsesStoredPostureFromMinimalState(t *testing.T) {
	t.Parallel()

	statePath := filepath.Join(t.TempDir(), "state.json")
	payload := []byte(`{
  "version": "v1",
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
  },
  "risk_report": {
    "attack_paths": [{"id": "path-a"}],
    "top_attack_paths": [{"id": "path-b"}]
  }
}
`)
	if err := os.WriteFile(statePath, payload, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := Run([]string{"score", "--state", statePath, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("score failed: %d %s", code, stderr.String())
	}

	var got map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("parse score payload: %v", err)
	}
	if got["score"] != 82.5 {
		t.Fatalf("unexpected score payload: %v", got["score"])
	}
	if got["grade"] != "B" {
		t.Fatalf("unexpected grade payload: %v", got["grade"])
	}
	attackPaths, ok := got["attack_paths"].([]any)
	if !ok || len(attackPaths) != 1 {
		t.Fatalf("expected attack_paths payload, got %v", got["attack_paths"])
	}
	topAttackPaths, ok := got["top_attack_paths"].([]any)
	if !ok || len(topAttackPaths) != 1 {
		t.Fatalf("expected top_attack_paths payload, got %v", got["top_attack_paths"])
	}
}
