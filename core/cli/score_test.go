package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
	"github.com/Clyra-AI/wrkr/core/score"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestScoreJSONUsesStoredPostureFromValidState(t *testing.T) {
	t.Parallel()

	statePath := filepath.Join(t.TempDir(), "state.json")
	snapshot := state.Snapshot{
		PostureScore: &score.Result{
			Score: 82.5,
			Grade: "B",
			Breakdown: score.Breakdown{
				PolicyPassRate:       90,
				ApprovalCoverage:     80,
				SeverityDistribution: 70,
				ProfileCompliance:    60,
				DriftRate:            50,
			},
			WeightedBreakdown: score.WeightedBreakdown{
				PolicyPassRate:       27,
				ApprovalCoverage:     16,
				SeverityDistribution: 14,
				ProfileCompliance:    12,
				DriftRate:            10,
			},
			Weights: scoremodel.Weights{
				PolicyPassRate:       30,
				ApprovalCoverage:     20,
				SeverityDistribution: 20,
				ProfileCompliance:    20,
				DriftRate:            10,
			},
			TrendDelta: 1.5,
		},
		RiskReport: &risk.Report{
			AttackPaths: []riskattack.ScoredPath{
				{
					PathID:          "path-a",
					Org:             "acme",
					Repo:            "backend",
					PathScore:       9.1,
					EntryNodeID:     "entry-a",
					TargetNodeID:    "target-a",
					EntryExposure:   3.1,
					PivotPrivilege:  2.8,
					TargetImpact:    3.2,
					EdgeRationale:   []string{"agent_to_auth_surface"},
					Explain:         []string{"entry_exposure=3.10"},
					SourceFindings:  []string{"finding-a"},
					GenerationModel: "wrkr_attack_path_v1",
				},
			},
			TopAttackPaths: []riskattack.ScoredPath{
				{
					PathID:          "path-b",
					Org:             "acme",
					Repo:            "backend",
					PathScore:       8.4,
					EntryNodeID:     "entry-b",
					TargetNodeID:    "target-b",
					EntryExposure:   2.9,
					PivotPrivilege:  2.5,
					TargetImpact:    3.0,
					EdgeRationale:   []string{"tool_to_auth_surface"},
					Explain:         []string{"entry_exposure=2.90"},
					SourceFindings:  []string{"finding-b"},
					GenerationModel: "wrkr_attack_path_v1",
				},
			},
		},
	}
	if err := state.Save(statePath, snapshot); err != nil {
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
	attackPath, ok := attackPaths[0].(map[string]any)
	if !ok || attackPath["path_id"] != "path-a" {
		t.Fatalf("expected stored attack path payload, got %v", got["attack_paths"])
	}
	topAttackPaths, ok := got["top_attack_paths"].([]any)
	if !ok || len(topAttackPaths) != 1 {
		t.Fatalf("expected top_attack_paths payload, got %v", got["top_attack_paths"])
	}
	topAttackPath, ok := topAttackPaths[0].(map[string]any)
	if !ok || topAttackPath["path_id"] != "path-b" {
		t.Fatalf("expected stored top_attack_paths payload, got %v", got["top_attack_paths"])
	}
}

func TestScoreJSONFailsClosedWhenCachedScoreStateContainsMalformedFindings(t *testing.T) {
	t.Parallel()

	assertMalformedCachedScoreStateRuntimeFailure(t, `{
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
}

func TestScoreJSONFailsClosedWhenCachedScoreStateIsMissingFindings(t *testing.T) {
	t.Parallel()

	assertMalformedCachedScoreStateRuntimeFailure(t, `{
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
  }
}`)
}

func TestScoreJSONFailsClosedWhenCachedScoreStateContainsMalformedIdentities(t *testing.T) {
	t.Parallel()

	assertMalformedCachedScoreStateRuntimeFailure(t, `{
  "version": "v1",
  "identities": "bad",
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
}

func TestScoreJSONFailsClosedWhenCachedScoreStateContainsMalformedRiskReport(t *testing.T) {
	t.Parallel()

	assertMalformedCachedScoreStateRuntimeFailure(t, `{
  "version": "v1",
  "risk_report": "bad",
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
}

func TestScoreJSONKeepsEmptyAttackPathArraysFromStoredState(t *testing.T) {
	t.Parallel()

	statePath := filepath.Join(t.TempDir(), "state.json")
	snapshot := state.Snapshot{
		Findings: []source.Finding{
			{ToolType: "source_repo", Location: "acme/backend", Org: "acme", Repo: "backend"},
		},
		PostureScore: &score.Result{
			Score: 82.5,
			Grade: "B",
		},
		RiskReport: &risk.Report{
			AttackPaths:    []riskattack.ScoredPath{},
			TopAttackPaths: []riskattack.ScoredPath{},
		},
	}
	if err := state.Save(statePath, snapshot); err != nil {
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
	if _, present := got["attack_paths"]; !present {
		t.Fatalf("expected attack_paths key to remain present, got %v", got)
	}
	if _, present := got["top_attack_paths"]; !present {
		t.Fatalf("expected top_attack_paths key to remain present, got %v", got)
	}
}

func assertMalformedCachedScoreStateRuntimeFailure(t *testing.T, payload string) {
	t.Helper()

	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(statePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run([]string{"score", "--state", statePath, "--json"}, &stdout, &stderr)
	if code != exitRuntime {
		t.Fatalf("expected runtime failure, got %d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("expected no stdout on runtime failure, got %q", stdout.String())
	}

	var errorPayload map[string]any
	if err := json.Unmarshal(stderr.Bytes(), &errorPayload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errObject, ok := errorPayload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", errorPayload)
	}
	if errObject["code"] != "runtime_failure" {
		t.Fatalf("unexpected error code: %v", errObject["code"])
	}
	if errObject["exit_code"] != float64(exitRuntime) {
		t.Fatalf("unexpected error exit code: %v", errObject["exit_code"])
	}
}
