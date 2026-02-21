package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestFixJSONTopThreeDeterministic(t *testing.T) {
	t.Parallel()

	statePath := writeFixStateFixture(t)

	var outA bytes.Buffer
	var errA bytes.Buffer
	code := Run([]string{"fix", "--state", statePath, "--top", "3", "--json"}, &outA, &errA)
	if code != 0 {
		t.Fatalf("fix run A failed: %d stderr=%q", code, errA.String())
	}
	if errA.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", errA.String())
	}

	var outB bytes.Buffer
	var errB bytes.Buffer
	code = Run([]string{"fix", "--state", statePath, "--top", "3", "--json"}, &outB, &errB)
	if code != 0 {
		t.Fatalf("fix run B failed: %d stderr=%q", code, errB.String())
	}
	if outA.String() != outB.String() {
		t.Fatalf("expected deterministic output\nA=%s\nB=%s", outA.String(), outB.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(outA.Bytes(), &payload); err != nil {
		t.Fatalf("parse fix payload: %v", err)
	}
	if payload["remediation_count"] != float64(3) {
		t.Fatalf("expected remediation_count=3, got %v", payload["remediation_count"])
	}
}

func TestFixOpenPRFailsClosedWithScanOnlyToken(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := writeFixStateFixture(t)
	configPath := filepath.Join(tmp, "config.json")

	cfg := config.Default()
	cfg.DefaultTarget = config.Target{Mode: config.TargetRepo, Value: "acme/backend"}
	cfg.Auth.Scan.Token = "scan-only-token"
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"fix", "--state", statePath, "--config", configPath, "--open-pr", "--repo", "acme/backend", "--json"}, &out, &errOut)
	if code != 4 {
		t.Fatalf("expected exit 4, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errorObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error payload, got %v", payload)
	}
	if errorObj["code"] != "approval_required" {
		t.Fatalf("expected approval_required code, got %v", errorObj["code"])
	}
}

func writeFixStateFixture(t *testing.T) string {
	t.Helper()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")

	snapshot := state.Snapshot{
		Version: state.SnapshotVersion,
		Target:  source.Target{Mode: "repo", Value: "acme/backend"},
		Findings: []model.Finding{
			{FindingType: "policy_violation", RuleID: "WRKR-004", Severity: model.SeverityHigh, ToolType: "ci", Location: ".github/workflows/pr.yml", Repo: "backend", Org: "acme"},
			{FindingType: "skill_policy_conflict", Severity: model.SeverityHigh, ToolType: "skill", Location: ".agents/skills/release/SKILL.md", Repo: "backend", Org: "acme"},
			{FindingType: "mcp_server", Severity: model.SeverityMedium, ToolType: "mcp", Location: ".codex/config.toml", Repo: "backend", Org: "acme"},
		},
		RiskReport: &risk.Report{
			Ranked: []risk.ScoredFinding{
				{Score: 9.9, Finding: model.Finding{FindingType: "policy_violation", RuleID: "WRKR-004", Severity: model.SeverityHigh, ToolType: "ci", Location: ".github/workflows/pr.yml", Repo: "backend", Org: "acme"}},
				{Score: 9.4, Finding: model.Finding{FindingType: "skill_policy_conflict", Severity: model.SeverityHigh, ToolType: "skill", Location: ".agents/skills/release/SKILL.md", Repo: "backend", Org: "acme"}},
				{Score: 8.7, Finding: model.Finding{FindingType: "mcp_server", Severity: model.SeverityMedium, ToolType: "mcp", Location: ".codex/config.toml", Repo: "backend", Org: "acme"}},
				{Score: 8.0, Finding: model.Finding{FindingType: "unknown", Severity: model.SeverityLow, ToolType: "misc", Location: "README.md", Repo: "backend", Org: "acme"}},
			},
		},
	}

	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state fixture: %v", err)
	}
	return statePath
}
