package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/config"
	githubpr "github.com/Clyra-AI/wrkr/core/github/pr"
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

func TestFixOpenPRWritesRemediationArtifacts(t *testing.T) {
	tmp := t.TempDir()
	statePath := writeFixStateFixture(t)
	configPath := filepath.Join(tmp, "config.json")

	cfg := config.Default()
	cfg.DefaultTarget = config.Target{Mode: config.TargetRepo, Value: "acme/backend"}
	cfg.Auth.Scan.Token = "scan-read-token"
	cfg.Auth.Fix.Token = "fix-write-token"
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	stub := &stubPRAPI{}
	previousClient := newGitHubPRClient
	newGitHubPRClient = func(_, _ string) githubpr.API { return stub }
	t.Cleanup(func() { newGitHubPRClient = previousClient })

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"fix", "--state", statePath, "--config", configPath, "--open-pr", "--repo", "acme/backend", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected success, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("expected empty stderr, got %q", errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	artifacts, ok := payload["remediation_artifacts"].(map[string]any)
	if !ok {
		t.Fatalf("expected remediation_artifacts, got %v", payload)
	}
	if got := int(artifacts["changed_count"].(float64)); got <= 0 {
		t.Fatalf("expected changed_count > 0, got %d", got)
	}
	if got := stub.ensureFileCalls; got <= 0 {
		t.Fatalf("expected EnsureFileContent calls, got %d", got)
	}
	if _, ok := payload["pull_request"].(map[string]any); !ok {
		t.Fatalf("expected pull_request payload, got %v", payload["pull_request"])
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

type stubPRAPI struct {
	ensureFileCalls int
}

func (s *stubPRAPI) EnsureHeadRef(context.Context, string, string, string, string) error {
	return nil
}

func (s *stubPRAPI) EnsureFileContent(context.Context, string, string, string, string, string, []byte) (bool, error) {
	s.ensureFileCalls++
	return true, nil
}

func (s *stubPRAPI) ListOpenByHead(context.Context, string, string, string, string) ([]githubpr.PullRequest, error) {
	return nil, nil
}

func (s *stubPRAPI) Create(context.Context, string, string, githubpr.CreateRequest) (githubpr.PullRequest, error) {
	return githubpr.PullRequest{
		Number: 11,
		URL:    "https://example.test/pr/11",
		Title:  "wrkr remediation",
		Body:   "body",
		Head:   "wrkr-bot/remediation/acme-backend/adhoc/abc",
		Base:   "main",
	}, nil
}

func (s *stubPRAPI) Update(context.Context, string, string, int, githubpr.UpdateRequest) (githubpr.PullRequest, error) {
	return githubpr.PullRequest{}, nil
}
