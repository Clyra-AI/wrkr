package risk

import (
	"testing"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/model"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
)

func TestScoreOrdersHeadlessHigherThanInteractive(t *testing.T) {
	t.Parallel()
	findings := []model.Finding{
		{FindingType: "ci_autonomy", Severity: model.SeverityHigh, ToolType: "ci_agent", Location: ".github/workflows/a.yml", Repo: "repo", Org: "acme", Autonomy: "interactive", Permissions: []string{"secret.read"}},
		{FindingType: "ci_autonomy", Severity: model.SeverityHigh, ToolType: "ci_agent", Location: ".github/workflows/b.yml", Repo: "repo", Org: "acme", Autonomy: "headless_auto", Permissions: []string{"secret.read"}},
	}
	report := Score(findings, 5, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC))
	if len(report.Ranked) != 2 {
		t.Fatalf("expected 2 ranked findings, got %d", len(report.Ranked))
	}
	if report.Ranked[0].AutonomyLevel != "headless_auto" {
		t.Fatalf("expected headless_auto to rank first, got %s", report.Ranked[0].AutonomyLevel)
	}
}

func TestSkillConflictCorrelation(t *testing.T) {
	t.Parallel()
	findings := []model.Finding{
		{FindingType: "policy_violation", RuleID: "WRKR-014", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-014", Repo: "repo", Org: "acme"},
		{FindingType: "skill_policy_conflict", Severity: model.SeverityHigh, ToolType: "skill", Location: ".claude/skills/deploy/SKILL.md", Repo: "repo", Org: "acme"},
	}
	report := Score(findings, 5, time.Time{})
	if len(report.Ranked) != 1 {
		t.Fatalf("expected deduped canonical conflict count 1, got %d", len(report.Ranked))
	}
}

func TestCompiledActionAmplification(t *testing.T) {
	t.Parallel()
	findings := []model.Finding{{
		FindingType: "compiled_action",
		Severity:    model.SeverityMedium,
		ToolType:    "compiled_action",
		Location:    "agent-plans/release.agent-script.json",
		Repo:        "repo",
		Org:         "acme",
		Evidence:    []model.Evidence{{Key: "tool_sequence", Value: "gait.eval.script,mcp"}},
	}}
	report := Score(findings, 5, time.Time{})
	if report.Ranked[0].Score <= 5 {
		t.Fatalf("expected amplified score, got %.2f", report.Ranked[0].Score)
	}
}

func TestGatewayCoverageAmplifiesRiskForUnprotectedDeclarations(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "webmcp_declaration",
			Severity:    model.SeverityMedium,
			ToolType:    "webmcp",
			Location:    "ui/register.js",
			Repo:        "repo",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "coverage", Value: "protected"},
				{Key: "policy_posture", Value: "deny"},
			},
		},
		{
			FindingType: "webmcp_declaration",
			Severity:    model.SeverityMedium,
			ToolType:    "webmcp",
			Location:    "ui/register2.js",
			Repo:        "repo",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "coverage", Value: "unprotected"},
				{Key: "policy_posture", Value: "allow"},
			},
		},
	}

	report := Score(findings, 5, time.Time{})
	if len(report.Ranked) != 2 {
		t.Fatalf("expected two ranked findings, got %d", len(report.Ranked))
	}
	if report.Ranked[0].Finding.Location != "ui/register2.js" {
		t.Fatalf("expected unprotected finding to rank higher, got %s", report.Ranked[0].Finding.Location)
	}
}

func TestPromptChannelCooccurrenceAmplifiesRisk(t *testing.T) {
	t.Parallel()

	baseReport := Score([]model.Finding{
		{
			FindingType: "prompt_channel_override",
			Severity:    model.SeverityHigh,
			ToolType:    "prompt_channel",
			Location:    "AGENTS.md",
			Repo:        "repo",
			Org:         "acme",
		},
	}, 5, time.Time{})

	withContext := Score([]model.Finding{
		{
			FindingType: "prompt_channel_override",
			Severity:    model.SeverityHigh,
			ToolType:    "prompt_channel",
			Location:    "AGENTS.md",
			Repo:        "repo",
			Org:         "acme",
		},
		{
			FindingType: "ci_autonomy",
			Severity:    model.SeverityHigh,
			ToolType:    "ci_agent",
			Location:    ".github/workflows/release.yml",
			Repo:        "repo",
			Org:         "acme",
			Autonomy:    "headless_auto",
		},
		{
			FindingType: "secret_presence",
			Severity:    model.SeverityHigh,
			ToolType:    "secret",
			Location:    ".env",
			Repo:        "repo",
			Org:         "acme",
		},
		{
			FindingType: "tool_config",
			Severity:    model.SeverityLow,
			ToolType:    "codex",
			Location:    ".codex/config.toml",
			Repo:        "repo",
			Org:         "acme",
			Permissions: []string{"filesystem.write"},
		},
	}, 20, time.Time{})

	basePrompt := findFindingByType(baseReport.Ranked, "prompt_channel_override")
	contextPrompt := findFindingByType(withContext.Ranked, "prompt_channel_override")
	if contextPrompt == nil || basePrompt == nil {
		t.Fatalf("expected prompt_channel_override in both reports, base=%v context=%v", basePrompt, contextPrompt)
	}
	if contextPrompt.Score <= basePrompt.Score {
		t.Fatalf("expected prompt score amplification, base=%.2f context=%.2f", basePrompt.Score, contextPrompt.Score)
	}

	reasonSet := map[string]bool{}
	for _, reason := range contextPrompt.Reasons {
		reasonSet[reason] = true
	}
	for _, required := range []string{
		"prompt_channel_with_ci_autonomy",
		"prompt_channel_with_secret_presence",
		"prompt_channel_with_production_write",
	} {
		if !reasonSet[required] {
			t.Fatalf("expected prompt amplification reason %s", required)
		}
	}
}

func findFindingByType(in []ScoredFinding, findingType string) *ScoredFinding {
	for _, item := range in {
		if item.Finding.FindingType == findingType {
			copyItem := item
			return &copyItem
		}
	}
	return nil
}

func TestMCPEnrichAdjustsTrustDeficitInEnrichModeOnly(t *testing.T) {
	t.Parallel()

	base := Score([]model.Finding{{
		FindingType: "mcp_server",
		Severity:    model.SeverityMedium,
		ToolType:    "mcp",
		Location:    ".mcp.json",
		Repo:        "repo",
		Org:         "acme",
		Evidence: []model.Evidence{
			{Key: "trust_score", Value: "5.0"},
		},
	}}, 5, time.Time{})

	enriched := Score([]model.Finding{{
		FindingType: "mcp_server",
		Severity:    model.SeverityMedium,
		ToolType:    "mcp",
		Location:    ".mcp.json",
		Repo:        "repo",
		Org:         "acme",
		Evidence: []model.Evidence{
			{Key: "trust_score", Value: "5.0"},
			{Key: "enrich_mode", Value: "true"},
			{Key: "enrich_quality", Value: "ok"},
			{Key: "advisory_count", Value: "3"},
			{Key: "registry_status", Value: "unlisted"},
		},
	}}, 5, time.Time{})

	if len(base.Ranked) != 1 || len(enriched.Ranked) != 1 {
		t.Fatalf("unexpected ranked lengths base=%d enriched=%d", len(base.Ranked), len(enriched.Ranked))
	}
	if enriched.Ranked[0].TrustDeficit <= base.Ranked[0].TrustDeficit {
		t.Fatalf("expected enriched trust deficit increase, base=%.2f enriched=%.2f", base.Ranked[0].TrustDeficit, enriched.Ranked[0].TrustDeficit)
	}
}

func TestMCPEnrichUnavailableDoesNotAlterTrustDeficit(t *testing.T) {
	t.Parallel()

	base := Score([]model.Finding{{
		FindingType: "mcp_server",
		Severity:    model.SeverityMedium,
		ToolType:    "mcp",
		Location:    ".mcp.json",
		Repo:        "repo",
		Org:         "acme",
		Evidence: []model.Evidence{
			{Key: "trust_score", Value: "5.0"},
		},
	}}, 5, time.Time{})

	unavailable := Score([]model.Finding{{
		FindingType: "mcp_server",
		Severity:    model.SeverityMedium,
		ToolType:    "mcp",
		Location:    ".mcp.json",
		Repo:        "repo",
		Org:         "acme",
		Evidence: []model.Evidence{
			{Key: "trust_score", Value: "5.0"},
			{Key: "enrich_mode", Value: "true"},
			{Key: "enrich_quality", Value: "unavailable"},
			{Key: "advisory_count", Value: "9"},
			{Key: "registry_status", Value: "unlisted"},
		},
	}}, 5, time.Time{})

	if len(base.Ranked) != 1 || len(unavailable.Ranked) != 1 {
		t.Fatalf("unexpected ranked lengths base=%d unavailable=%d", len(base.Ranked), len(unavailable.Ranked))
	}
	if unavailable.Ranked[0].TrustDeficit != base.Ranked[0].TrustDeficit {
		t.Fatalf("expected unavailable enrich to not alter trust deficit, base=%.2f unavailable=%.2f", base.Ranked[0].TrustDeficit, unavailable.Ranked[0].TrustDeficit)
	}
}

func TestBuildActionPathsRanksAndSelectsControlFirst(t *testing.T) {
	t.Parallel()

	inventory := &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                  "wrkr:alpha:acme",
				Framework:                "langchain",
				Org:                      "acme",
				Repos:                    []string{"payments"},
				Location:                 "agents/payments.py",
				RiskScore:                8.8,
				WriteCapable:             true,
				ProductionWrite:          true,
				ApprovalClassification:   "approved",
				SecurityVisibilityStatus: "approved",
			},
			{
				AgentID:                  "wrkr:beta:acme",
				Framework:                "crewai",
				Org:                      "acme",
				Repos:                    []string{"ops"},
				Location:                 "crews/ops.py",
				RiskScore:                7.4,
				WriteCapable:             true,
				ApprovalClassification:   "unknown",
				SecurityVisibilityStatus: agginventory.SecurityVisibilityUnknownToSecurity,
			},
		},
	}
	attackPaths := []riskattack.ScoredPath{
		{Org: "acme", Repo: "payments", PathScore: 9.1},
		{Org: "acme", Repo: "ops", PathScore: 6.5},
	}

	actionPaths, choice := BuildActionPaths(attackPaths, inventory)
	if len(actionPaths) != 2 {
		t.Fatalf("expected 2 action paths, got %+v", actionPaths)
	}
	if choice == nil {
		t.Fatal("expected action_path_to_control_first")
	}
	if actionPaths[0].RecommendedAction != "control" {
		t.Fatalf("expected control-ranked action path first, got %+v", actionPaths[0])
	}
	if choice.Path.RecommendedAction != "control" {
		t.Fatalf("expected control-first choice, got %+v", choice.Path)
	}
	if choice.Summary.TotalPaths != 2 || choice.Summary.WriteCapablePaths != 2 || choice.Summary.ProductionTargetBackedPaths != 1 {
		t.Fatalf("unexpected action-path summary: %+v", choice.Summary)
	}
}

func TestBuildActionPathsCarriesDeliveryChainMetadata(t *testing.T) {
	t.Parallel()

	inventory := &agginventory.Inventory{
		AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{
			{
				AgentID:                "wrkr:workflow-full:acme",
				Framework:              "compiled_action",
				Org:                    "acme",
				Repos:                  []string{"payments-prod"},
				Location:               ".github/workflows/release.yml",
				RiskScore:              8.1,
				ApprovalClassification: "approved",
				PullRequestWrite:       true,
				MergeExecute:           true,
				DeployWrite:            true,
				DeliveryChainStatus:    "pr_merge_deploy",
				ProductionTargetStatus: agginventory.ProductionTargetsStatusNotConfigured,
			},
			{
				AgentID:                "wrkr:workflow-pr:acme",
				Framework:              "compiled_action",
				Org:                    "acme",
				Repos:                  []string{"payments-prod"},
				Location:               ".github/workflows/pr.yml",
				RiskScore:              8.1,
				ApprovalClassification: "approved",
				PullRequestWrite:       true,
				DeliveryChainStatus:    "pr_only",
				ProductionTargetStatus: agginventory.ProductionTargetsStatusNotConfigured,
			},
		},
	}

	actionPaths, choice := BuildActionPaths(nil, inventory)
	if len(actionPaths) != 2 {
		t.Fatalf("expected 2 action paths, got %+v", actionPaths)
	}
	if actionPaths[0].DeliveryChainStatus != "pr_merge_deploy" {
		t.Fatalf("expected full delivery chain first, got %+v", actionPaths[0])
	}
	if !actionPaths[0].PullRequestWrite || !actionPaths[0].MergeExecute || !actionPaths[0].DeployWrite {
		t.Fatalf("expected delivery chain booleans on first path, got %+v", actionPaths[0])
	}
	if actionPaths[0].ProductionTargetStatus != agginventory.ProductionTargetsStatusNotConfigured {
		t.Fatalf("expected production target status to carry through, got %+v", actionPaths[0])
	}
	if actionPaths[0].RecommendedAction != "proof" {
		t.Fatalf("expected proof recommendation without production backing, got %+v", actionPaths[0])
	}
	if choice == nil || choice.Path.DeliveryChainStatus != "pr_merge_deploy" {
		t.Fatalf("expected control-first selection to preserve delivery metadata, got %+v", choice)
	}
}

func TestScoreKeepsSameFileAgentsDistinctByInstanceIdentity(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType:   "agent_framework",
			Severity:      model.SeverityLow,
			ToolType:      "crewai",
			Location:      "agents/crew.py",
			LocationRange: &model.LocationRange{StartLine: 4, EndLine: 9},
			Repo:          "repo",
			Org:           "acme",
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "research_agent"},
				{Key: "bound_tools", Value: "search.read"},
			},
		},
		{
			FindingType:   "agent_framework",
			Severity:      model.SeverityLow,
			ToolType:      "crewai",
			Location:      "agents/crew.py",
			LocationRange: &model.LocationRange{StartLine: 11, EndLine: 16},
			Repo:          "repo",
			Org:           "acme",
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "publisher_agent"},
				{Key: "bound_tools", Value: "deploy.write"},
			},
		},
	}

	report := Score(findings, 5, time.Time{})
	if len(report.Ranked) != 2 {
		t.Fatalf("expected two ranked findings, got %d", len(report.Ranked))
	}
	if report.Ranked[0].CanonicalKey == report.Ranked[1].CanonicalKey {
		t.Fatalf("expected distinct canonical keys for same-file agents, got %+v", report.Ranked)
	}
}

func TestRiskScore_AgentAmplificationElevatesHighBlastExposure(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{
			FindingType: "agent_framework",
			Severity:    model.SeverityMedium,
			ToolType:    "langchain",
			Location:    "agents/base.py",
			Repo:        "repo",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "approval_status", Value: "approved"},
				{Key: "deployment_status", Value: "unknown"},
				{Key: "kill_switch", Value: "true"},
			},
		},
		{
			FindingType: "agent_framework",
			Severity:    model.SeverityHigh,
			ToolType:    "langchain",
			Location:    "agents/release.py",
			Repo:        "repo",
			Org:         "acme",
			Permissions: []string{"deploy.write", "secret.read"},
			Evidence: []model.Evidence{
				{Key: "deployment_status", Value: "deployed"},
				{Key: "approval_status", Value: "missing"},
				{Key: "kill_switch", Value: "false"},
				{Key: "dynamic_discovery", Value: "true"},
				{Key: "delegation", Value: "true"},
				{Key: "auto_deploy", Value: "true"},
				{Key: "human_gate", Value: "false"},
			},
		},
	}

	report := Score(findings, 5, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC))
	if len(report.Ranked) != 2 {
		t.Fatalf("expected 2 ranked findings, got %d", len(report.Ranked))
	}
	if report.Ranked[0].Finding.Location != "agents/release.py" {
		t.Fatalf("expected amplified agent finding to rank first, got %s", report.Ranked[0].Finding.Location)
	}
	reasonSet := map[string]bool{}
	for _, reason := range report.Ranked[0].Reasons {
		reasonSet[reason] = true
	}
	for _, reason := range []string{
		"agent_deployment_scope=deployed",
		"agent_production_write",
		"agent_delegation_enabled",
		"agent_dynamic_tool_discovery",
		"agent_approval_missing",
		"agent_kill_switch_missing",
	} {
		if !reasonSet[reason] {
			t.Fatalf("expected amplified agent reason %s, got %v", reason, report.Ranked[0].Reasons)
		}
	}
}

func TestRiskReasons_DeterministicOrderingWithAgentFactors(t *testing.T) {
	t.Parallel()

	finding := model.Finding{
		FindingType: "agent_framework",
		Severity:    model.SeverityHigh,
		ToolType:    "crewai",
		Location:    "crews/release.py",
		Repo:        "repo",
		Org:         "acme",
		Permissions: []string{"deploy.write"},
		Evidence: []model.Evidence{
			{Key: "deployment_status", Value: "deployed"},
			{Key: "approval_status", Value: "missing"},
			{Key: "kill_switch", Value: "false"},
			{Key: "dynamic_discovery", Value: "true"},
			{Key: "delegation", Value: "true"},
			{Key: "auto_deploy", Value: "true"},
			{Key: "human_gate", Value: "false"},
		},
	}

	first := Score([]model.Finding{finding}, 5, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)).Ranked[0].Reasons
	for i := 0; i < 32; i++ {
		next := Score([]model.Finding{finding}, 5, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)).Ranked[0].Reasons
		if len(next) != len(first) {
			t.Fatalf("expected stable reason count, got %d vs %d", len(next), len(first))
		}
		for idx := range first {
			if first[idx] != next[idx] {
				t.Fatalf("non-deterministic reason ordering at run %d\nfirst=%v\nnext=%v", i+1, first, next)
			}
		}
	}
}
