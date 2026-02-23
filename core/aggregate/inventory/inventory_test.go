package inventory

import (
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/aggregate/exposure"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/source"
)

func TestBuildDedupesAcrossReposWithLocationContext(t *testing.T) {
	t.Parallel()
	manifest := source.Manifest{Target: source.Target{Mode: "org", Value: "acme"}, Repos: []source.RepoManifest{{Repo: "acme/a", Location: t.TempDir()}, {Repo: "acme/b", Location: t.TempDir()}}}
	findings := []model.Finding{
		{FindingType: "mcp_server", ToolType: "mcp", Location: ".mcp.json", Repo: "acme/a", Org: "acme", Permissions: []string{"mcp.access"}},
		{FindingType: "mcp_server", ToolType: "mcp", Location: ".mcp.json", Repo: "acme/b", Org: "acme", Permissions: []string{"mcp.access"}},
	}
	ctx := map[string]ToolContext{
		KeyForFinding(findings[0]): {RiskScore: 8.2, EndpointClass: "network_service", DataClass: "code", AutonomyLevel: "interactive", ApprovalStatus: "missing", LifecycleState: "discovered"},
		KeyForFinding(findings[1]): {RiskScore: 7.9, EndpointClass: "network_service", DataClass: "code", AutonomyLevel: "interactive", ApprovalStatus: "missing", LifecycleState: "discovered"},
	}
	inv := Build(BuildInput{Manifest: manifest, Findings: findings, Contexts: ctx, RepoExposureSummaries: []exposure.RepoExposureSummary{}, GeneratedAt: time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)})
	if len(inv.Tools) != 1 {
		t.Fatalf("expected deduped tool count 1, got %d", len(inv.Tools))
	}
	if inv.Tools[0].DiscoveryMethod != model.DiscoveryMethodStatic {
		t.Fatalf("expected default discovery_method static, got %q", inv.Tools[0].DiscoveryMethod)
	}
	if inv.Tools[0].ToolCategory != "mcp_integration" {
		t.Fatalf("expected tool_category=mcp_integration, got %q", inv.Tools[0].ToolCategory)
	}
	if inv.Tools[0].ConfidenceScore != 0.75 {
		t.Fatalf("expected confidence_score=0.75, got %.2f", inv.Tools[0].ConfidenceScore)
	}
	if inv.Tools[0].PermissionTier != "none" || inv.Tools[0].RiskTier != "high" {
		t.Fatalf("unexpected permission/risk tiers: permission=%q risk=%q", inv.Tools[0].PermissionTier, inv.Tools[0].RiskTier)
	}
	if inv.Tools[0].AdoptionPattern != "team_level" {
		t.Fatalf("expected adoption_pattern=team_level, got %q", inv.Tools[0].AdoptionPattern)
	}
	if len(inv.Tools[0].RegulatoryMapping) == 0 {
		t.Fatal("expected non-empty regulatory_mapping")
	}
	if len(inv.RegulatorySummary.ByRegulation) == 0 || len(inv.RegulatorySummary.ByControl) == 0 {
		t.Fatalf("expected non-empty regulatory summary rollups: %+v", inv.RegulatorySummary)
	}
	if len(inv.Tools[0].Locations) != 2 {
		t.Fatalf("expected two location contexts, got %d", len(inv.Tools[0].Locations))
	}
	if inv.Tools[0].ApprovalClass != "unapproved" {
		t.Fatalf("expected approval_classification=unapproved, got %q", inv.Tools[0].ApprovalClass)
	}
	if inv.Methodology.Detectors == nil {
		t.Fatal("expected methodology.detectors to be an empty array, not null")
	}
	if inv.ApprovalSummary.UnapprovedTools != 1 || inv.ApprovalSummary.ApprovedTools != 0 || inv.ApprovalSummary.UnknownTools != 0 {
		t.Fatalf("unexpected approval summary: %+v", inv.ApprovalSummary)
	}
	if inv.ApprovalSummary.UnapprovedPercent != 100 {
		t.Fatalf("expected unapproved_percent=100, got %.2f", inv.ApprovalSummary.UnapprovedPercent)
	}
	if inv.AdoptionSummary.TeamLevel != 1 || inv.AdoptionSummary.OrgWide != 0 || inv.AdoptionSummary.Individual != 0 || inv.AdoptionSummary.OneOff != 0 {
		t.Fatalf("unexpected adoption summary: %+v", inv.AdoptionSummary)
	}
}

func TestBuildApprovalSummaryRatios(t *testing.T) {
	t.Parallel()
	manifest := source.Manifest{Target: source.Target{Mode: "org", Value: "acme"}, Repos: []source.RepoManifest{{Repo: "acme/a", Location: t.TempDir()}, {Repo: "acme/b", Location: t.TempDir()}, {Repo: "acme/c", Location: t.TempDir()}}}
	findings := []model.Finding{
		{FindingType: "tool_config", ToolType: "codex", Location: ".codex/config.toml", Repo: "acme/a", Org: "acme"},
		{FindingType: "tool_config", ToolType: "codex", Location: ".codex/agent.toml", Repo: "acme/b", Org: "acme"},
		{FindingType: "tool_config", ToolType: "codex", Location: ".codex/unknown.toml", Repo: "acme/c", Org: "acme"},
	}
	ctx := map[string]ToolContext{
		KeyForFinding(findings[0]): {RiskScore: 6.2, EndpointClass: "workspace", DataClass: "code", AutonomyLevel: "interactive", ApprovalStatus: "valid", LifecycleState: "approved"},
		KeyForFinding(findings[1]): {RiskScore: 5.1, EndpointClass: "workspace", DataClass: "code", AutonomyLevel: "interactive", ApprovalStatus: "missing", LifecycleState: "under_review"},
		KeyForFinding(findings[2]): {RiskScore: 4.0, EndpointClass: "workspace", DataClass: "code", AutonomyLevel: "interactive", ApprovalStatus: "pending", LifecycleState: "queued"},
	}
	inv := Build(BuildInput{Manifest: manifest, Findings: findings, Contexts: ctx, RepoExposureSummaries: []exposure.RepoExposureSummary{}, GeneratedAt: time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)})
	if inv.ApprovalSummary.ApprovedTools != 1 || inv.ApprovalSummary.UnapprovedTools != 1 || inv.ApprovalSummary.UnknownTools != 1 {
		t.Fatalf("unexpected approval summary counts: %+v", inv.ApprovalSummary)
	}
	if inv.ApprovalSummary.ApprovedPercent != 33.33 || inv.ApprovalSummary.UnapprovedPercent != 33.33 || inv.ApprovalSummary.UnknownPercent != 33.33 {
		t.Fatalf("unexpected approval percentages: %+v", inv.ApprovalSummary)
	}
	if inv.ApprovalSummary.UnapprovedPerApprove == nil || *inv.ApprovalSummary.UnapprovedPerApprove != 1 {
		t.Fatalf("expected unapproved_per_approved=1, got %+v", inv.ApprovalSummary.UnapprovedPerApprove)
	}
}

func TestBuildMethodologyMetadataPassThrough(t *testing.T) {
	t.Parallel()
	manifest := source.Manifest{Target: source.Target{Mode: "repo", Value: "acme/a"}, Repos: []source.RepoManifest{{Repo: "acme/a", Location: t.TempDir()}}}
	findings := []model.Finding{
		{FindingType: "tool_config", ToolType: "codex", Location: ".codex/config.toml", Repo: "acme/a", Org: "acme", Detector: "codex"},
	}
	ctx := map[string]ToolContext{
		KeyForFinding(findings[0]): {RiskScore: 4.8, EndpointClass: "workspace", DataClass: "code", AutonomyLevel: "interactive", ApprovalStatus: "missing", LifecycleState: "discovered"},
	}
	inv := Build(BuildInput{
		Manifest: manifest,
		Findings: findings,
		Contexts: ctx,
		Methodology: MethodologySummary{
			WrkrVersion:         "v1.0.0",
			ScanStartedAt:       "2026-02-23T10:00:00Z",
			ScanCompletedAt:     "2026-02-23T10:00:02Z",
			ScanDurationSeconds: 2,
			RepoCount:           1,
			FileCountProcessed:  1,
			Detectors: []MethodologyDetector{
				{ID: "codex", Version: "v1", FindingCount: 1},
			},
		},
		RepoExposureSummaries: []exposure.RepoExposureSummary{},
		GeneratedAt:           time.Date(2026, 2, 23, 10, 0, 2, 0, time.UTC),
	})
	if inv.Methodology.WrkrVersion != "v1.0.0" {
		t.Fatalf("expected wrkr_version=v1.0.0, got %q", inv.Methodology.WrkrVersion)
	}
	if inv.Methodology.FileCountProcessed != 1 || len(inv.Methodology.Detectors) != 1 {
		t.Fatalf("unexpected methodology payload: %+v", inv.Methodology)
	}
	if len(inv.Tools) != 1 || inv.Tools[0].ToolCategory != "assistant" || inv.Tools[0].ConfidenceScore != 0.9 {
		t.Fatalf("unexpected tool taxonomy/confidence payload: %+v", inv.Tools)
	}
	if inv.Tools[0].PermissionTier != "none" || inv.Tools[0].RiskTier != "low" {
		t.Fatalf("unexpected permission/risk tiers: %+v", inv.Tools[0])
	}
}

func TestReclassifyApprovalWithMatcherOverridesSummary(t *testing.T) {
	t.Parallel()

	inv := Inventory{
		Tools: []Tool{
			{
				ToolID:         "wrkr:codex:.codex/config.toml",
				AgentID:        "wrkr:wrkr:codex:.codex/config.toml:acme",
				ToolType:       "codex",
				Org:            "acme",
				Repos:          []string{"acme/backend"},
				PermissionTier: "read",
				AutonomyLevel:  "interactive",
				RiskScore:      6.3,
			},
			{
				ToolID:         "wrkr:mcp:.mcp.json",
				AgentID:        "wrkr:wrkr:mcp:.mcp.json:acme",
				ToolType:       "mcp",
				Org:            "acme",
				Repos:          []string{"acme/backend"},
				PermissionTier: "write",
				AutonomyLevel:  "headless_auto",
				RiskScore:      9.1,
			},
		},
	}

	ReclassifyApprovalWithMatcher(&inv, func(tool Tool) bool {
		return tool.ToolType == "codex"
	})

	if inv.Tools[0].ApprovalClass != "approved" || inv.Tools[0].ApprovalStatus != "approved_list" {
		t.Fatalf("expected first tool approved via list, got %+v", inv.Tools[0])
	}
	if inv.Tools[1].ApprovalClass != "unapproved" {
		t.Fatalf("expected second tool unapproved, got %+v", inv.Tools[1])
	}
	if inv.ApprovalSummary.ApprovedTools != 1 || inv.ApprovalSummary.UnapprovedTools != 1 {
		t.Fatalf("unexpected approval summary after reclassify: %+v", inv.ApprovalSummary)
	}
	if len(inv.RegulatorySummary.ByRegulation) == 0 {
		t.Fatalf("expected regulatory summary rollups after reclassify: %+v", inv.RegulatorySummary)
	}
}
