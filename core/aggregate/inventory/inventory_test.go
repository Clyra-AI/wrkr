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
	if len(inv.Tools[0].Locations) != 2 {
		t.Fatalf("expected two location contexts, got %d", len(inv.Tools[0].Locations))
	}
}
