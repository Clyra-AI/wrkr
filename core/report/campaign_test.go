package report

import (
	"strings"
	"testing"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/source"
)

func TestAggregateCampaignDeterministicMetrics(t *testing.T) {
	t.Parallel()

	one := 1
	two := 2
	inputs := []CampaignScanInput{
		{
			Path:   "b.json",
			Target: source.Target{Mode: "org", Value: "acme"},
			SourceManifest: source.Manifest{
				Repos: []source.RepoManifest{
					{Repo: "acme/backend"},
					{Repo: "acme/api"},
				},
			},
			Inventory: &agginventory.Inventory{
				Tools: []agginventory.Tool{{}, {}, {}, {}},
				ApprovalSummary: agginventory.ApprovalSummary{
					ApprovedTools:   1,
					UnapprovedTools: 3,
					UnknownTools:    0,
				},
				SecurityVisibility: agginventory.SecurityVisibilitySummary{
					ReferenceBasis:                      "state_snapshot",
					UnknownToSecurityTools:              2,
					UnknownToSecurityAgents:             3,
					UnknownToSecurityWriteCapableAgents: 1,
				},
			},
			PrivilegeBudget: agginventory.PrivilegeBudget{
				TotalTools:            4,
				WriteCapableTools:     2,
				CredentialAccessTools: 1,
				ExecCapableTools:      2,
				ProductionWrite:       agginventory.ProductionWriteBudget{Configured: true, Status: agginventory.ProductionTargetsStatusConfigured, Count: &one},
			},
			Findings: []source.Finding{
				{Detector: "codex", Repo: "acme/backend", Location: ".codex/config.toml"},
				{Detector: "mcp", Repo: "acme/backend", Location: ".mcp.json"},
			},
		},
		{
			Path:   "a.json",
			Target: source.Target{Mode: "repo", Value: "acme/frontend"},
			SourceManifest: source.Manifest{
				Repos: []source.RepoManifest{
					{Repo: "acme/frontend"},
				},
			},
			Inventory: &agginventory.Inventory{
				Tools: []agginventory.Tool{{}, {}, {}},
				ApprovalSummary: agginventory.ApprovalSummary{
					ApprovedTools:   2,
					UnapprovedTools: 0,
					UnknownTools:    1,
				},
				SecurityVisibility: agginventory.SecurityVisibilitySummary{
					ReferenceBasis:                      "state_snapshot",
					UnknownToSecurityTools:              1,
					UnknownToSecurityAgents:             2,
					UnknownToSecurityWriteCapableAgents: 1,
				},
			},
			PrivilegeBudget: agginventory.PrivilegeBudget{
				TotalTools:            3,
				WriteCapableTools:     1,
				CredentialAccessTools: 1,
				ExecCapableTools:      0,
				ProductionWrite:       agginventory.ProductionWriteBudget{Configured: true, Status: agginventory.ProductionTargetsStatusConfigured, Count: &two},
			},
			Findings: []source.Finding{
				{Detector: "codex", Repo: "acme/frontend", Location: ".codex/config.toml"},
			},
		},
	}

	out := AggregateCampaign(inputs, time.Date(2026, 2, 23, 18, 15, 0, 0, time.UTC))
	if out.SchemaVersion != SummaryVersion {
		t.Fatalf("unexpected schema version: %s", out.SchemaVersion)
	}
	if out.GeneratedAt != "2026-02-23T18:15:00Z" {
		t.Fatalf("unexpected generated_at: %s", out.GeneratedAt)
	}
	if out.Methodology.ScanCount != 2 {
		t.Fatalf("expected 2 scans, got %d", out.Methodology.ScanCount)
	}
	if out.Metrics.ReposScanned != 3 {
		t.Fatalf("expected 3 repos, got %d", out.Metrics.ReposScanned)
	}
	if out.Metrics.ToolsDetectedTotal != 7 {
		t.Fatalf("expected 7 total tools, got %d", out.Metrics.ToolsDetectedTotal)
	}
	if out.Metrics.WriteCapableTools != 3 || out.Metrics.CredentialAccessTools != 2 || out.Metrics.ExecCapableTools != 2 {
		t.Fatalf("unexpected capability totals: %+v", out.Metrics)
	}
	if out.Metrics.ApprovedTools != 3 || out.Metrics.UnapprovedTools != 3 || out.Metrics.UnknownTools != 1 {
		t.Fatalf("unexpected approval totals: %+v", out.Metrics)
	}
	if out.Metrics.UnknownToSecurityTools != 3 || out.Metrics.UnknownToSecurityAgents != 5 || out.Metrics.UnknownToSecurityWriteCapableAgents != 2 {
		t.Fatalf("unexpected visibility totals: %+v", out.Metrics)
	}
	if out.Metrics.SecurityVisibilityReference != "state_snapshot" {
		t.Fatalf("unexpected visibility reference: %+v", out.Metrics)
	}
	if out.Metrics.ApprovedPercent != 42.86 || out.Metrics.UnapprovedPercent != 42.86 || out.Metrics.UnknownPercent != 14.29 {
		t.Fatalf("unexpected approval percentages: %+v", out.Metrics)
	}
	if out.Metrics.UnapprovedPerApproved == nil || *out.Metrics.UnapprovedPerApproved != 1 {
		t.Fatalf("expected unapproved_per_approved=1, got %v", out.Metrics.UnapprovedPerApproved)
	}
	if out.Metrics.ProductionWriteTools == nil || *out.Metrics.ProductionWriteTools != 3 {
		t.Fatalf("expected production write tools=3, got %v", out.Metrics.ProductionWriteTools)
	}
	if len(out.Scans) != 2 || !strings.HasSuffix(out.Scans[0].Path, "a.json") {
		t.Fatalf("expected sorted scan paths, got %+v", out.Scans)
	}
	if len(out.Methodology.Detectors) == 0 || out.Methodology.Detectors[0].ID != "codex" {
		t.Fatalf("expected detector inventory, got %+v", out.Methodology.Detectors)
	}
	if len(out.Segments.OrgSizeBands) == 0 || len(out.Segments.IndustryBands) == 0 {
		t.Fatalf("expected non-empty segment bands, got %+v", out.Segments)
	}
}

func TestAggregateCampaignMarksProductionNotConfigured(t *testing.T) {
	t.Parallel()

	out := AggregateCampaign([]CampaignScanInput{
		{
			Path: "scan.json",
			PrivilegeBudget: agginventory.PrivilegeBudget{
				ProductionWrite: agginventory.ProductionWriteBudget{
					Configured: false,
					Status:     agginventory.ProductionTargetsStatusNotConfigured,
					Count:      nil,
				},
			},
		},
	}, time.Date(2026, 2, 23, 18, 15, 0, 0, time.UTC))

	if out.Metrics.ProductionWriteStatus != agginventory.ProductionTargetsStatusNotConfigured {
		t.Fatalf("unexpected production status: %s", out.Metrics.ProductionWriteStatus)
	}
	if out.Metrics.ProductionWriteTools != nil {
		t.Fatalf("expected null production_write_tools when not configured, got %v", out.Metrics.ProductionWriteTools)
	}
	if out.Metrics.UnapprovedPerApproved != nil {
		t.Fatalf("expected null unapproved_per_approved without approved tools, got %v", out.Metrics.UnapprovedPerApproved)
	}
}

func TestAggregateCampaignWithOptionsUsesSegmentMetadata(t *testing.T) {
	t.Parallel()

	out := AggregateCampaignWithOptions([]CampaignScanInput{
		{
			Path:   "scan.json",
			Target: source.Target{Mode: "org", Value: "acme"},
			SourceManifest: source.Manifest{
				Repos: []source.RepoManifest{
					{Repo: "acme/backend"},
				},
			},
			Inventory: &agginventory.Inventory{
				Tools: []agginventory.Tool{{ToolType: "codex"}},
			},
		},
	}, time.Date(2026, 2, 23, 18, 15, 0, 0, time.UTC), CampaignOptions{
		SegmentMetadata: map[string]SegmentMetadata{
			"acme": {
				Industry: "fintech",
				SizeBand: "large",
			},
		},
	})

	if len(out.Segments.IndustryBands) == 0 || out.Segments.IndustryBands[0].Segment != "fintech" {
		t.Fatalf("expected metadata industry segment fintech, got %+v", out.Segments.IndustryBands)
	}
	if len(out.Segments.OrgSizeBands) == 0 || out.Segments.OrgSizeBands[0].Segment != "large" {
		t.Fatalf("expected metadata size segment large, got %+v", out.Segments.OrgSizeBands)
	}
}
