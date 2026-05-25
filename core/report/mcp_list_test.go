package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestBuildMCPListUsesOverlayWhenPresent(t *testing.T) {
	t.Parallel()

	overlayPath := filepath.Join(t.TempDir(), "trust.yaml")
	if err := os.WriteFile(overlayPath, []byte("servers:\n  alpha:\n    trust_status: trusted\n"), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	payload := BuildMCPList(state.Snapshot{
		Inventory: &agginventory.Inventory{
			GeneratedAt: "2026-03-09T00:00:00Z",
			Tools: []agginventory.Tool{
				{
					ToolType: "mcp",
					Org:      "local",
					Locations: []agginventory.ToolLocation{
						{Repo: "local-machine", Location: ".mcp.json"},
					},
					PermissionSurface: agginventory.PermissionSurface{Read: true},
				},
			},
		},
		Findings: []source.Finding{
			{
				FindingType: "mcp_server",
				Severity:    model.SeverityMedium,
				ToolType:    "mcp",
				Location:    ".mcp.json",
				Repo:        "local-machine",
				Org:         "local",
				Evidence: []model.Evidence{
					{Key: "server", Value: "alpha"},
					{Key: "transport", Value: "stdio"},
				},
			},
		},
	}, time.Time{}, overlayPath, true)

	if len(payload.Rows) != 1 {
		t.Fatalf("expected one row, got %d", len(payload.Rows))
	}
	if payload.Rows[0].TrustStatus != MCPTrustTrusted {
		t.Fatalf("expected trusted status, got %q", payload.Rows[0].TrustStatus)
	}
}

func TestBuildMCPListCanDisableAmbientOverlayDiscovery(t *testing.T) {
	overlayPath := filepath.Join(t.TempDir(), "trust.yaml")
	if err := os.WriteFile(overlayPath, []byte("servers:\n  alpha:\n    trust_status: trusted\n"), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	t.Setenv("WRKR_GAIT_TRUST_PATH", overlayPath)

	payload := BuildMCPList(state.Snapshot{
		Inventory: &agginventory.Inventory{
			GeneratedAt: "2026-03-09T00:00:00Z",
			Tools: []agginventory.Tool{
				{
					ToolType: "mcp",
					Org:      "local",
					Locations: []agginventory.ToolLocation{
						{Repo: "local-machine", Location: ".mcp.json"},
					},
					PermissionSurface: agginventory.PermissionSurface{Read: true},
				},
			},
		},
		Findings: []source.Finding{
			{
				FindingType: "mcp_server",
				Severity:    model.SeverityMedium,
				ToolType:    "mcp",
				Location:    ".mcp.json",
				Repo:        "local-machine",
				Org:         "local",
				Evidence: []model.Evidence{
					{Key: "server", Value: "alpha"},
					{Key: "transport", Value: "stdio"},
				},
			},
		},
	}, time.Time{}, "", false)

	if len(payload.Rows) != 1 {
		t.Fatalf("expected one row, got %d", len(payload.Rows))
	}
	if payload.Rows[0].TrustStatus != MCPTrustUnavailable {
		t.Fatalf("expected ambient overlay to be ignored, got %q", payload.Rows[0].TrustStatus)
	}
	if len(payload.Warnings) != 0 {
		t.Fatalf("expected no ambient overlay warnings, got %v", payload.Warnings)
	}
}

func TestBuildMCPListWarnsWhenKnownMCPDeclarationFilesFailToParse(t *testing.T) {
	t.Parallel()

	payload := BuildMCPList(state.Snapshot{
		Findings: []source.Finding{
			{
				FindingType: "parse_error",
				ToolType:    "claude",
				Location:    ".claude/settings.json",
				Repo:        "local-machine",
				Org:         "local",
			},
			{
				FindingType: "parse_error",
				ToolType:    "codex",
				Location:    ".codex/config.toml",
				Repo:        "local-machine",
				Org:         "local",
			},
		},
	}, time.Time{}, "", false)

	if len(payload.Rows) != 0 {
		t.Fatalf("expected no MCP rows, got %d", len(payload.Rows))
	}
	if len(payload.Warnings) != 1 {
		t.Fatalf("expected one warning, got %v", payload.Warnings)
	}
	if !strings.Contains(payload.Warnings[0], ".claude/settings.json") || !strings.Contains(payload.Warnings[0], ".codex/config.toml") {
		t.Fatalf("expected warning to name suppressed MCP declaration paths, got %v", payload.Warnings)
	}
}

func TestBuildMCPListHighlightsUnprotectedAdminSurface(t *testing.T) {
	t.Parallel()

	payload := BuildMCPList(state.Snapshot{
		Findings: []source.Finding{
			{
				FindingType: "mcp_server",
				Severity:    model.SeverityHigh,
				ToolType:    "mcp",
				Location:    ".mcp.json",
				Repo:        "local-machine",
				Org:         "local",
				Permissions: []string{"mcp.access", "mcp.read", "mcp.write", "mcp.admin"},
				Evidence: []model.Evidence{
					{Key: "server", Value: "admin-surface"},
					{Key: "transport", Value: "stdio"},
					{Key: "declared_action_surface", Value: "read,write,admin"},
				},
			},
			{
				FindingType: "mcp_gateway_posture",
				ToolType:    "mcp",
				Location:    ".mcp.json",
				Repo:        "local-machine",
				Org:         "local",
				Evidence: []model.Evidence{
					{Key: "declaration_name", Value: "admin-surface"},
					{Key: "coverage", Value: "unprotected"},
				},
			},
		},
	}, time.Time{}, "", false)

	if len(payload.Rows) != 1 {
		t.Fatalf("expected one row, got %d", len(payload.Rows))
	}
	if !strings.Contains(payload.Rows[0].RiskNote, "admin-capable") || !strings.Contains(payload.Rows[0].RiskNote, "unprotected") {
		t.Fatalf("expected admin-capable unprotected risk note, got %q", payload.Rows[0].RiskNote)
	}
}

func TestBuildMCPListPrefersServerScopedDeclaredActionSurface(t *testing.T) {
	t.Parallel()

	payload := BuildMCPList(state.Snapshot{
		Inventory: &agginventory.Inventory{
			GeneratedAt: "2026-03-09T00:00:00Z",
			Tools: []agginventory.Tool{
				{
					ToolType: "mcp",
					Org:      "local",
					Locations: []agginventory.ToolLocation{
						{Repo: "local-machine", Location: ".mcp.json"},
					},
					PermissionSurface: agginventory.PermissionSurface{Read: true, Write: true, Admin: true},
				},
			},
		},
		Findings: []source.Finding{
			{
				FindingType: "mcp_server",
				Severity:    model.SeverityMedium,
				ToolType:    "mcp",
				Location:    ".mcp.json",
				Repo:        "local-machine",
				Org:         "local",
				Evidence: []model.Evidence{
					{Key: "server", Value: "read-only"},
					{Key: "transport", Value: "stdio"},
					{Key: "declared_action_surface", Value: "read"},
				},
			},
		},
	}, time.Time{}, "", false)

	if len(payload.Rows) != 1 {
		t.Fatalf("expected one row, got %d", len(payload.Rows))
	}
	if got := payload.Rows[0].PrivilegeSurface; len(got) != 1 || got[0] != "read" {
		t.Fatalf("expected server-scoped privilege surface [read], got %v", got)
	}
	if strings.Contains(payload.Rows[0].RiskNote, "admin-capable") {
		t.Fatalf("expected row risk note to avoid unioned admin surface, got %q", payload.Rows[0].RiskNote)
	}
}

func TestBuildMCPListExplainsMissedExpectedServer(t *testing.T) {
	t.Parallel()

	payload := BuildMCPListWithOptions(state.Snapshot{
		ScanQuality: &scanquality.Report{
			ScanQualityVersion: scanquality.ReportVersion,
			Mode:               "governance",
			SuppressedPaths: []scanquality.SuppressedPath{
				{Org: "acme", Repo: "acme/payments", Path: "node_modules/mcp/generated.js", Kind: "file", Reason: "generated_or_package_noise"},
			},
		},
		Findings: []source.Finding{
			{
				FindingType: "mcp_server_candidate",
				ToolType:    "mcp",
				Location:    "package.json",
				Repo:        "acme/payments",
				Org:         "acme",
				Evidence: []model.Evidence{
					{Key: "candidate_name", Value: "payments-mcp"},
					{Key: "evidence_type", Value: "package_script"},
					{Key: "confidence", Value: "medium"},
					{Key: "declaration_type", Value: "script_command"},
					{Key: "transport_hint", Value: "stdio"},
				},
			},
			{
				FindingType: "parse_error",
				ToolType:    "dependency",
				Location:    "package.json",
				Repo:        "acme/payments",
				Org:         "acme",
			},
		},
	}, MCPListOptions{
		RepoFilter:      "acme/payments",
		ExpectedServers: []string{"payments-mcp"},
	})

	if payload.RepoFilter != "acme/payments" {
		t.Fatalf("expected repo filter to round-trip, got %q", payload.RepoFilter)
	}
	if len(payload.Candidates) != 1 {
		t.Fatalf("expected one candidate, got %+v", payload.Candidates)
	}
	if len(payload.Diagnostics) != 1 {
		t.Fatalf("expected one diagnostic, got %+v", payload.Diagnostics)
	}
	if payload.Diagnostics[0].Status != "candidate_only" {
		t.Fatalf("expected candidate_only diagnostic, got %+v", payload.Diagnostics[0])
	}
	if !containsString(payload.Diagnostics[0].CandidatesFound, "payments-mcp") {
		t.Fatalf("expected candidate evidence in diagnostic, got %+v", payload.Diagnostics[0])
	}
}

func TestBuildMCPListEmitsNotDetectedDiagnosticWhenExpectedServerHasNoSignals(t *testing.T) {
	t.Parallel()

	payload := BuildMCPListWithOptions(state.Snapshot{}, MCPListOptions{
		RepoFilter:      "acme/payments",
		ExpectedServers: []string{"payments-mcp"},
	})

	if len(payload.Diagnostics) != 1 {
		t.Fatalf("expected one diagnostic, got %+v", payload.Diagnostics)
	}
	if payload.Diagnostics[0].Org != "acme" || payload.Diagnostics[0].Repo != "acme/payments" {
		t.Fatalf("expected diagnostic to preserve repo scope, got %+v", payload.Diagnostics[0])
	}
	if payload.Diagnostics[0].Status != "not_detected" {
		t.Fatalf("expected not_detected diagnostic, got %+v", payload.Diagnostics[0])
	}
	if payload.Diagnostics[0].ExpectedServer != "payments-mcp" {
		t.Fatalf("expected expected_server to round-trip, got %+v", payload.Diagnostics[0])
	}
}

func TestBuildMCPListIgnoresUnrelatedDependencyParseErrorsInDiagnostics(t *testing.T) {
	t.Parallel()

	payload := BuildMCPListWithOptions(state.Snapshot{
		Findings: []source.Finding{
			{
				FindingType: "parse_error",
				ToolType:    "dependency",
				Detector:    "dependency",
				Location:    "requirements.txt",
				Repo:        "acme/payments",
				Org:         "acme",
			},
		},
	}, MCPListOptions{
		RepoFilter:      "acme/payments",
		ExpectedServers: []string{"payments-mcp"},
	})

	if len(payload.Diagnostics) != 1 {
		t.Fatalf("expected one diagnostic, got %+v", payload.Diagnostics)
	}
	if payload.Diagnostics[0].Status != "not_detected" {
		t.Fatalf("expected unrelated dependency parse error to stay not_detected, got %+v", payload.Diagnostics[0])
	}
	if len(payload.Diagnostics[0].ParseFailures) != 0 {
		t.Fatalf("expected unrelated dependency parse error to be excluded, got %+v", payload.Diagnostics[0])
	}
}

func TestBuildMCPListKeepsMCPParseErrorsAsReducedCoverage(t *testing.T) {
	t.Parallel()

	payload := BuildMCPListWithOptions(state.Snapshot{
		Findings: []source.Finding{
			{
				FindingType: "parse_error",
				ToolType:    "mcp",
				Detector:    "mcp",
				Location:    ".mcp.json",
				Repo:        "acme/payments",
				Org:         "acme",
			},
		},
	}, MCPListOptions{
		RepoFilter:      "acme/payments",
		ExpectedServers: []string{"payments-mcp"},
	})

	if len(payload.Diagnostics) != 1 {
		t.Fatalf("expected one diagnostic, got %+v", payload.Diagnostics)
	}
	if payload.Diagnostics[0].Status != "reduced_coverage" {
		t.Fatalf("expected MCP parse error to reduce coverage, got %+v", payload.Diagnostics[0])
	}
	if !containsString(payload.Diagnostics[0].ParseFailures, ".mcp.json") {
		t.Fatalf("expected MCP parse failure to be preserved, got %+v", payload.Diagnostics[0])
	}
}

func TestBuildMCPListCarriesCompleteCoverageAbsenceStatus(t *testing.T) {
	t.Parallel()

	payload := BuildMCPListWithOptions(state.Snapshot{
		ScanQuality: &scanquality.Report{
			ScanQualityVersion: scanquality.ReportVersion,
			Mode:               "governance",
			AbsenceClaims: []scanquality.AbsenceClaim{{
				Org:     "acme",
				Repo:    "acme/payments",
				Surface: scanquality.SurfaceMCPServer,
				Status:  scanquality.AbsenceStatusNotFoundCompleteCoverage,
				Reasons: []string{"detector:mcp=complete", "mcp:no_candidate_inputs"},
				Impact:  "Complete MCP coverage supported a clean negative result for the scanned surfaces.",
			}},
		},
	}, MCPListOptions{
		RepoFilter: "acme/payments",
	})

	if payload.AbsenceStatus != scanquality.AbsenceStatusNotFoundCompleteCoverage {
		t.Fatalf("expected complete-coverage absence status, got %+v", payload)
	}
	if !containsString(payload.AbsenceReasons, "detector:mcp=complete") {
		t.Fatalf("expected absence reasons to round-trip, got %+v", payload.AbsenceReasons)
	}
	if payload.AbsenceImpact == "" {
		t.Fatalf("expected absence impact, got %+v", payload)
	}
}

func TestBuildMCPListFallsBackToReducedCoverageWhenOnlyCandidatesExist(t *testing.T) {
	t.Parallel()

	payload := BuildMCPListWithOptions(state.Snapshot{
		Findings: []source.Finding{
			{
				FindingType: "mcp_server_candidate",
				ToolType:    "mcp",
				Location:    "package.json",
				Repo:        "acme/payments",
				Org:         "acme",
				Evidence: []model.Evidence{
					{Key: "candidate_name", Value: "payments-mcp"},
				},
			},
		},
	}, MCPListOptions{
		RepoFilter: "acme/payments",
	})

	if payload.AbsenceStatus != scanquality.AbsenceStatusNotFoundReducedCoverage {
		t.Fatalf("expected reduced-coverage fallback, got %+v", payload)
	}
	if !containsString(payload.AbsenceReasons, "candidate_evidence:present") {
		t.Fatalf("expected candidate evidence reason, got %+v", payload.AbsenceReasons)
	}
}
