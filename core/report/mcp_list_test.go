package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
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
