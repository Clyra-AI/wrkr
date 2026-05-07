package scanquality

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestBuildScanQualityReportsGeneratedSuppressionAndParseErrors(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "pkg"), 0o755); err != nil {
		t.Fatalf("mkdir node_modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "pkg", "package.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write package: %v", err)
	}

	report := Build(Input{
		Mode:   "governance",
		Scopes: []detect.Scope{{Org: "acme", Repo: "app", Root: root}},
		Findings: []model.Finding{{
			FindingType: "parse_error",
			Location:    "node_modules/pkg/package.json",
			Repo:        "app",
			Org:         "acme",
			ParseError:  &model.ParseError{Kind: "parse_error", Path: "node_modules/pkg/package.json", Detector: "dependency", Message: "broken"},
		}},
	})
	if report.ScanQualityVersion != ReportVersion {
		t.Fatalf("unexpected version: %s", report.ScanQualityVersion)
	}
	if len(report.SuppressedPaths) == 0 {
		t.Fatalf("expected suppressed generated/package path, got %+v", report)
	}
	if len(report.ParseErrors) != 1 || report.ParseErrors[0].Reason != "generated_or_package_noise" {
		t.Fatalf("expected generated parse issue, got %+v", report.ParseErrors)
	}
	if report.ParseErrors[0].RecommendedAction != "suppress" {
		t.Fatalf("expected suppress action for generated parse issue, got %+v", report.ParseErrors[0])
	}
}

func TestDeepModeDoesNotReportSuppressedPathSet(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "dist"), 0o755); err != nil {
		t.Fatalf("mkdir dist: %v", err)
	}
	report := Build(Input{
		Mode:   "deep",
		Scopes: []detect.Scope{{Repo: "app", Root: root}},
	})
	if report.Mode != "deep" {
		t.Fatalf("expected deep mode, got %s", report.Mode)
	}
	if len(report.SuppressedPaths) != 0 {
		t.Fatalf("deep mode should not report generated suppression as active, got %+v", report.SuppressedPaths)
	}
}

func TestScanQualityReportsReducedCoverageForParseFailures(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), []byte("{"), 0o600); err != nil {
		t.Fatalf("write mcp config: %v", err)
	}

	report := Build(Input{
		Mode:   "governance",
		Scopes: []detect.Scope{{Org: "acme", Repo: "app", Root: root}},
		Findings: []model.Finding{{
			FindingType: "parse_error",
			Location:    ".mcp.json",
			Repo:        "app",
			Org:         "acme",
			ParseError:  &model.ParseError{Kind: "parse_error", Path: ".mcp.json", Detector: "mcp", Message: "broken"},
		}},
	})

	mcp := findDetectorHealth(t, report, "mcp")
	if mcp.Status != "reduced" {
		t.Fatalf("expected reduced mcp coverage, got %+v", mcp)
	}
	if mcp.ParseFailures != 1 {
		t.Fatalf("expected one parse failure, got %+v", mcp)
	}
	if !containsReason(mcp.CoverageReasons, "parse_failures") {
		t.Fatalf("expected parse_failures reason, got %+v", mcp)
	}
}

func TestScanQualityReportsPartialCoverageWhenFallbackKeepsPositiveSignal(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "ui"), 0o755); err != nil {
		t.Fatalf("mkdir ui: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "ui", "register.mjs"), []byte("const registration = await navigator.modelContext.registerTool(\"classify\", {})"), 0o600); err != nil {
		t.Fatalf("write webmcp file: %v", err)
	}

	report := Build(Input{
		Mode:   "governance",
		Scopes: []detect.Scope{{Org: "acme", Repo: "app", Root: root}},
		Findings: []model.Finding{
			{
				FindingType: "parse_error",
				Location:    "ui/register.mjs",
				Repo:        "app",
				Org:         "acme",
				ParseError:  &model.ParseError{Kind: "parse_error", Path: "ui/register.mjs", Detector: "webmcp", Message: "top-level await"},
			},
			{
				FindingType: "webmcp_declaration",
				Location:    "ui/register.mjs",
				Repo:        "app",
				Org:         "acme",
				Detector:    "webmcp",
			},
		},
	})

	webmcp := findDetectorHealth(t, report, "webmcp")
	if webmcp.Status != "partial" {
		t.Fatalf("expected partial webmcp coverage, got %+v", webmcp)
	}
	if webmcp.PartialParses != 1 {
		t.Fatalf("expected one partial parse, got %+v", webmcp)
	}
	if !containsReason(webmcp.CoverageReasons, "partial_parse") {
		t.Fatalf("expected partial_parse reason, got %+v", webmcp)
	}
}

func TestScanQualityReportsCompleteMCPCoverageForCleanNegativeResult(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	report := Build(Input{
		Mode:   "governance",
		Scopes: []detect.Scope{{Org: "acme", Repo: "app", Root: root}},
	})

	mcp := findDetectorHealth(t, report, "mcp")
	if mcp.Status != "complete" {
		t.Fatalf("expected complete clean-negative mcp coverage, got %+v", mcp)
	}
	if !containsReason(mcp.CoverageReasons, "no_candidate_inputs") {
		t.Fatalf("expected no_candidate_inputs reason, got %+v", mcp)
	}
}

func findDetectorHealth(t *testing.T, report Report, detector string) DetectorHealth {
	t.Helper()
	for _, item := range report.Detectors {
		if strings.TrimSpace(item.Detector) == detector {
			return item
		}
	}
	t.Fatalf("expected detector %s in %+v", detector, report.Detectors)
	return DetectorHealth{}
}

func containsReason(reasons []string, want string) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}
