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
	claim := findAbsenceClaim(t, report, "acme", "app", SurfaceMCPServer)
	if claim.Status != AbsenceStatusCandidateParseFailed {
		t.Fatalf("expected candidate_parse_failed absence claim, got %+v", claim)
	}
}

func TestCoverageSummaryCountsReducedSignals(t *testing.T) {
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

	if report.CompactSummary == nil {
		t.Fatalf("expected compact coverage summary, got %+v", report)
	}
	if report.CompactSummary.CoverageConfidence != CoverageConfidenceReduced {
		t.Fatalf("expected reduced compact coverage summary, got %+v", report.CompactSummary)
	}
	if report.CompactSummary.ReducedDetectorCount != 1 {
		t.Fatalf("expected one reduced detector, got %+v", report.CompactSummary)
	}
	if report.CompactSummary.ParseFailureCount != 1 {
		t.Fatalf("expected one parse failure, got %+v", report.CompactSummary)
	}
	if !strings.Contains(report.CompactSummary.ImpactStatement, "coverage") &&
		!strings.Contains(report.CompactSummary.ImpactStatement, "scoped") {
		t.Fatalf("expected buyer-safe impact statement, got %+v", report.CompactSummary)
	}
}

func TestCompletenessSignalsForRepoCollectsReducedCoverageAndUnsupportedSurfaces(t *testing.T) {
	t.Parallel()

	signals := CompletenessSignalsForRepo(&Report{
		Detectors: []DetectorHealth{{
			Org:             "acme",
			Repo:            "payments",
			Detector:        "mcp",
			Status:          "reduced",
			CoverageReasons: []string{"generated_suppression"},
		}},
		ParseErrors: []ParseIssue{{
			Org:  "acme",
			Repo: "payments",
			Kind: "parse_error",
		}},
		AbsenceClaims: []AbsenceClaim{{
			Org:     "acme",
			Repo:    "payments",
			Surface: SurfaceMCPServer,
			Status:  AbsenceStatusUnsupportedSurface,
		}},
	}, "acme", "payments")

	if !signals.ReducedCoverage {
		t.Fatalf("expected reduced coverage signals, got %+v", signals)
	}
	if len(signals.ReducedDetectors) != 1 || signals.ReducedDetectors[0] != "mcp" {
		t.Fatalf("expected reduced detector signal, got %+v", signals)
	}
	if len(signals.UnsupportedSurfaces) != 1 || signals.UnsupportedSurfaces[0] != SurfaceMCPServer {
		t.Fatalf("expected unsupported surface signal, got %+v", signals)
	}
}

func TestScanQualitySkipsGeneratedDependencyDirectoriesInGovernanceMode(t *testing.T) {
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
	})

	dependency := findDetectorHealth(t, report, "dependency")
	if dependency.AttemptedFiles != 0 {
		t.Fatalf("expected generated dependency manifests to stay out of governance attempts, got %+v", dependency)
	}
	if dependency.SuppressedFiles == 0 {
		t.Fatalf("expected generated directory suppression, got %+v", dependency)
	}
	if dependency.SkippedFiles != 0 {
		t.Fatalf("expected no skipped files from generated directory descent, got %+v", dependency)
	}
	if dependency.Status != "reduced" {
		t.Fatalf("expected reduced coverage when generated directories are suppressed, got %+v", dependency)
	}
	if !containsReason(dependency.CoverageReasons, "generated_suppression") {
		t.Fatalf("expected generated_suppression reason, got %+v", dependency)
	}
}

func TestScanQualityDeepModeIncludesGeneratedDependencyManifests(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "node_modules", "pkg"), 0o755); err != nil {
		t.Fatalf("mkdir node_modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "node_modules", "pkg", "package.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write package: %v", err)
	}

	report := Build(Input{
		Mode:   "deep",
		Scopes: []detect.Scope{{Org: "acme", Repo: "app", Root: root}},
	})

	dependency := findDetectorHealth(t, report, "dependency")
	if dependency.AttemptedFiles != 1 {
		t.Fatalf("expected deep mode to attempt generated dependency manifests, got %+v", dependency)
	}
	if dependency.SuppressedFiles != 0 {
		t.Fatalf("expected deep mode to avoid generated suppression, got %+v", dependency)
	}
	if dependency.Status != "complete" {
		t.Fatalf("expected complete coverage for deep generated manifest scan, got %+v", dependency)
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

func TestScanQualityReportsCIAgentPartialCoverageForWorkflowFallback(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitlab-ci.yml"), []byte("deploy:\n  script:\n    - codex --full-auto --approval never\n"), 0o600); err != nil {
		t.Fatalf("write gitlab pipeline: %v", err)
	}

	report := Build(Input{
		Mode:   "governance",
		Scopes: []detect.Scope{{Org: "acme", Repo: "payments", Root: root}},
		Findings: []model.Finding{
			{
				FindingType: "parse_error",
				Location:    ".gitlab-ci.yml",
				Repo:        "payments",
				Org:         "acme",
				ParseError:  &model.ParseError{Kind: "parse_error", Path: ".gitlab-ci.yml", Detector: "ciagent", Message: "unsupported remote include"},
			},
			{
				FindingType: "ci_autonomy",
				Location:    ".gitlab-ci.yml",
				Repo:        "payments",
				Org:         "acme",
				Detector:    "ciagent",
				ToolType:    "ci_agent",
				Evidence: []model.Evidence{
					{Key: "ci_platform", Value: "gitlab_ci"},
					{Key: "include_resolution_status", Value: "partial"},
				},
			},
		},
	})

	ciagent := findDetectorHealth(t, report, "ciagent")
	if ciagent.Status != "partial" {
		t.Fatalf("expected partial ciagent coverage, got %+v", ciagent)
	}
	if ciagent.PartialParses != 1 {
		t.Fatalf("expected one partial parse, got %+v", ciagent)
	}
	if !containsReason(ciagent.CoverageReasons, "partial_parse") {
		t.Fatalf("expected partial_parse reason, got %+v", ciagent)
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
	claim := findAbsenceClaim(t, report, "acme", "app", SurfaceMCPServer)
	if claim.Status != AbsenceStatusNotFoundCompleteCoverage {
		t.Fatalf("expected complete-coverage absence claim, got %+v", claim)
	}
}

func TestScanQualityMCPCandidatesMatchDetectorInputs(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir .codex: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, ".codex", "config.yml"), []byte("mcpServers: {}\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	report := Build(Input{
		Mode:   "governance",
		Scopes: []detect.Scope{{Org: "acme", Repo: "app", Root: root}},
	})

	mcp := findDetectorHealth(t, report, "mcp")
	if mcp.AttemptedFiles != 0 {
		t.Fatalf("expected MCP scan quality to ignore unsupported config.yml candidate, got %+v", mcp)
	}
	if !containsReason(mcp.CoverageReasons, "no_candidate_inputs") {
		t.Fatalf("expected clean negative MCP coverage for ignored config.yml, got %+v", mcp)
	}
}

func TestScanQualityReportsUnsupportedSurfaceAbsenceClaim(t *testing.T) {
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
			ParseError:  &model.ParseError{Kind: "schema_validation_error", Path: ".mcp.json", Detector: "mcp", Message: "unsupported declaration"},
		}},
	})

	claim := findAbsenceClaim(t, report, "acme", "app", SurfaceMCPServer)
	if claim.Status != AbsenceStatusUnsupportedSurface {
		t.Fatalf("expected unsupported_surface absence claim, got %+v", claim)
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

func findAbsenceClaim(t *testing.T, report Report, org string, repo string, surface string) AbsenceClaim {
	t.Helper()
	for _, item := range report.AbsenceClaims {
		if item.Org == org && item.Repo == repo && item.Surface == surface {
			return item
		}
	}
	t.Fatalf("expected absence claim for %s/%s surface=%s in %+v", org, repo, surface, report.AbsenceClaims)
	return AbsenceClaim{}
}
