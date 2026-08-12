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
	if report.CompactSummary == nil || report.CompactSummary.CoverageConfidence != CoverageConfidenceComplete {
		t.Fatalf("expected generated-only noise to remain localized without reducing global coverage, got %+v", report.CompactSummary)
	}
}

func TestScanQualityGroupsRepeatedParseIssues(t *testing.T) {
	t.Parallel()

	findings := make([]model.Finding, 0, 3)
	for range 3 {
		findings = append(findings, model.Finding{
			FindingType: "parse_error",
			Location:    ".gitmodules",
			Repo:        "platform",
			Org:         "acme",
			ParseError:  &model.ParseError{Kind: "missing_submodule", Path: ".gitmodules", Detector: "dependency", Message: "submodule checkout unavailable"},
		})
	}
	report := Build(Input{Mode: "governance", Findings: findings})
	if len(report.ParseErrors) != 1 || report.ParseErrors[0].OccurrenceCount != 3 {
		t.Fatalf("expected one grouped parse issue with three occurrences, got %+v", report.ParseErrors)
	}
	if report.CompactSummary == nil || report.CompactSummary.ParseFailureCount != 3 {
		t.Fatalf("expected occurrence-aware parse failure count, got %+v", report.CompactSummary)
	}
}

func TestGeneratedSuppressionDoesNotReduceUnrelatedRepoCompleteness(t *testing.T) {
	t.Parallel()

	report := &Report{Detectors: []DetectorHealth{{
		Org:             "acme",
		Repo:            "payments",
		Detector:        "dependency",
		Status:          "reduced",
		CoverageReasons: []string{"generated_suppression"},
		SuppressedFiles: 12,
	}}}
	compact := BuildCompactCoverageSummary(report)
	if compact.CoverageConfidence != CoverageConfidenceComplete || compact.ReducedDetectorCount != 0 {
		t.Fatalf("expected expected generated suppression to stay diagnostic, got %+v", compact)
	}
	if signals := CompletenessSignalsForRepo(report, "acme", "payments"); signals.ReducedCoverage {
		t.Fatalf("expected generated-only suppression not to reduce unrelated path coverage, got %+v", signals)
	}
}

func TestDetectorErrorOutsideBuiltinsCreatesBlockedHealth(t *testing.T) {
	t.Parallel()

	report := Build(Input{
		Mode:   "governance",
		Scopes: []detect.Scope{{Org: "acme", Repo: "platform", Root: t.TempDir()}},
		DetectorErrors: []detect.DetectorError{{
			Detector: "agentcustom",
			Org:      "acme",
			Repo:     "platform",
			Code:     "parse_failed",
			Class:    "detector",
			Message:  "custom declaration could not be parsed",
		}},
	})
	health := findDetectorHealth(t, report, "agentcustom")
	if health.Status != "blocked" || report.CompactSummary == nil || report.CompactSummary.BlockedDetectorCount != 1 {
		t.Fatalf("expected non-builtin detector failure to block its coverage surface, got health=%+v compact=%+v", health, report.CompactSummary)
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

func TestHostedPublicOnlyCoverageReducesCompactConfidence(t *testing.T) {
	t.Parallel()
	report := Report{ScanQualityVersion: ReportVersion, Mode: "governance"}
	report.HostedCoverage = BuildHostedCoverage(HostedCoverageInput{
		HostedTarget: true, OrgTarget: true, PublicOnlyOptIn: true,
		RequestedRepos: 8, CompletedRepos: 8,
	})
	compact := BuildCompactCoverageSummary(&report)
	if report.HostedCoverage == nil || report.HostedCoverage.Scope != HostedCoveragePublicOnly || report.HostedCoverage.Completeness != HostedCoverageReduced {
		t.Fatalf("unexpected hosted coverage: %+v", report.HostedCoverage)
	}
	if compact.CoverageConfidence != CoverageConfidenceReduced || !strings.Contains(compact.ImpactStatement, "organization-wide completeness") {
		t.Fatalf("public-only source coverage must qualify scan completeness: %+v", compact)
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
		SurfaceCoverage: []detect.SurfaceCoverage{{
			Surface: "webmcp", Org: "acme", Repo: "app", Detector: "webmcp",
			Discovered: 1, Selected: 1, Attempted: 1, Partial: 1,
		}},
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
	if len(signals.ReducedDetectors) != 0 {
		t.Fatalf("expected generated-only detector suppression to remain localized, got %+v", signals)
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
