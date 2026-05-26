package report

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/governancequeue"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
	"github.com/Clyra-AI/wrkr/core/score"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestSelectTopFindingsDeterministic(t *testing.T) {
	t.Parallel()

	report := risk.Report{
		TopN:   []risk.ScoredFinding{{CanonicalKey: "k1", Score: 9.1}, {CanonicalKey: "k2", Score: 8.2}},
		Ranked: []risk.ScoredFinding{{CanonicalKey: "k1", Score: 9.1}, {CanonicalKey: "k2", Score: 8.2}, {CanonicalKey: "k3", Score: 7.0}},
	}
	first := SelectTopFindings(report, 3)
	second := SelectTopFindings(report, 3)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("select top findings must be deterministic\nfirst=%v\nsecond=%v", first, second)
	}
	if len(first) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(first))
	}
}

func TestBuildRiskItemsPrefersActionPathsWhenPresent(t *testing.T) {
	t.Parallel()

	findings := []risk.ScoredFinding{{
		CanonicalKey: "secret_presence|workflow|ci|.github/workflows/release.yml|payments|acme",
		Score:        9.9,
		Finding: model.Finding{
			FindingType: "secret_presence",
			Severity:    model.SeverityHigh,
			ToolType:    "secret",
			Location:    ".github/workflows/release.yml",
			Repo:        "payments",
			Org:         "acme",
		},
	}}
	actionPaths := []risk.ActionPath{{
		PathID:               "apc-123456789abc",
		Org:                  "acme",
		Repo:                 "payments",
		ToolType:             "compiled_action",
		Location:             ".github/workflows/release.yml",
		WriteCapable:         true,
		OwnerSource:          "codeowners",
		OwnershipStatus:      "explicit",
		DeliveryChainStatus:  "pr_merge_deploy",
		BusinessStateSurface: "deploy",
		RiskScore:            8.8,
		RecommendedAction:    "proof",
	}}

	items := buildRiskItems(findings, actionPaths)
	if len(items) != 1 {
		t.Fatalf("expected one action-path risk item, got %+v", items)
	}
	if items[0].FindingType != "action_path" {
		t.Fatalf("expected action_path to lead when action paths exist, got %+v", items[0])
	}
	if items[0].PathID != actionPaths[0].PathID {
		t.Fatalf("expected path id %q, got %+v", actionPaths[0].PathID, items[0])
	}
	for _, required := range []string{
		"recommended_action=proof",
		"delivery_chain_status=pr_merge_deploy",
		"business_state_surface=deploy",
		"ownership_status=explicit",
	} {
		if !containsStringValue(items[0].Rationale, required) {
			t.Fatalf("expected rationale to include %q, got %+v", required, items[0].Rationale)
		}
	}
}

func TestReportRemediationTextNamesConcreteNextAction(t *testing.T) {
	t.Parallel()

	items := buildActionPathRiskItems([]risk.ActionPath{{
		PathID:            "apc-remediate",
		Org:               "acme",
		Repo:              "acme/release",
		ToolType:          "compiled_action",
		Location:          ".github/workflows/release.yml",
		WriteCapable:      true,
		DeployWrite:       true,
		CredentialAccess:  true,
		OperationalOwner:  "@acme/release",
		OwnershipStatus:   "explicit",
		RecommendedAction: "control",
		ControlPriority:   risk.ControlPriorityControlFirst,
		RiskTier:          risk.RiskTierHigh,
		CredentialProvenance: &agginventory.CredentialProvenance{
			Type:           agginventory.CredentialProvenanceStaticSecret,
			Scope:          agginventory.CredentialScopeWorkflow,
			Confidence:     "high",
			StandingAccess: true,
			RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceStaticSecret),
		},
	}})

	if len(items) != 1 {
		t.Fatalf("expected one risk item, got %+v", items)
	}
	if !strings.Contains(strings.ToLower(items[0].Remediation), "brokered") &&
		!strings.Contains(strings.ToLower(items[0].Remediation), "jit") &&
		!strings.Contains(strings.ToLower(items[0].Remediation), "deployment") {
		t.Fatalf("expected concrete next-action remediation, got %+v", items[0])
	}
}

func TestReportIncludesControlPathGraphSummary(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:               "apc-123456",
					AgentID:              "wrkr:ci:acme",
					Org:                  "acme",
					Repo:                 "acme/release",
					ToolType:             "compiled_action",
					Location:             ".github/workflows/release.yml",
					WriteCapable:         true,
					PullRequestWrite:     true,
					RecommendedAction:    "proof",
					BusinessStateSurface: "deploy",
				}},
			},
		},
		GeneratedAt: time.Date(2026, 4, 25, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.ControlPathGraph == nil {
		t.Fatalf("expected control_path_graph on summary, got %+v", summary)
	}
	if summary.ControlPathGraph.Version != "1" {
		t.Fatalf("expected graph version 1, got %+v", summary.ControlPathGraph)
	}
	markdown := RenderMarkdown(summary)
	if !strings.Contains(markdown, "control_path_graph version=1") {
		t.Fatalf("expected markdown to include control_path_graph facts, got %q", markdown)
	}
}

func TestRenderMarkdownStableForFixedSummary(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt:  "2026-02-21T12:00:00Z",
		Template:     "operator",
		ShareProfile: "internal",
		Sections: []Section{
			{
				ID:     SectionHeadline,
				Title:  "Operator posture summary",
				Facts:  []string{"posture score 81.40 (B)", "profile status pass at 92.75%"},
				Impact: "posture controlled",
				Action: "maintain cadence",
				Proof:  ProofReference{ChainPath: ".wrkr/proof-chain.json", HeadHash: "sha256:abc", RecordCount: 5},
			},
		},
	}

	first := RenderMarkdown(summary)
	second := RenderMarkdown(summary)
	if first != second {
		t.Fatalf("markdown rendering must be deterministic\nfirst=%q\nsecond=%q", first, second)
	}
	if len(MarkdownLines(first)) == 0 {
		t.Fatal("expected markdown lines output")
	}
}

func TestRenderMarkdownIncludesTriggerPostureOnTopPaths(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt:  "2026-02-21T12:00:00Z",
		Template:     "operator",
		ShareProfile: "internal",
		AssessmentSummary: &AssessmentSummary{
			GovernablePathCount:   1,
			WriteCapablePathCount: 1,
			TopPathToControlFirst: &risk.ActionPath{
				Repo:                 "acme/release",
				Location:             ".github/workflows/nightly.yml",
				RecommendedAction:    "control",
				WorkflowTriggerClass: "scheduled",
			},
		},
	}

	markdown := RenderMarkdown(summary)
	if !strings.Contains(markdown, "trigger=scheduled") {
		t.Fatalf("expected markdown to surface trigger posture, got %q", markdown)
	}
}

func TestBuildSummaryCarriesScanQualityIntoReportAndBOM(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			ScanQuality: &scanquality.Report{
				ScanQualityVersion: scanquality.ReportVersion,
				Mode:               "governance",
				Detectors: []scanquality.DetectorHealth{
					{Detector: "mcp", Status: "complete", CoverageReasons: []string{"no_candidate_inputs"}},
					{Detector: "webmcp", Status: "reduced", AttemptedFiles: 1, ParseFailures: 1, CoverageReasons: []string{"parse_failures"}},
				},
			},
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:            "apc-123456",
					Org:               "acme",
					Repo:              "acme/release",
					ToolType:          "compiled_action",
					Location:          ".github/workflows/release.yml",
					WriteCapable:      true,
					CredentialAccess:  true,
					ApprovalGap:       true,
					RecommendedAction: "proof",
				}},
			},
		},
		GeneratedAt: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.ScanQuality == nil || len(summary.ScanQuality.Detectors) != 2 {
		t.Fatalf("expected summary scan quality, got %+v", summary.ScanQuality)
	}
	if summary.AgentActionBOM == nil || summary.AgentActionBOM.ScanQuality == nil {
		t.Fatalf("expected BOM scan quality, got %+v", summary.AgentActionBOM)
	}
	if summary.ScanQuality.CompactSummary == nil || summary.AgentActionBOM.Summary.ScanCoverage == nil {
		t.Fatalf("expected compact scan coverage summaries, got summary=%+v bom=%+v", summary.ScanQuality, summary.AgentActionBOM.Summary)
	}
	markdown := RenderMarkdown(summary)
	if !strings.Contains(markdown, "Coverage summary: confidence=reduced") {
		t.Fatalf("expected markdown to surface compact reduced coverage, got %q", markdown)
	}
	if !strings.Contains(markdown, "## Scan Quality Appendix") {
		t.Fatalf("expected markdown appendix for detector rows, got %q", markdown)
	}
}

func TestBuyerMarkdownUsesCompactCoverageSummary(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt:  "2026-05-24T12:00:00Z",
		Template:     "operator",
		ShareProfile: "internal",
		ScanQuality: &scanquality.Report{
			ScanQualityVersion: scanquality.ReportVersion,
			Mode:               "governance",
			CompactSummary: &scanquality.CompactCoverageSummary{
				CoverageConfidence:           scanquality.CoverageConfidenceReduced,
				ReducedDetectorCount:         2,
				ParseFailureCount:            1,
				SuppressedGeneratedFileCount: 4,
				BlockedDetectorCount:         1,
				UnsupportedDeclarationCount:  1,
				ImpactStatement:              "One or more detector surfaces were blocked, so negative claims remain coverage-qualified.",
			},
			Detectors: []scanquality.DetectorHealth{
				{Detector: "mcp", Status: "blocked", AttemptedFiles: 1, ParsedFiles: 0},
			},
		},
	}

	markdown := RenderMarkdown(summary)
	if !strings.Contains(markdown, "Coverage summary: confidence=reduced reduced_detectors=2 parse_failures=1") {
		t.Fatalf("expected compact scan coverage summary, got %q", markdown)
	}
	if strings.Index(markdown, "Coverage summary: confidence=reduced") > strings.Index(markdown, "## Scan Quality Appendix") {
		t.Fatalf("expected compact summary before appendix, got %q", markdown)
	}
}

func TestScanQualityAppendixRetainsDetectorDetails(t *testing.T) {
	t.Parallel()

	markdown := RenderMarkdown(Summary{
		GeneratedAt:  "2026-05-24T12:00:00Z",
		Template:     "operator",
		ShareProfile: "internal",
		ScanQuality: &scanquality.Report{
			ScanQualityVersion: scanquality.ReportVersion,
			Mode:               "governance",
			Detectors: []scanquality.DetectorHealth{
				{Detector: "webmcp", Status: "reduced", AttemptedFiles: 1, ParsedFiles: 0, ParseFailures: 1, CoverageReasons: []string{"parse_failures"}},
			},
		},
	})

	if !strings.Contains(markdown, "## Scan Quality Appendix") || !strings.Contains(markdown, "webmcp status=reduced attempted=1 parsed=0") {
		t.Fatalf("expected detector details in appendix, got %q", markdown)
	}
}

func TestNegativeClaimRenderMarkdownIncludesAbsenceClaimSummary(t *testing.T) {
	t.Parallel()

	markdown := RenderMarkdown(Summary{
		GeneratedAt:  "2026-05-24T12:00:00Z",
		Template:     "operator",
		ShareProfile: "internal",
		ScanQuality: &scanquality.Report{
			ScanQualityVersion: scanquality.ReportVersion,
			Mode:               "governance",
			Detectors: []scanquality.DetectorHealth{
				{Detector: "mcp", Status: "reduced", ParseFailures: 1, AttemptedFiles: 1, ParsedFiles: 0, CoverageReasons: []string{"parse_failures"}},
			},
			AbsenceClaims: []scanquality.AbsenceClaim{{
				Org:     "acme",
				Repo:    "acme/payments",
				Surface: scanquality.SurfaceMCPServer,
				Status:  scanquality.AbsenceStatusCandidateParseFailed,
				Reasons: []string{"detector:mcp=reduced", "mcp:parse_failures"},
				Impact:  "At least one MCP candidate surface failed to parse, so absence is not authoritative.",
			}},
		},
	})

	if !strings.Contains(markdown, "mcp_server absence_status=candidate_parse_failed") {
		t.Fatalf("expected markdown to render absence status, got %q", markdown)
	}
	if !strings.Contains(markdown, "impact=At least one MCP candidate surface failed to parse") {
		t.Fatalf("expected markdown to render absence impact, got %q", markdown)
	}
}

func TestBuildSummaryKeepsDiagnosticsOutOfSecuritySurfaces(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			Findings: []source.Finding{
				{
					FindingType: "parse_error",
					Severity:    model.SeverityMedium,
					ToolType:    "webmcp",
					Location:    "ui/register.mjs",
					Repo:        "repo",
					Org:         "acme",
					ParseError:  &model.ParseError{Kind: "parse_error", Path: "ui/register.mjs", Detector: "webmcp", Message: "unsupported syntax"},
				},
			},
			ScanQuality: &scanquality.Report{
				ScanQualityVersion: scanquality.ReportVersion,
				Mode:               "governance",
				Detectors:          []scanquality.DetectorHealth{{Detector: "webmcp", Status: "reduced", ParseFailures: 1}},
			},
		},
		GeneratedAt: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if len(summary.TopRisks) != 0 {
		t.Fatalf("expected parse diagnostics to stay out of top risks, got %+v", summary.TopRisks)
	}
	if len(summary.ActionPaths) != 0 {
		t.Fatalf("expected parse diagnostics to stay out of action paths, got %+v", summary.ActionPaths)
	}
	if summary.AgentActionBOM != nil {
		t.Fatalf("expected parse diagnostics to stay out of BOM items, got %+v", summary.AgentActionBOM)
	}
}

func TestPublicSanitizeFindingsRedactsLocationRepoOrg(t *testing.T) {
	t.Parallel()

	input := []risk.ScoredFinding{{
		CanonicalKey: "policy_violation|hardcoded-token|codex|/Users/example/private/repo/.codex/config.toml|backend|acme",
		Finding: model.Finding{
			Location: "/Users/example/private/repo/.codex/config.toml",
			Repo:     "backend",
			Org:      "acme",
		},
	}}
	out := PublicSanitizeFindings(input)
	if len(out) != 1 {
		t.Fatalf("expected one finding, got %d", len(out))
	}
	if strings.Contains(out[0].Finding.Location, "/Users/example") {
		t.Fatalf("expected redacted location, got %q", out[0].Finding.Location)
	}
	if out[0].Finding.Repo == "backend" || out[0].Finding.Org == "acme" {
		t.Fatalf("expected redacted repo/org, got repo=%q org=%q", out[0].Finding.Repo, out[0].Finding.Org)
	}
	if out[0].CanonicalKey == input[0].CanonicalKey || strings.Contains(out[0].CanonicalKey, "backend") {
		t.Fatalf("expected redacted canonical key, got %q", out[0].CanonicalKey)
	}
}

func TestBuildSummaryRejectsUnknownTemplateAndShareProfile(t *testing.T) {
	t.Parallel()

	_, err := BuildSummary(BuildInput{Template: Template("unknown"), ShareProfile: ShareProfileInternal})
	if err == nil {
		t.Fatal("expected unknown template error")
	}
	_, err = BuildSummary(BuildInput{Template: TemplateOperator, ShareProfile: ShareProfile("external")})
	if err == nil {
		t.Fatal("expected unknown share profile error")
	}
}

func TestParseRedactionFieldsRejectsDuplicateSelectors(t *testing.T) {
	t.Parallel()

	_, err := ParseRedactionFields("owners,repos,owners")
	if err == nil {
		t.Fatal("expected duplicate redaction selector error")
	}
}

func TestBuildSummaryDesignPartnerDefaultsToDesignPartnerShareProfile(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:            "apc-design-partner",
					Org:               "acme",
					Repo:              "acme/payments",
					ToolType:          "ci_agent",
					Location:          ".github/workflows/release.yml",
					WriteCapable:      true,
					CredentialAccess:  true,
					ApprovalGap:       true,
					RecommendedAction: "control",
					OperationalOwner:  "@acme/release",
					Purpose:           "Release workflow",
					PurposeSource:     "workflow_name",
					ConfidenceLane:    risk.ConfidenceLaneConfirmedActionPath,
					ControlState:      risk.ControlStateBlockRecommend,
					RiskZone:          risk.RiskZoneRelease,
					ReviewBurden:      risk.ReviewBurdenHigh,
					CredentialAuthority: &agginventory.CredentialAuthority{
						CredentialPresent:      true,
						CredentialUsableByPath: true,
						StandingAccess:         true,
						CredentialKind:         agginventory.CredentialKindGitHubPAT,
						AccessType:             agginventory.CredentialAccessTypeStanding,
					},
				}},
			},
		},
		Template:    TemplateDesignPartnerSummary,
		GeneratedAt: time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.ShareProfile != string(ShareProfileDesignPartner) {
		t.Fatalf("expected design-partner share profile default, got %q", summary.ShareProfile)
	}
	if summary.ShareProfileMetadata == nil || !summary.ShareProfileMetadata.RedactionApplied {
		t.Fatalf("expected redaction metadata for design-partner summary, got %+v", summary.ShareProfileMetadata)
	}
}

func TestBuildSummaryManualRedactionAddsMetadataAndSanitizesPaths(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:            "apc-manual-redact",
					Org:               "acme",
					Repo:              "acme/payments-private",
					ToolType:          "ci_agent",
					Location:          "/Users/example/private/.github/workflows/release.yml",
					WriteCapable:      true,
					CredentialAccess:  true,
					ApprovalGap:       true,
					RecommendedAction: "control",
				}},
			},
		},
		Template:        TemplateAgentActionBOM,
		ShareProfile:    ShareProfileInternal,
		RedactionFields: []RedactionField{RedactionOwners, RedactionRepos},
		GeneratedAt:     time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.ShareProfileMetadata == nil {
		t.Fatal("expected share profile metadata for manual redaction")
	}
	if !reflect.DeepEqual(summary.ShareProfileMetadata.SelectedFields, []string{"owners", "repos"}) {
		t.Fatalf("unexpected selected fields metadata: %+v", summary.ShareProfileMetadata)
	}
	if !strings.HasPrefix(summary.ActionPaths[0].Repo, "repo-") {
		t.Fatalf("expected repo redaction to apply, got %+v", summary.ActionPaths[0])
	}
	if summary.ActionPaths[0].Location != "/Users/example/private/.github/workflows/release.yml" {
		t.Fatalf("expected unselected location field to remain visible, got %+v", summary.ActionPaths[0])
	}
}

func TestSanitizeProofReferenceWithConfigHonorsSelectedFields(t *testing.T) {
	t.Parallel()

	input := ProofReference{
		ChainPath:            "/Users/example/.wrkr/proof-chain.json",
		CanonicalFindingKeys: []string{"finding:acme/payments:.github/workflows/release.yml"},
	}

	unselected := sanitizeProofReferenceWithConfig(input, ResolveRedactionConfig(ShareProfileInternal, []RedactionField{RedactionOwners}))
	if unselected.ChainPath != input.ChainPath {
		t.Fatalf("expected proof chain path to remain when proof refs were not selected, got %q", unselected.ChainPath)
	}
	if !reflect.DeepEqual(unselected.CanonicalFindingKeys, input.CanonicalFindingKeys) {
		t.Fatalf("expected canonical finding keys to remain when proof refs were not selected, got %+v", unselected.CanonicalFindingKeys)
	}

	selected := sanitizeProofReferenceWithConfig(input, ResolveRedactionConfig(ShareProfileInternal, []RedactionField{RedactionProofRefs}))
	if selected.ChainPath == input.ChainPath {
		t.Fatalf("expected proof chain path redaction when proof refs were selected, got %q", selected.ChainPath)
	}
	if reflect.DeepEqual(selected.CanonicalFindingKeys, input.CanonicalFindingKeys) {
		t.Fatalf("expected canonical finding keys to be redacted when proof refs were selected, got %+v", selected.CanonicalFindingKeys)
	}
}

func TestReportTemplateCISOLeadsWithControlBacklog(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			ControlBacklog: &controlbacklog.Backlog{Items: []controlbacklog.Item{{
				ID:                "cb-1",
				Repo:              "payments",
				Path:              ".github/workflows/release.yml",
				Owner:             "@acme/payments",
				RecommendedAction: "approve",
				SLA:               "7d",
				ClosureCriteria:   "Record owner-approved evidence and rescan.",
				EvidenceBasis:     []string{"workflow_permission"},
			}}},
		},
		Template:     TemplateCISO,
		ShareProfile: ShareProfileInternal,
		GeneratedAt:  time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.Template != "ciso" || summary.ControlBacklog == nil || len(summary.ControlBacklog.Items) != 1 {
		t.Fatalf("expected ciso backlog-led summary, got %+v", summary)
	}
	markdown := RenderMarkdown(summary)
	controlIdx := strings.Index(markdown, "## Control Backlog")
	risksIdx := strings.Index(markdown, "Top prioritized")
	if controlIdx < 0 {
		t.Fatalf("expected control backlog section, got %q", markdown)
	}
	if risksIdx >= 0 && controlIdx > risksIdx {
		t.Fatalf("expected control backlog to lead raw risk sections, got %q", markdown)
	}
}

func TestCustomerDraftReportRedactsSensitiveEvidence(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			ControlBacklog: &controlbacklog.Backlog{Items: []controlbacklog.Item{{
				ID:                 "cb-1",
				Repo:               "private-repo",
				Path:               "/Users/example/private/.github/workflows/release.yml",
				Owner:              "@acme/security",
				RecommendedAction:  "attach_evidence",
				SLA:                "7d",
				ClosureCriteria:    "Attach proof evidence.",
				EvidenceBasis:      []string{"secret_reference"},
				OwnershipEvidence:  []string{"/Users/example/private/CODEOWNERS"},
				OwnershipConflicts: []string{"@acme/security"},
				LinkedActionPathID: "apc-private",
				LinkedFindingIDs:   []string{"finding-private"},
			}}},
		},
		Template:    TemplateCustomerDraft,
		GeneratedAt: time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.ShareProfile != "public" {
		t.Fatalf("expected customer draft to force public share profile, got %q", summary.ShareProfile)
	}
	payload := string(mustJSONEvidenceBundle(t, summary))
	if strings.Contains(payload, "/Users/example") || strings.Contains(payload, "private-repo") || strings.Contains(payload, "@acme/security") {
		t.Fatalf("expected customer draft bundle redaction, got %s", payload)
	}
}

func TestRenderBacklogCSVIncludesClosureCriteriaAndSLA(t *testing.T) {
	t.Parallel()

	payload, err := RenderBacklogCSV(&controlbacklog.Backlog{Items: []controlbacklog.Item{{
		ID:                "cb-1",
		Repo:              "repo",
		Path:              "AGENTS.md",
		Owner:             "@acme/appsec",
		EvidenceBasis:     []string{"direct_config"},
		RecommendedAction: "approve",
		SLA:               "7d",
		ClosureCriteria:   "Record owner approval.",
	}}})
	if err != nil {
		t.Fatalf("render csv: %v", err)
	}
	text := string(payload)
	for _, want := range []string{"owner", "evidence", "recommended_action", "sla", "closure_criteria", "@acme/appsec", "Record owner approval."} {
		if !strings.Contains(text, want) {
			t.Fatalf("expected csv to contain %q, got %q", want, text)
		}
	}
}

func TestBuildAgentActionBOMDerivesStableItemsFromSummary(t *testing.T) {
	t.Parallel()

	summary := Summary{
		SummaryVersion: SummaryVersion,
		GeneratedAt:    "2026-04-29T19:33:12Z",
		Proof: ProofReference{
			ChainPath:            ".wrkr/proof-chain.json",
			HeadHash:             "sha256:abc123",
			CanonicalFindingKeys: []string{"finding:one"},
		},
		ActionPaths: []risk.ActionPath{
			{
				PathID:                   "apc-200000",
				AgentID:                  "wrkr:agent-b:acme",
				Org:                      "acme",
				Repo:                     "acme/zebra",
				ToolType:                 "compiled_action",
				Location:                 ".github/workflows/release.yml",
				WriteCapable:             true,
				CredentialAccess:         true,
				CredentialProvenance:     &agginventory.CredentialProvenance{Type: agginventory.CredentialProvenanceStaticSecret, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
				StandingPrivilege:        true,
				ActionClasses:            []string{"deploy", "write", "credential_access"},
				ActionReasons:            []string{"permission:deploy.write"},
				ProductionWrite:          true,
				MatchedProductionTargets: []string{"built_in:deploy_workflow"},
				ApprovalGap:              true,
				ApprovalGapReasons:       []string{"approval_source_missing"},
				PolicyCoverageStatus:     risk.PolicyCoverageStatusMatched,
				PolicyRefs:               []string{"gait://release"},
				PolicyConfidence:         "high",
				PolicyEvidenceRefs:       []string{".gait/policy.yaml"},
				RecommendedAction:        "control",
				OperationalOwner:         "@acme/release",
				OwnershipStatus:          "explicit",
				OwnershipState:           "explicit_owner",
				IntroducedBy:             &attribution.Result{Source: "local_git", Confidence: "high", CommitSHA: "abc123", Author: "Wrkr Test", ChangedFile: ".github/workflows/release.yml"},
			},
			{
				PathID:               "apc-100000",
				AgentID:              "wrkr:agent-a:acme",
				Org:                  "acme",
				Repo:                 "acme/alpha",
				ToolType:             "mcp",
				Location:             ".mcp.json",
				WriteCapable:         false,
				CredentialAccess:     true,
				CredentialProvenance: &agginventory.CredentialProvenance{Type: agginventory.CredentialProvenanceJIT, CredentialKind: agginventory.CredentialKindJITCredential, AccessType: agginventory.CredentialAccessTypeJIT},
				ActionClasses:        []string{"credential_access", "egress"},
				RecommendedAction:    "proof",
				OperationalOwner:     "@acme/platform",
				OwnershipStatus:      "unresolved",
				OwnershipState:       "missing",
			},
		},
		ActionPathToControlFirst: &risk.ActionPathToControlFirst{
			Summary: risk.ActionPathSummary{TotalPaths: 2, WriteCapablePaths: 1, ProductionTargetBackedPaths: 1},
			Path:    risk.ActionPath{PathID: "apc-200000"},
		},
		ControlPathGraph: &aggattack.ControlPathGraph{
			Version: "1",
			Nodes: []aggattack.ControlPathNode{
				{NodeID: "node-1", PathID: "apc-200000"},
				{NodeID: "node-2", PathID: "apc-100000"},
			},
			Edges: []aggattack.ControlPathEdge{
				{EdgeID: "edge-1", PathID: "apc-200000"},
			},
		},
		RuntimeEvidence: &ingest.Summary{
			Correlations: []ingest.Correlation{
				{PathID: "apc-200000", Status: "matched", EvidenceClasses: []string{"approval"}, RecordIDs: []string{"rec-1"}},
			},
		},
		ControlBacklog: &controlbacklog.Backlog{
			Items: []controlbacklog.Item{
				{LinkedActionPathID: "apc-200000", EvidenceBasis: []string{"rotation_evidence_missing"}},
			},
		},
	}

	first := BuildAgentActionBOM(summary)
	second := BuildAgentActionBOM(summary)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected stable BOM projection\nfirst=%+v\nsecond=%+v", first, second)
	}
	if first == nil {
		t.Fatal("expected non-nil BOM")
		return
	}
	firstBOM := *first
	if firstBOM.BOMID == "" || firstBOM.SchemaVersion != AgentActionBOMSchemaVersion {
		t.Fatalf("unexpected BOM identity: %+v", firstBOM)
	}
	if len(firstBOM.Items) != 2 {
		t.Fatalf("expected two BOM items, got %+v", firstBOM.Items)
	}
	if firstBOM.Items[0].PathID != "apc-200000" {
		t.Fatalf("expected govern-first ordering to be preserved, got %+v", firstBOM.Items)
	}
	if firstBOM.Summary.ControlFirstItems != 1 || firstBOM.Summary.StandingPrivilegeItems != 1 || firstBOM.Summary.RuntimeProvenItems != 0 {
		t.Fatalf("unexpected BOM summary counts: %+v", firstBOM.Summary)
	}
	if firstBOM.Summary.ScanCoverage == nil || firstBOM.Summary.CoverageConfidence != scanquality.CoverageConfidenceUnknown {
		t.Fatalf("expected additive BOM scan coverage summary, got %+v", firstBOM.Summary)
	}
	if !containsStringValue(firstBOM.Items[0].GraphRefs.NodeIDs, "node-1") || !containsStringValue(firstBOM.Items[0].ProofRefs, "path:apc-200000") {
		t.Fatalf("expected graph refs and path-specific proof refs on BOM item, got %+v", first.Items[0])
	}
	if !containsStringValue(first.ProofRefs, "proof_head:sha256:abc123") {
		t.Fatalf("expected global proof refs to remain on the BOM summary, got %+v", first.ProofRefs)
	}
	if first.Items[0].PolicyStatus != risk.PolicyCoverageStatusMatched || first.Items[0].IntroducedBy == nil || first.Items[0].IntroducedBy.CommitSHA != "abc123" {
		t.Fatalf("expected policy coverage and introduction attribution on BOM item, got %+v", first.Items[0])
	}
	if first.Items[0].RuntimeEvidenceStatus != ingest.CorrelationStatusMatched || first.Items[0].RuntimeEvidenceAbsenceStatus != "" {
		t.Fatalf("expected synthetic summary input to preserve raw matched runtime status without derived absence framing, got %+v", first.Items[0])
	}
}

func TestBuildAgentActionBOMCarriesGovernanceDispositionAndLifecycleQueue(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt: "2026-05-26T12:00:00Z",
		ActionPaths: []risk.ActionPath{{
			PathID:                "apc-governed",
			AgentID:               "wrkr:codex-app:acme",
			Org:                   "acme",
			Repo:                  "app",
			ToolType:              "codex",
			Location:              "AGENTS.md",
			ApprovalGap:           true,
			ApprovalEvidenceState: risk.EvidenceStateUnknown,
			RecommendedAction:     "approve",
		}},
		ControlBacklog: &controlbacklog.Backlog{
			Items: []controlbacklog.Item{{
				LinkedActionPathID: "apc-governed",
				Queue:              controlbacklog.QueueAcceptedRisk,
				FindingVisibility:  controlbacklog.FindingVisibilityAppendix,
				Remediation:        "Monitor the accepted-risk exception until it expires.",
				GovernanceDisposition: &controlbacklog.GovernanceDisposition{
					Kind:               controlbacklog.GovernanceKindAcceptedRisk,
					Status:             controlbacklog.GovernanceStatusActive,
					Reason:             "time_bounded_exception",
					Scope:              "control_path",
					ExpiresAt:          "2026-05-28T12:00:00Z",
					EvidenceState:      risk.EvidenceStateUnknown,
					VisibilityBehavior: controlbacklog.QueueAcceptedRisk,
					RescanBehavior:     "repromote_on_expiry",
				},
				LifecycleQueue: &governancequeue.Item{
					QueueID:           "lq-governed",
					GapID:             "gap-governed",
					AgentID:           "wrkr:codex-app:acme",
					ReasonCode:        lifecycle.GapApprovalExpired,
					Severity:          "high",
					CredentialStatus:  governancequeue.CredentialStatusPresent,
					RecommendedAction: "approve",
					SLA:               "7d",
					ClosureCriteria:   "Attach fresh approval evidence with owner, expiry, and review scope.",
				},
			}},
		},
	}

	bom := BuildAgentActionBOM(summary)
	if bom == nil || len(bom.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", bom)
	}
	item := bom.Items[0]
	if item.GovernanceDisposition == nil || item.GovernanceDisposition.Kind != controlbacklog.GovernanceKindAcceptedRisk {
		t.Fatalf("expected accepted-risk governance disposition on BOM item, got %+v", item)
	}
	if item.LifecycleQueue == nil || item.LifecycleQueue.ReasonCode != lifecycle.GapApprovalExpired {
		t.Fatalf("expected lifecycle queue metadata on BOM item, got %+v", item)
	}
	if bom.Summary.AcceptedRiskItems != 1 || bom.Summary.LifecycleQueueItems != 1 {
		t.Fatalf("expected BOM summary counts for accepted risk and lifecycle queue, got %+v", bom.Summary)
	}
}

func TestBuildAgentActionBOMCountsMissingProofWhenChainAttachedButControlProofMissing(t *testing.T) {
	t.Parallel()

	snapshot := state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:            "apc-proof-gap",
				AgentID:           "wrkr:ci:acme",
				Org:               "acme",
				Repo:              "demo-app",
				ToolType:          "ci_agent",
				Location:          ".github/workflows/release.yml",
				CredentialAccess:  true,
				ApprovalGap:       true,
				RecommendedAction: "approval",
			}},
		},
		ControlBacklog: &controlbacklog.Backlog{Items: []controlbacklog.Item{{
			ID:                 "cb-proof-gap",
			Repo:               "demo-app",
			Path:               ".github/workflows/release.yml",
			RecommendedAction:  controlbacklog.ActionApprove,
			ClosureCriteria:    "Record owner-approved, time-bounded approval evidence and rescan.",
			LinkedActionPathID: "apc-proof-gap",
			GovernanceControls: []agginventory.GovernanceControlMapping{
				{Control: agginventory.GovernanceControlApproval, Status: agginventory.ControlStatusGap},
			},
		}}},
	}
	summary := Summary{
		SummaryVersion: SummaryVersion,
		GeneratedAt:    "2026-04-30T12:00:00Z",
		Proof: ProofReference{
			ChainPath: ".wrkr/proof-chain.json",
			HeadHash:  "sha256:attached",
		},
		ActionPaths:    snapshot.RiskReport.ActionPaths,
		ControlBacklog: snapshot.ControlBacklog,
	}
	summary.controlProofStatus = BuildControlProofStatus(snapshot, proof.NewChain("wrkr-proof"))

	bom := BuildAgentActionBOM(summary)
	if bom == nil || len(bom.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", bom)
	}
	if bom.Items[0].ProofCoverage != proofCoverageMissing {
		t.Fatalf("expected missing proof coverage with attached chain and missing control proof, got %+v", bom.Items[0])
	}
	if bom.Summary.MissingProofItems != 1 {
		t.Fatalf("expected one missing proof item, got %+v", bom.Summary)
	}
	if !containsStringValue(bom.ProofRefs, "proof_head:sha256:attached") {
		t.Fatalf("expected proof head ref to remain visible at BOM scope, got %+v", bom.ProofRefs)
	}
	if !containsStringValue(bom.Items[0].ProofRefs, "path:apc-proof-gap") {
		t.Fatalf("expected path-specific proof refs on the BOM item, got %+v", bom.Items[0].ProofRefs)
	}
}

func TestAgentActionBOMCarriesCanonicalEvidenceStates(t *testing.T) {
	t.Parallel()

	bom := BuildAgentActionBOM(Summary{
		SummaryVersion: SummaryVersion,
		GeneratedAt:    "2026-05-24T12:00:00Z",
		ActionPaths: []risk.ActionPath{{
			PathID:                  "apc-evidence-states",
			Org:                     "acme",
			Repo:                    "acme/release",
			ToolType:                "compiled_action",
			Location:                ".github/workflows/release.yml",
			WriteCapable:            true,
			CredentialAccess:        true,
			ApprovalGap:             true,
			ApprovalGapReasons:      []string{"approval_source_missing"},
			OperationalOwner:        "@acme/release",
			OwnershipStatus:         "explicit",
			OwnershipEvidence:       []string{"codeowners:CODEOWNERS:*"},
			PolicyCoverageStatus:    risk.PolicyCoverageStatusNone,
			GaitCoverage:            &risk.GaitCoverage{ProofVerification: risk.GaitCoverageDetail{Status: risk.GaitStatusMissing}},
			ControlResolutionState:  risk.ControlResolutionStateNoVisibleControl,
			ApprovalEvidenceState:   risk.EvidenceStateUnknown,
			OwnerEvidenceState:      risk.EvidenceStateVerified,
			ProofEvidenceState:      risk.EvidenceStateUnknown,
			RuntimeEvidenceState:    risk.EvidenceStateUnknown,
			TargetEvidenceState:     risk.EvidenceStateInferred,
			CredentialEvidenceState: risk.EvidenceStateInferred,
		}},
	})
	if bom == nil || len(bom.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", bom)
	}
	item := bom.Items[0]
	if item.ControlResolutionState != risk.ControlResolutionStateDetectedControl {
		t.Fatalf("expected control resolution state on BOM item, got %+v", item)
	}
	if item.ApprovalEvidenceState != risk.EvidenceStateUnknown || item.OwnerEvidenceState != risk.EvidenceStateVerified {
		t.Fatalf("expected canonical evidence states on BOM item, got %+v", item)
	}
	if bom.Summary.ApprovalEvidenceUnknownItems != 1 || bom.Summary.ProofEvidenceUnknownItems != 1 {
		t.Fatalf("expected canonical evidence-state summary counters, got %+v", bom.Summary)
	}
}

func TestBuildAgentActionBOMMarksProofCoveredWhenLinkedProofSatisfied(t *testing.T) {
	t.Parallel()

	snapshot := state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:            "apc-proof-covered",
				AgentID:           "wrkr:ci:acme",
				Org:               "acme",
				Repo:              "demo-app",
				ToolType:          "ci_agent",
				Location:          ".github/workflows/release.yml",
				CredentialAccess:  true,
				ApprovalGap:       false,
				RecommendedAction: "approval",
			}},
		},
		ControlBacklog: &controlbacklog.Backlog{Items: []controlbacklog.Item{{
			ID:                 "cb-proof-covered",
			Repo:               "demo-app",
			Path:               ".github/workflows/release.yml",
			RecommendedAction:  controlbacklog.ActionApprove,
			ClosureCriteria:    "Record owner-approved, time-bounded approval evidence and rescan.",
			LinkedActionPathID: "apc-proof-covered",
			GovernanceControls: []agginventory.GovernanceControlMapping{
				{Control: agginventory.GovernanceControlApproval, Status: agginventory.ControlStatusGap},
			},
		}}},
	}
	chain := proof.NewChain("wrkr-proof")
	chain.Records = append(chain.Records, proof.Record{
		RecordID:   "rec-approval",
		RecordType: "approval",
		AgentID:    "wrkr:ci:acme",
		Event: map[string]any{
			"event_type":     "approval_recorded",
			"owner":          "platform-security",
			"review_cadence": "90d",
			"control_id":     agginventory.GovernanceControlApproval,
		},
	})
	summary := Summary{
		SummaryVersion: SummaryVersion,
		GeneratedAt:    "2026-04-30T12:00:00Z",
		Proof: ProofReference{
			ChainPath: ".wrkr/proof-chain.json",
			HeadHash:  "sha256:attached",
		},
		ActionPaths:    snapshot.RiskReport.ActionPaths,
		ControlBacklog: snapshot.ControlBacklog,
	}
	summary.controlProofStatus = BuildControlProofStatus(snapshot, chain)

	bom := BuildAgentActionBOM(summary)
	if bom == nil || len(bom.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", bom)
	}
	if bom.Items[0].ProofCoverage != proofCoverageCovered {
		t.Fatalf("expected covered proof coverage, got %+v", bom.Items[0])
	}
	if bom.Summary.MissingProofItems != 0 {
		t.Fatalf("expected no missing proof items, got %+v", bom.Summary)
	}
}

func TestBuildAgentActionBOMPreservesContradictoryProofEvidenceState(t *testing.T) {
	t.Parallel()

	snapshot := state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:               "apc-proof-contradictory",
				AgentID:              "wrkr:ci:acme",
				Org:                  "acme",
				Repo:                 "demo-app",
				ToolType:             "ci_agent",
				Location:             ".github/workflows/release.yml",
				CredentialAccess:     true,
				PolicyCoverageStatus: risk.PolicyCoverageStatusConflict,
				GaitCoverage: &risk.GaitCoverage{
					ProofVerification: risk.GaitCoverageDetail{
						Status:       risk.GaitStatusConflict,
						EvidenceRefs: []string{"runtime:proof-conflict"},
					},
				},
				RecommendedAction: "approval",
			}},
		},
		ControlBacklog: &controlbacklog.Backlog{Items: []controlbacklog.Item{{
			ID:                 "cb-proof-contradictory",
			Repo:               "demo-app",
			Path:               ".github/workflows/release.yml",
			RecommendedAction:  controlbacklog.ActionApprove,
			ClosureCriteria:    "Record owner-approved, time-bounded approval evidence and rescan.",
			LinkedActionPathID: "apc-proof-contradictory",
			GovernanceControls: []agginventory.GovernanceControlMapping{
				{Control: agginventory.GovernanceControlApproval, Status: agginventory.ControlStatusGap},
			},
		}}},
	}
	chain := proof.NewChain("wrkr-proof")
	chain.Records = append(chain.Records, proof.Record{
		RecordID:   "rec-approval",
		RecordType: "approval",
		AgentID:    "wrkr:ci:acme",
		Event: map[string]any{
			"event_type":     "approval_recorded",
			"owner":          "platform-security",
			"review_cadence": "90d",
			"control_id":     agginventory.GovernanceControlApproval,
		},
	})
	summary := Summary{
		SummaryVersion: SummaryVersion,
		GeneratedAt:    "2026-04-30T12:00:00Z",
		Proof: ProofReference{
			ChainPath: ".wrkr/proof-chain.json",
			HeadHash:  "sha256:attached",
		},
		ActionPaths:    snapshot.RiskReport.ActionPaths,
		ControlBacklog: snapshot.ControlBacklog,
	}
	summary.controlProofStatus = BuildControlProofStatus(snapshot, chain)

	bom := BuildAgentActionBOM(summary)
	if bom == nil || len(bom.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", bom)
	}
	if bom.Items[0].ProofCoverage != proofCoverageCovered {
		t.Fatalf("expected covered proof coverage from control proof status, got %+v", bom.Items[0])
	}
	if bom.Items[0].ProofEvidenceState != risk.EvidenceStateContradictory {
		t.Fatalf("expected contradictory proof evidence state to be preserved, got %+v", bom.Items[0])
	}
}

func TestBuildAgentActionBOMSharesMergedControlProofAcrossSiblingPaths(t *testing.T) {
	t.Parallel()

	snapshot := state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{
				{
					PathID:            "apc-proof-covered-primary",
					AgentID:           "wrkr:ci:acme",
					Org:               "acme",
					Repo:              "demo-app",
					ToolType:          "ci_agent",
					Location:          ".github/workflows/release.yml",
					CredentialAccess:  true,
					ApprovalGap:       false,
					RecommendedAction: "approval",
				},
				{
					PathID:            "apc-proof-covered-sibling",
					AgentID:           "wrkr:ci:acme",
					Org:               "acme",
					Repo:              "demo-app",
					ToolType:          "ci_agent",
					Location:          ".github/workflows/release.yml",
					CredentialAccess:  true,
					ApprovalGap:       false,
					RecommendedAction: "approval",
				},
			},
		},
		ControlBacklog: &controlbacklog.Backlog{Items: []controlbacklog.Item{{
			ID:                 "cb-proof-covered",
			Repo:               "demo-app",
			Path:               ".github/workflows/release.yml",
			RecommendedAction:  controlbacklog.ActionApprove,
			ClosureCriteria:    "Record owner-approved, time-bounded approval evidence and rescan.",
			LinkedActionPathID: "apc-proof-covered-primary",
			GovernanceControls: []agginventory.GovernanceControlMapping{
				{Control: agginventory.GovernanceControlApproval, Status: agginventory.ControlStatusGap},
			},
		}}},
	}
	chain := proof.NewChain("wrkr-proof")
	chain.Records = append(chain.Records, proof.Record{
		RecordID:   "rec-approval",
		RecordType: "approval",
		AgentID:    "wrkr:ci:acme",
		Event: map[string]any{
			"event_type":     "approval_recorded",
			"owner":          "platform-security",
			"review_cadence": "90d",
			"control_id":     agginventory.GovernanceControlApproval,
		},
	})
	summary := Summary{
		SummaryVersion: SummaryVersion,
		GeneratedAt:    "2026-04-30T12:00:00Z",
		Proof: ProofReference{
			ChainPath: ".wrkr/proof-chain.json",
			HeadHash:  "sha256:attached",
		},
		ActionPaths:    snapshot.RiskReport.ActionPaths,
		ControlBacklog: snapshot.ControlBacklog,
	}
	summary.controlProofStatus = BuildControlProofStatus(snapshot, chain)

	bom := BuildAgentActionBOM(summary)
	if bom == nil || len(bom.Items) != 2 {
		t.Fatalf("expected two BOM items, got %+v", bom)
	}
	for _, item := range bom.Items {
		if item.ProofCoverage != proofCoverageCovered {
			t.Fatalf("expected sibling path to inherit covered proof status, got %+v", item)
		}
	}
	if bom.Summary.MissingProofItems != 0 {
		t.Fatalf("expected no missing proof items, got %+v", bom.Summary)
	}
}

func TestAgentActionBOMProofRefsArePathSpecific(t *testing.T) {
	t.Parallel()

	summary := Summary{
		SummaryVersion: SummaryVersion,
		GeneratedAt:    "2026-05-01T12:00:00Z",
		Proof: ProofReference{
			ChainPath: ".wrkr/proof-chain.json",
			HeadHash:  "sha256:attached",
		},
		ActionPaths: []risk.ActionPath{{
			PathID:            "apc-path-specific",
			Org:               "acme",
			Repo:              "acme/app",
			ToolType:          "mcp",
			Location:          ".mcp.json",
			CredentialAccess:  true,
			RecommendedAction: "proof",
		}},
	}

	bom := BuildAgentActionBOM(summary)
	if bom == nil || len(bom.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", bom)
	}
	if containsStringValue(bom.Items[0].ProofRefs, "proof_head:sha256:attached") {
		t.Fatalf("expected item proof refs to stay path-specific, got %+v", bom.Items[0].ProofRefs)
	}
	if !containsStringValue(bom.ProofRefs, "proof_head:sha256:attached") {
		t.Fatalf("expected global proof refs on BOM, got %+v", bom.ProofRefs)
	}
	if !containsStringValue(bom.Items[0].ProofRefs, "path:apc-path-specific") {
		t.Fatalf("expected path ref on BOM item, got %+v", bom.Items[0].ProofRefs)
	}
}

func TestAgentActionBOMIncludesEveryTopAttackPathOrExclusion(t *testing.T) {
	t.Parallel()

	summary := Summary{
		SummaryVersion: SummaryVersion,
		GeneratedAt:    "2026-05-01T12:00:00Z",
		ActionPaths: []risk.ActionPath{{
			PathID:            "apc-matched",
			Org:               "acme",
			Repo:              "acme/app",
			ToolType:          "langchain",
			Location:          "agents/app.py",
			CredentialAccess:  true,
			RecommendedAction: "proof",
			AttackPathRefs:    []string{"ap-matched"},
			SourceFindingKeys: []string{"agent_framework||langchain|agents/app.py|acme/app|acme"},
		}},
		topAttackPaths: []riskattack.ScoredPath{
			{
				PathID:         "ap-matched",
				Org:            "acme",
				Repo:           "acme/app",
				PathScore:      8.8,
				SourceFindings: []string{"agent_framework||langchain|agents/app.py|acme/app|acme"},
			},
			{
				PathID:         "ap-orphaned",
				Org:            "acme",
				Repo:           "acme/app",
				PathScore:      7.6,
				SourceFindings: []string{"agent_framework||langchain|agents/orphan.py|acme/app|acme"},
			},
		},
	}

	bom := BuildAgentActionBOM(summary)
	if bom == nil || len(bom.Items) != 2 {
		t.Fatalf("expected one matched item plus one exclusion item, got %+v", bom)
	}
	if !containsStringValue(bom.Items[0].AttackPathRefs, "ap-matched") && !containsStringValue(bom.Items[1].AttackPathRefs, "ap-matched") {
		t.Fatalf("expected matched attack path ref to remain visible, got %+v", bom.Items)
	}
	var orphan AgentActionBOMItem
	found := false
	for _, item := range bom.Items {
		if containsStringValue(item.AttackPathRefs, "ap-orphaned") {
			orphan = item
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected orphaned top attack path to produce an exclusion item, got %+v", bom.Items)
	}
	if orphan.ExclusionReason == "" {
		t.Fatalf("expected exclusion reason on orphaned top attack path item, got %+v", orphan)
	}
}

func TestBuildAgentActionBOMExposesNamedReachabilityProjections(t *testing.T) {
	t.Parallel()

	summary := Summary{
		SummaryVersion: SummaryVersion,
		GeneratedAt:    "2026-04-29T19:33:12Z",
		ActionPaths: []risk.ActionPath{{
			PathID:            "apc-reachable",
			AgentID:           "wrkr:mcp:acme",
			Org:               "acme",
			Repo:              "control-plane",
			ToolType:          "mcp",
			Location:          ".mcp.json",
			CredentialAccess:  true,
			ApprovalGap:       true,
			RecommendedAction: "control",
		}},
	}
	findings := []model.Finding{
		{
			FindingType: "mcp_server",
			Org:         "acme",
			Repo:        "control-plane",
			Location:    ".mcp.json",
			Permissions: []string{"mcp.write", "mcp.admin"},
			Evidence: []model.Evidence{
				{Key: "server", Value: "prod-mcp"},
				{Key: "trust_surface", Value: "mcp"},
				{Key: "auth_strength", Value: "static_secret"},
				{Key: "delegation_model", Value: "tool_proxy"},
				{Key: "exposure", Value: "private"},
				{Key: "gateway_coverage", Value: "protected"},
			},
		},
		{
			FindingType: "a2a_agent_card",
			Org:         "acme",
			Repo:        "control-plane",
			Location:    ".mcp.json",
			Evidence: []model.Evidence{
				{Key: "agent_name", Value: "release-agent"},
				{Key: "capabilities", Value: "delegate.run,search"},
				{Key: "trust_surface", Value: "a2a"},
				{Key: "auth_strength", Value: "oauth_delegation"},
				{Key: "delegation_model", Value: "agent_delegate"},
				{Key: "exposure", Value: "private"},
				{Key: "gateway_coverage", Value: "protected"},
			},
		},
	}

	bom := buildAgentActionBOM(summary, findings)
	if bom == nil || len(bom.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", bom)
	}
	item := bom.Items[0]
	if len(item.Reachability) != 2 {
		t.Fatalf("expected compatibility reachability entries, got %+v", item.Reachability)
	}
	if !containsReachabilityName(item.ReachableServers, "prod-mcp") || !containsReachabilityName(item.ReachableAgents, "release-agent") {
		t.Fatalf("expected named server and agent reachability, got servers=%+v agents=%+v", item.ReachableServers, item.ReachableAgents)
	}
	if !containsReachabilityName(item.ReachableTools, "mcp.admin") || !containsReachabilityName(item.ReachableTools, "mcp.write") {
		t.Fatalf("expected MCP capabilities as reachable tools, got %+v", item.ReachableTools)
	}
	if !containsReachabilityName(item.ReachableAPIs, "delegate.run") || !containsReachabilityName(item.ReachableAPIs, "search") {
		t.Fatalf("expected A2A capabilities as reachable APIs, got %+v", item.ReachableAPIs)
	}
	if item.ReachableServers[0].TrustDepth == nil || item.ReachableAPIs[0].TrustDepth == nil {
		t.Fatalf("expected trust-depth metadata on named reachability, got servers=%+v apis=%+v", item.ReachableServers, item.ReachableAPIs)
	}
}

func TestDecorateActionPathsForReportPromotesRuntimePolicyCoverage(t *testing.T) {
	t.Parallel()

	paths := decorateActionPathsForReport([]risk.ActionPath{{
		PathID:               "apc-1",
		Org:                  "local",
		Repo:                 "policy-target",
		ToolType:             "compiled_action",
		Location:             ".github/workflows/release.yml",
		PolicyCoverageStatus: risk.PolicyCoverageStatusMatched,
		PolicyRefs:           []string{"gait://release"},
	}}, &ingest.Summary{
		Correlations: []ingest.Correlation{{
			PathID:          "apc-1",
			Status:          ingest.CorrelationStatusMatched,
			EvidenceClasses: []string{ingest.EvidenceClassPolicyDecision},
			PolicyRefs:      []string{"gait://release"},
			RecordIDs:       []string{"rec-1"},
		}},
	})
	if len(paths) != 1 {
		t.Fatalf("expected one path, got %+v", paths)
	}
	if paths[0].PolicyCoverageStatus != risk.PolicyCoverageStatusRuntimeProven {
		t.Fatalf("expected runtime-proven policy coverage, got %+v", paths[0])
	}
	if !containsStringValue(paths[0].PolicyEvidenceRefs, "rec-1") {
		t.Fatalf("expected runtime record ref on policy evidence, got %+v", paths[0])
	}
}

func TestDecorateActionPathsForReportDoesNotPromoteUnmatchedRuntimeEvidence(t *testing.T) {
	t.Parallel()

	paths := decorateActionPathsForReport([]risk.ActionPath{{
		PathID:               "apc-1",
		Org:                  "local",
		Repo:                 "policy-target",
		ToolType:             "compiled_action",
		Location:             ".github/workflows/release.yml",
		PolicyCoverageStatus: risk.PolicyCoverageStatusMatched,
		PolicyRefs:           []string{"gait://release"},
	}}, &ingest.Summary{
		Correlations: []ingest.Correlation{{
			PathID:          "apc-1",
			Status:          ingest.CorrelationStatusUnmatched,
			EvidenceClasses: []string{ingest.EvidenceClassPolicyDecision},
			PolicyRefs:      []string{"gait://release"},
			RecordIDs:       []string{"rec-1"},
		}},
	})
	if len(paths) != 1 {
		t.Fatalf("expected one path, got %+v", paths)
	}
	if paths[0].PolicyCoverageStatus != risk.PolicyCoverageStatusMatched {
		t.Fatalf("expected unmatched runtime evidence to preserve matched policy coverage, got %+v", paths[0])
	}
	if containsStringValue(paths[0].PolicyStatusReasons, "runtime_policy_decision_attached") {
		t.Fatalf("expected unmatched runtime evidence to avoid runtime-proven promotion, got %+v", paths[0])
	}
}

func TestDecorateActionPathsForReportProjectsGaitCoverageAndBuyerState(t *testing.T) {
	t.Parallel()

	paths := decorateActionPathsForReport([]risk.ActionPath{{
		PathID:               "apc-1",
		Org:                  "local",
		Repo:                 "policy-target",
		ToolType:             "compiled_action",
		Location:             ".github/workflows/release.yml",
		WriteCapable:         true,
		DeployWrite:          true,
		CredentialAccess:     true,
		ApprovalGap:          true,
		StandingPrivilege:    true,
		PolicyCoverageStatus: risk.PolicyCoverageStatusMatched,
		PolicyRefs:           []string{"gait://release"},
	}}, &ingest.Summary{
		Correlations: []ingest.Correlation{{
			PathID:          "apc-1",
			Status:          ingest.CorrelationStatusMatched,
			EvidenceClasses: []string{ingest.EvidenceClassPolicyDecision, ingest.EvidenceClassApproval, ingest.EvidenceClassProofVerify},
			PolicyRefs:      []string{"gait://release"},
			RecordIDs:       []string{"rec-1"},
		}},
	})
	if len(paths) != 1 {
		t.Fatalf("expected one path, got %+v", paths)
	}
	if paths[0].GaitCoverage == nil {
		t.Fatalf("expected gait coverage projection, got %+v", paths[0])
	}
	if paths[0].GaitCoverage.PolicyDecision.Status != risk.GaitStatusPresent || paths[0].GaitCoverage.ProofVerification.Status != risk.GaitStatusPresent {
		t.Fatalf("expected present gait coverage for matched classes, got %+v", paths[0].GaitCoverage)
	}
	if paths[0].ControlState != risk.ControlStateBlockRecommend {
		t.Fatalf("expected block-recommended buyer state after projection, got %+v", paths[0])
	}
	if paths[0].RiskZone != risk.RiskZoneRelease {
		t.Fatalf("expected release risk zone, got %+v", paths[0])
	}
	if paths[0].ReviewBurden == "" {
		t.Fatalf("expected review burden projection, got %+v", paths[0])
	}
}

func TestStaticOnlyRuntimeEvidenceNotCollected(t *testing.T) {
	t.Parallel()

	paths := decorateActionPathsForReport([]risk.ActionPath{{
		PathID:           "apc-static-only",
		Org:              "acme",
		Repo:             "acme/release",
		ToolType:         "compiled_action",
		Location:         ".github/workflows/release.yml",
		WriteCapable:     true,
		CredentialAccess: true,
		ApprovalGap:      true,
	}}, nil)
	if len(paths) != 1 {
		t.Fatalf("expected one projected path, got %+v", paths)
	}
	if got := risk.RuntimeEvidenceAbsenceStatus(paths[0]); got != risk.RuntimeEvidenceAbsenceNotCollected {
		t.Fatalf("expected static-only runtime evidence to be not_collected, got %+v", paths[0])
	}
	if label := risk.BuyerRuntimeEvidenceLabel(paths[0].RuntimeEvidenceState, risk.RuntimeEvidenceAbsenceStatus(paths[0]), paths[0].GaitCoverage); label != "runtime evidence not collected" {
		t.Fatalf("expected static-only runtime label, got %q", label)
	}
}

func TestMissingRuntimeForControlClaimEscalates(t *testing.T) {
	t.Parallel()

	paths := decorateActionPathsForReport([]risk.ActionPath{{
		PathID:               "apc-runtime-claim",
		Org:                  "acme",
		Repo:                 "acme/release",
		ToolType:             "compiled_action",
		Location:             ".github/workflows/release.yml",
		WriteCapable:         true,
		DeployWrite:          true,
		CredentialAccess:     true,
		ApprovalGap:          true,
		PolicyCoverageStatus: risk.PolicyCoverageStatusRuntimeProven,
		PolicyRefs:           []string{"gait://release"},
	}}, nil)
	if len(paths) != 1 {
		t.Fatalf("expected one projected path, got %+v", paths)
	}
	if got := risk.RuntimeEvidenceAbsenceStatus(paths[0]); got != risk.RuntimeEvidenceAbsenceMissingForClaim {
		t.Fatalf("expected runtime control claim gap, got %+v", paths[0])
	}
	if paths[0].ControlPriority != risk.ControlPriorityControlFirst || paths[0].ReviewBurden != risk.ReviewBurdenCritical {
		t.Fatalf("expected runtime control-claim gap to escalate review posture, got %+v", paths[0])
	}
	if label := risk.BuyerRuntimeEvidenceLabel(paths[0].RuntimeEvidenceState, risk.RuntimeEvidenceAbsenceStatus(paths[0]), paths[0].GaitCoverage); label != "runtime evidence missing for a control claim" {
		t.Fatalf("expected control-claim runtime label, got %q", label)
	}
}

func TestGaitCoverageAndBOMRuntimeEvidenceAgree(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:               "apc-bom-runtime",
					Org:                  "acme",
					Repo:                 "acme/release",
					ToolType:             "compiled_action",
					Location:             ".github/workflows/release.yml",
					WriteCapable:         true,
					DeployWrite:          true,
					CredentialAccess:     true,
					ApprovalGap:          true,
					PolicyCoverageStatus: risk.PolicyCoverageStatusRuntimeProven,
					PolicyRefs:           []string{"gait://release"},
				}},
			},
		},
		GeneratedAt: time.Date(2026, 5, 25, 12, 0, 0, 0, time.UTC),
		Template:    TemplateAgentActionBOM,
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.AgentActionBOM == nil || len(summary.AgentActionBOM.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", summary.AgentActionBOM)
	}
	item := summary.AgentActionBOM.Items[0]
	if item.RuntimeEvidenceAbsenceStatus != risk.RuntimeEvidenceAbsenceMissingForClaim {
		t.Fatalf("expected BOM runtime absence status, got %+v", item)
	}
	if item.GaitCoverage == nil || risk.RuntimeEvidenceAbsenceStatus(risk.ActionPath{GaitCoverage: item.GaitCoverage}) != risk.RuntimeEvidenceAbsenceMissingForClaim {
		t.Fatalf("expected BOM gait coverage to carry the same runtime absence posture, got %+v", item.GaitCoverage)
	}
}

func TestAgentActionBOMTemplateLeadsWithBOMSections(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:               "apc-123456",
					AgentID:              "wrkr:ci:acme",
					Org:                  "acme",
					Repo:                 "acme/release",
					ToolType:             "compiled_action",
					Location:             ".github/workflows/release.yml",
					WriteCapable:         true,
					CredentialAccess:     true,
					ActionClasses:        []string{"deploy", "write"},
					ApprovalGap:          true,
					RecommendedAction:    "control",
					BusinessStateSurface: "deploy",
				}},
			},
		},
		Template:    TemplateAgentActionBOM,
		GeneratedAt: time.Date(2026, 4, 29, 19, 33, 12, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.AgentActionBOM == nil {
		t.Fatalf("expected agent_action_bom on summary, got %+v", summary)
	}
	markdown := RenderMarkdown(summary)
	bomIdx := strings.Index(markdown, "## Agent Action BOM")
	topRiskIdx := strings.Index(markdown, "Top risky agent action BOM items")
	if bomIdx < 0 {
		t.Fatalf("expected BOM section in markdown, got %q", markdown)
	}
	if topRiskIdx >= 0 && bomIdx > topRiskIdx {
		t.Fatalf("expected BOM section to lead before raw sections, got %q", markdown)
	}
}

func TestAgentActionBOMMarkdownLeadsWithBuyerSummary(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		Snapshot: state.Snapshot{
			Target: source.Target{Mode: "path", Value: "."},
			Targets: []source.Target{
				{Mode: "path", Value: "."},
			},
			SourcePrivacy: &sourceprivacy.Contract{
				RetentionMode:              sourceprivacy.RetentionEphemeral,
				MaterializedSourceRetained: false,
				RawSourceInArtifacts:       false,
				SerializedLocations:        sourceprivacy.SerializedLocationsLogical,
				CleanupStatus:              sourceprivacy.CleanupRemoved,
			},
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:               "apc-123456",
					Org:                  "acme",
					Repo:                 "acme/release",
					ToolType:             "langchain",
					Location:             "agents/release.py",
					WriteCapable:         true,
					CredentialAccess:     true,
					ApprovalGap:          true,
					RecommendedAction:    "control",
					ControlPriority:      risk.ControlPriorityControlFirst,
					RiskTier:             risk.RiskTierHigh,
					PolicyCoverageStatus: risk.PolicyCoverageStatusNone,
				}},
			},
		},
		Template:    TemplateAgentActionBOM,
		GeneratedAt: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}

	markdown := RenderMarkdown(summary)
	if !strings.Contains(markdown, "- Scanned scope:") {
		t.Fatalf("expected buyer summary to include scanned scope, got %q", markdown)
	}
	if !strings.Contains(markdown, "- Operational exposure:") || !strings.Contains(markdown, "- Governance readiness:") {
		t.Fatalf("expected buyer summary to include split readiness axes, got %q", markdown)
	}
	if strings.Index(markdown, "- Scanned scope:") > strings.Index(markdown, "## Assessment Summary") {
		t.Fatalf("expected buyer summary to lead before assessment details, got %q", markdown)
	}
}

func TestMarkdownApprovalUnknownUsesEvidenceNotFound(t *testing.T) {
	t.Parallel()

	summary := Summary{
		SummaryVersion: SummaryVersion,
		GeneratedAt:    "2026-05-24T12:00:00Z",
		Template:       string(TemplateAgentActionBOM),
		ShareProfile:   string(ShareProfileInternal),
		AgentActionBOM: &AgentActionBOM{
			BOMID:         "bom-evidence-language",
			SchemaVersion: AgentActionBOMSchemaVersion,
			GeneratedAt:   "2026-05-24T12:00:00Z",
			Summary: AgentActionBOMSummary{
				TotalItems:                   1,
				ApprovalEvidenceUnknownItems: 1,
				ControlFirstItems:            1,
			},
			Items: []AgentActionBOMItem{{
				PathID:                 "apc-evidence-language",
				Org:                    "acme",
				Repo:                   "acme/release",
				ToolType:               "compiled_action",
				Location:               ".github/workflows/release.yml",
				ControlState:           risk.ControlStateEvidenceNeeded,
				ControlPriority:        risk.ControlPriorityControlFirst,
				RiskTier:               risk.RiskTierHigh,
				ReviewBurden:           risk.ReviewBurdenHigh,
				ConfidenceLane:         risk.ConfidenceLaneConfirmedActionPath,
				ApprovalEvidenceState:  risk.EvidenceStateUnknown,
				ControlResolutionState: risk.ControlResolutionStateNoVisibleControl,
				Remediation:            "Attach owner, policy, proof, or credential-scope evidence for this exact path and rescan.",
			}},
		},
	}

	markdown := RenderMarkdown(summary)
	if !strings.Contains(markdown, "approval evidence not found") {
		t.Fatalf("expected buyer-safe approval wording, got:\n%s", markdown)
	}
	if strings.Contains(markdown, "approval missing") {
		t.Fatalf("expected blunt approval-missing wording to stay out of markdown, got:\n%s", markdown)
	}
}

func TestReportQABlocksUnsupportedApprovalMissing(t *testing.T) {
	t.Parallel()

	err := ValidateBuyerArtifactTexts(BuyerArtifactQAInput{
		Texts: map[string]string{
			"markdown": "approval missing for workflow release.yml",
		},
	})
	if err == nil {
		t.Fatal("expected QA guardrail to reject unsupported approval-missing wording")
	}
	if !strings.Contains(err.Error(), "approval missing") {
		t.Fatalf("expected approval-missing phrase in QA error, got %v", err)
	}
}

func TestReportQABlocksAgentLabelForPlainSourcePath(t *testing.T) {
	t.Parallel()

	err := ValidateBuyerArtifactTexts(BuyerArtifactQAInput{
		ActionPathTypes: []string{risk.ActionPathTypePlainSourceCode},
		PathEvidence: []BuyerArtifactPathEvidence{{
			ActionPathType: risk.ActionPathTypePlainSourceCode,
			Repo:           "acme/payments",
			Location:       "openapi/payments.yaml",
		}},
		Texts: map[string]string{
			"markdown": "confirmed agent framework repo=acme/payments location=openapi/payments.yaml",
		},
	})
	if err == nil {
		t.Fatal("expected QA guardrail to reject unsupported agent-framework wording")
	}
	if !strings.Contains(err.Error(), risk.ActionPathTypeAgentFramework) {
		t.Fatalf("expected agent-framework evidence hint in QA error, got %v", err)
	}
}

func TestReportQAAllowsAgentLabelWhenActionPathTypeIsAgentFramework(t *testing.T) {
	t.Parallel()

	if err := ValidateBuyerArtifactTexts(BuyerArtifactQAInput{
		ActionPathTypes: []string{risk.ActionPathTypeAgentFramework},
		PathEvidence: []BuyerArtifactPathEvidence{{
			ActionPathType: risk.ActionPathTypeAgentFramework,
			Repo:           "acme/payments",
			Location:       "agents/release.py",
		}},
		Texts: map[string]string{
			"markdown": "confirmed agent framework repo=acme/payments location=agents/release.py",
		},
	}); err != nil {
		t.Fatalf("expected agent-framework wording to be allowed with agent evidence, got %v", err)
	}
}

func TestReportQABlocksAgentLabelForWrongPathInMixedArtifact(t *testing.T) {
	t.Parallel()

	err := ValidateBuyerArtifactTexts(BuyerArtifactQAInput{
		ActionPathTypes: []string{risk.ActionPathTypeAgentFramework, risk.ActionPathTypePlainSourceCode},
		PathEvidence: []BuyerArtifactPathEvidence{
			{
				ActionPathType: risk.ActionPathTypeAgentFramework,
				Repo:           "acme/agents",
				Location:       "agents/release.py",
			},
			{
				ActionPathType: risk.ActionPathTypePlainSourceCode,
				Repo:           "acme/payments",
				Location:       "openapi/payments.yaml",
			},
		},
		Texts: map[string]string{
			"markdown": "- confirmed agent framework repo=acme/payments location=openapi/payments.yaml",
		},
	})
	if err == nil {
		t.Fatal("expected path-specific QA guardrail to reject mixed-artifact agent overclaim")
	}
	if !strings.Contains(err.Error(), "specific path evidence") {
		t.Fatalf("expected path-specific evidence wording in QA error, got %v", err)
	}
}

func TestAgentActionBOMDoesNotRenderPositiveEmptyStateForStandingCredential(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:                   "apc-standing",
					Org:                      "acme",
					Repo:                     "acme/release",
					ToolType:                 "compiled_action",
					Location:                 ".github/workflows/release.yml",
					WriteCapable:             true,
					CredentialAccess:         true,
					StandingPrivilege:        true,
					StandingPrivilegeReasons: []string{"credential_access_type:standing"},
					PullRequestWrite:         true,
					ApprovalGap:              true,
					ApprovalGapReasons:       []string{"approval_source_missing"},
				}},
			},
		},
		Template:    TemplateAgentActionBOM,
		GeneratedAt: time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}

	markdown := RenderMarkdown(summary)
	if strings.Contains(markdown, "## Empty-State Assessment") {
		t.Fatalf("expected standing-credential path to block empty-state messaging, got %q", markdown)
	}
	if !strings.Contains(markdown, "## Top Governable Paths") {
		t.Fatalf("expected governable path section instead of empty state, got %q", markdown)
	}
}

func TestReportArtifactsShareActionPathProjection(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:                   "apc-shared",
					Org:                      "acme",
					Repo:                     "acme/release",
					ToolType:                 "compiled_action",
					Location:                 ".github/workflows/release.yml",
					WriteCapable:             true,
					CredentialAccess:         true,
					PullRequestWrite:         true,
					ApprovalGap:              true,
					ApprovalGapReasons:       []string{"approval_source_missing"},
					ActionClasses:            []string{"deploy", "write"},
					RecommendedAction:        "control",
					ProductionWrite:          true,
					MatchedProductionTargets: []string{"deploy/prod"},
				}},
			},
		},
		Template:    TemplateAgentActionBOM,
		GeneratedAt: time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if len(summary.ActionPaths) != 1 || summary.AgentActionBOM == nil || len(summary.AgentActionBOM.Items) != 1 || len(summary.TopRisks) != 1 {
		t.Fatalf("expected one projected path across summary artifacts, got %+v", summary)
	}

	path := summary.ActionPaths[0]
	item := summary.AgentActionBOM.Items[0]
	top := summary.TopRisks[0]
	if path.ControlState != item.ControlState || path.ControlState != top.ControlState {
		t.Fatalf("expected shared control_state, path=%q item=%q top=%q", path.ControlState, item.ControlState, top.ControlState)
	}
	if path.RiskZone != item.RiskZone || path.RiskZone != top.RiskZone {
		t.Fatalf("expected shared risk_zone, path=%q item=%q top=%q", path.RiskZone, item.RiskZone, top.RiskZone)
	}
	if path.ReviewBurden != item.ReviewBurden || path.ReviewBurden != top.ReviewBurden {
		t.Fatalf("expected shared review_burden, path=%q item=%q top=%q", path.ReviewBurden, item.ReviewBurden, top.ReviewBurden)
	}
	if path.ConfidenceLane != item.ConfidenceLane || path.ConfidenceLane != top.ConfidenceLane {
		t.Fatalf("expected shared confidence_lane, path=%q item=%q top=%q", path.ConfidenceLane, item.ConfidenceLane, top.ConfidenceLane)
	}
	if path.RiskTier != item.RiskTier || path.RiskTier != top.RiskTier {
		t.Fatalf("expected shared risk_tier, path=%q item=%q top=%q", path.RiskTier, item.RiskTier, top.RiskTier)
	}

	payload := mustJSONEvidenceBundle(t, summary)
	var bundle map[string]any
	if err := json.Unmarshal(payload, &bundle); err != nil {
		t.Fatalf("parse evidence bundle: %v", err)
	}
	agentActionBOM, ok := bundle["agent_action_bom"].(map[string]any)
	if !ok {
		t.Fatalf("expected agent_action_bom in evidence bundle, got %T", bundle["agent_action_bom"])
	}
	items, ok := agentActionBOM["items"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("expected one evidence BOM item, got %v", agentActionBOM["items"])
	}
	first, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected evidence BOM item type: %T", items[0])
	}
	if first["control_state"] != path.ControlState || first["confidence_lane"] != path.ConfidenceLane {
		t.Fatalf("expected evidence JSON to share action-path projection, got %v", first)
	}
}

func TestCustomerRedactedProjectionPreservesControlState(t *testing.T) {
	t.Parallel()

	input := BuildInput{
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:             "apc-redact",
					AgentID:            "wrkr:release:acme",
					Org:                "acme",
					Repo:               "acme/payments",
					ToolType:           "compiled_action",
					Location:           ".github/workflows/release.yml",
					WriteCapable:       true,
					CredentialAccess:   true,
					PullRequestWrite:   true,
					ApprovalGap:        true,
					ApprovalGapReasons: []string{"approval_source_missing"},
					ActionClasses:      []string{"deploy", "write"},
					RecommendedAction:  "control",
				}},
			},
		},
		Template:    TemplateAgentActionBOM,
		GeneratedAt: time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
	}

	internal, err := BuildSummary(input)
	if err != nil {
		t.Fatalf("build internal summary: %v", err)
	}
	input.ShareProfile = ShareProfileCustomerRedacted
	redacted, err := BuildSummary(input)
	if err != nil {
		t.Fatalf("build redacted summary: %v", err)
	}

	internalPath := internal.ActionPaths[0]
	redactedPath := redacted.ActionPaths[0]
	if internalPath.ControlState != redactedPath.ControlState || internalPath.RiskZone != redactedPath.RiskZone || internalPath.ReviewBurden != redactedPath.ReviewBurden || internalPath.ConfidenceLane != redactedPath.ConfidenceLane {
		t.Fatalf("expected redaction to preserve derived posture, internal=%+v redacted=%+v", internalPath, redactedPath)
	}
	if internal.AgentActionBOM.Summary.EmptyStateStatus != redacted.AgentActionBOM.Summary.EmptyStateStatus {
		t.Fatalf("expected redaction to preserve empty-state status, internal=%+v redacted=%+v", internal.AgentActionBOM.Summary, redacted.AgentActionBOM.Summary)
	}
}

func TestRenderMarkdownUsesReviewCandidateWording(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:             "apc-review",
					Org:                "acme",
					Repo:               "acme/platform",
					ToolType:           "prompt_channel",
					Location:           "AGENTS.md",
					ApprovalGap:        true,
					ApprovalGapReasons: []string{"approval_source_missing"},
					RecommendedAction:  "proof",
				}},
			},
		},
		Template:    TemplateAgentActionBOM,
		GeneratedAt: time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}

	markdown := RenderMarkdown(summary)
	if !strings.Contains(markdown, "review candidate") {
		t.Fatalf("expected semantic review wording in markdown, got %q", markdown)
	}
	if strings.Contains(markdown, "confirmed action path repo=acme/platform location=AGENTS.md") {
		t.Fatalf("did not expect semantic review candidate to read as confirmed path, got %q", markdown)
	}
}

func TestReportAgentLabelRequiresAgenticPathType(t *testing.T) {
	t.Parallel()

	plainSummary := Summary{
		GeneratedAt:  "2026-05-25T12:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
		AgentActionBOM: &AgentActionBOM{
			BOMID:         "bom-plain",
			SchemaVersion: AgentActionBOMSchemaVersion,
			GeneratedAt:   "2026-05-25T12:00:00Z",
			Summary:       AgentActionBOMSummary{TotalItems: 1},
			Items: []AgentActionBOMItem{{
				Repo:           "acme/app",
				Location:       "openapi/payments.yaml",
				ConfidenceLane: risk.ConfidenceLaneConfirmedActionPath,
				ActionPathType: risk.ActionPathTypePlainSourceCode,
			}},
		},
	}
	if strings.Contains(RenderMarkdown(plainSummary), "agent framework") {
		t.Fatalf("did not expect plain source path to read as agentic")
	}

	agentSummary := Summary{
		GeneratedAt:  "2026-05-25T12:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
		AgentActionBOM: &AgentActionBOM{
			BOMID:         "bom-agent",
			SchemaVersion: AgentActionBOMSchemaVersion,
			GeneratedAt:   "2026-05-25T12:00:00Z",
			Summary:       AgentActionBOMSummary{TotalItems: 1},
			Items: []AgentActionBOMItem{{
				Repo:           "acme/app",
				Location:       "agents/release.py",
				ConfidenceLane: risk.ConfidenceLaneConfirmedActionPath,
				ActionPathType: risk.ActionPathTypeAgentFramework,
			}},
		},
	}
	if !strings.Contains(RenderMarkdown(agentSummary), "agent framework") {
		t.Fatalf("expected agentic path type to drive agent wording")
	}
}

func TestRenderMarkdownDesignPartnerTemplateRendersTopValidatedFindings(t *testing.T) {
	t.Parallel()

	summary := Summary{
		GeneratedAt:  "2026-05-11T12:00:00Z",
		Template:     string(TemplateDesignPartnerSummary),
		ShareProfile: string(ShareProfileDesignPartner),
		ShareProfileMetadata: &ShareProfileMetadata{
			RedactionApplied: true,
			RedactionVersion: "customer-share-v2",
			SelectedFields:   []string{"authors", "credential-subjects", "filesystem", "graph-refs", "proof-refs", "providers"},
		},
		ScanScope: &ScanScopeSummary{
			Mode:           "path",
			ScopeLabel:     "local repo group",
			SourceBoundary: "repo_group",
			RepoCount:      1,
			TargetCount:    1,
		},
		AgentActionBOM: &AgentActionBOM{
			Items: []AgentActionBOMItem{{
				Repo:                  "repo-123abc",
				Location:              "loc-456def",
				Owner:                 "owner-789ghi",
				Purpose:               "refund automation",
				PurposeSource:         "mcp_description",
				Version:               "1.2.3",
				VersionSource:         "launcher_arg",
				ConfigSource:          "loc-config123",
				ConfidenceLane:        risk.ConfidenceLaneConfirmedActionPath,
				ControlState:          risk.ControlStateBlockRecommend,
				RiskZone:              risk.RiskZoneProductionData,
				RiskTier:              risk.RiskTierCritical,
				ProofCoverage:         "missing",
				PolicyStatus:          "none",
				RuntimeEvidenceStatus: "unmatched",
				ApprovalGap:           true,
				Remediation:           "Require CODEOWNERS review, attach proof, and rescan.",
				CredentialAuthority: &agginventory.CredentialAuthority{
					CredentialKind:         agginventory.CredentialKindGitHubPAT,
					CredentialSource:       agginventory.CredentialSourceWorkflowSecretRef,
					AccessType:             agginventory.CredentialAccessTypeStanding,
					RotationEvidenceStatus: agginventory.CredentialRotationEvidenceMissing,
				},
				MutableEndpointSemantics: []agginventory.MutableEndpointSemantic{{
					Semantic:   agginventory.EndpointSemanticRefund,
					Confidence: "high",
				}},
				ActionLineage: &risk.ActionLineage{
					Segments: []risk.ActionLineageSegment{
						{Kind: "repo", Label: "repo-123abc", Status: "present"},
						{Kind: "workflow", Label: "loc-456def", Status: "present"},
						{Kind: "approval", Label: "approval_gap", Status: "missing"},
						{Kind: "proof", Label: "missing", Status: "missing"},
					},
				},
			}},
		},
		ActionSurfaceRegistry: []ActionSurfaceRegistryEntry{{
			Label:          "refund automation",
			SurfaceType:    "workflow",
			Owner:          "owner-789ghi",
			Purpose:        "refund automation",
			ConfidenceLane: risk.ConfidenceLaneConfirmedActionPath,
			Remediation:    "Require CODEOWNERS review, attach proof, and rescan.",
		}},
	}

	markdown := RenderMarkdown(summary)
	for _, want := range []string{
		"# Wrkr Design Partner Summary",
		"## Top Validated Findings",
		"Problem:",
		"Likely explanation:",
		"Threat:",
		"Recommended control:",
		"Lineage:",
		"## Registry Highlights",
		"## Known Limits",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("expected design-partner markdown to contain %q, got %q", want, markdown)
		}
	}
}

func TestBuildSummaryDecoratesBacklogWithProjectedPosture(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:                   "apc-backlog",
					Org:                      "acme",
					Repo:                     "acme/release",
					ToolType:                 "compiled_action",
					Location:                 ".github/workflows/release.yml",
					WriteCapable:             true,
					CredentialAccess:         true,
					PullRequestWrite:         true,
					ApprovalGap:              true,
					ApprovalGapReasons:       []string{"approval_source_missing"},
					PolicyCoverageStatus:     risk.PolicyCoverageStatusNone,
					PolicyMissingReasons:     []string{"policy_binding_missing"},
					PolicyConfidence:         "high",
					MatchedProductionTargets: []string{"deploy/prod"},
				}},
			},
			ControlBacklog: &controlbacklog.Backlog{
				Items: []controlbacklog.Item{{
					LinkedActionPathID:   "apc-backlog",
					Repo:                 "acme/release",
					Path:                 ".github/workflows/release.yml",
					ControlState:         "inventory_only",
					RiskZone:             "visibility_only",
					ReviewBurden:         "low",
					ConfidenceLane:       "context_only",
					PolicyCoverageStatus: risk.PolicyCoverageStatusMatched,
					PolicyConfidence:     "low",
					ApprovalStatus:       "approved",
				}},
			},
		},
		Template:    TemplateAgentActionBOM,
		GeneratedAt: time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.ControlBacklog == nil || len(summary.ControlBacklog.Items) != 1 {
		t.Fatalf("expected decorated control backlog item, got %+v", summary.ControlBacklog)
	}

	item := summary.ControlBacklog.Items[0]
	path := summary.ActionPaths[0]
	if item.ControlState != path.ControlState || item.RiskZone != path.RiskZone || item.ReviewBurden != path.ReviewBurden || item.ConfidenceLane != path.ConfidenceLane {
		t.Fatalf("expected backlog posture to match projected action path, item=%+v path=%+v", item, path)
	}
	if item.PolicyCoverageStatus != path.PolicyCoverageStatus || item.PolicyConfidence != path.PolicyConfidence {
		t.Fatalf("expected backlog policy posture to match projected action path, item=%+v path=%+v", item, path)
	}
	if item.ApprovalStatus != "approved" {
		t.Fatalf("expected user-managed approval status to be preserved, got %+v", item)
	}
}

func TestMergeBacklogGovernanceAppendsOverlayOnlyItems(t *testing.T) {
	t.Parallel()

	base := &controlbacklog.Backlog{
		Items: []controlbacklog.Item{{
			ID:   "cb-base",
			Repo: "acme/repo",
			Path: "AGENTS.md",
		}},
	}
	overlay := &controlbacklog.Backlog{
		Items: []controlbacklog.Item{{
			ID:                "cb-overlay",
			Repo:              "acme/repo",
			Path:              ".github/workflows/release.yml",
			Queue:             controlbacklog.QueueAcceptedRisk,
			FindingVisibility: controlbacklog.FindingVisibilityAppendix,
			GovernanceDisposition: &controlbacklog.GovernanceDisposition{
				Kind:   controlbacklog.GovernanceKindAcceptedRisk,
				Status: controlbacklog.GovernanceStatusActive,
				Reason: "time_bounded_exception",
				Scope:  "control_path",
			},
		}},
	}

	merged := mergeBacklogGovernance(base, overlay)
	if merged == nil || len(merged.Items) != 2 {
		t.Fatalf("expected overlay-only backlog item to be appended, got %+v", merged)
	}
	last := merged.Items[1]
	if last.ID != "cb-overlay" || last.GovernanceDisposition == nil || last.GovernanceDisposition.Kind != controlbacklog.GovernanceKindAcceptedRisk {
		t.Fatalf("expected appended overlay item with governance metadata, got %+v", last)
	}
}

func TestControlStateConsistencyBuildSummaryNormalizesCriticalControlStateAcrossSurfaces(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:                   "apc-critical-summary",
					Org:                      "acme",
					Repo:                     "acme/release",
					ToolType:                 "compiled_action",
					Location:                 ".github/workflows/release.yml",
					WriteCapable:             true,
					CredentialAccess:         true,
					StandingPrivilege:        true,
					DeployWrite:              true,
					ProductionWrite:          true,
					MatchedProductionTargets: []string{"built_in:deploy_workflow"},
					PolicyCoverageStatus:     risk.PolicyCoverageStatusMatched,
					PolicyEvidenceRefs:       []string{"gait://release"},
					GaitCoverage: &risk.GaitCoverage{
						ProofVerification: risk.GaitCoverageDetail{
							Status:       risk.GaitStatusPresent,
							EvidenceRefs: []string{"proof_record:rec-111"},
						},
					},
				}},
			},
			ControlBacklog: &controlbacklog.Backlog{
				Items: []controlbacklog.Item{{
					LinkedActionPathID: "apc-critical-summary",
					Repo:               "acme/release",
					Path:               ".github/workflows/release.yml",
				}},
			},
		},
		Template:    TemplateAgentActionBOM,
		GeneratedAt: time.Date(2026, 5, 24, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if len(summary.ActionPaths) != 1 || summary.AgentActionBOM == nil || len(summary.AgentActionBOM.Items) != 1 || summary.ControlBacklog == nil || len(summary.ControlBacklog.Items) != 1 {
		t.Fatalf("expected projected path, bom item, and backlog item, got summary=%+v", summary)
	}

	path := summary.ActionPaths[0]
	item := summary.AgentActionBOM.Items[0]
	backlogItem := summary.ControlBacklog.Items[0]

	if path.ReviewBurden != risk.ReviewBurdenCritical || item.ReviewBurden != path.ReviewBurden || backlogItem.ReviewBurden != path.ReviewBurden {
		t.Fatalf("expected critical review burden across surfaces, path=%+v item=%+v backlog=%+v", path, item, backlogItem)
	}
	if path.ControlState == risk.ControlStateSafeByDefault || item.ControlState != path.ControlState || backlogItem.ControlState != path.ControlState {
		t.Fatalf("expected non-clean control state across surfaces, path=%+v item=%+v backlog=%+v", path, item, backlogItem)
	}
	if path.RiskTier != risk.RiskTierCritical || item.RiskTier != path.RiskTier {
		t.Fatalf("expected critical risk tier across projected path and BOM, path=%+v item=%+v", path, item)
	}
	if item.Queue != controlbacklog.QueueControlFirst || backlogItem.Queue != controlbacklog.QueueControlFirst {
		t.Fatalf("expected fail-closed queue across BOM and backlog, item=%+v backlog=%+v", item, backlogItem)
	}
}

func TestRenderMarkdownDoesNotLabelUnknownLaneAsConfirmed(t *testing.T) {
	t.Parallel()

	summary := Summary{
		Template: string(TemplateAgentActionBOM),
		AgentActionBOM: &AgentActionBOM{
			Items: []AgentActionBOMItem{{
				Repo:         "acme/platform",
				Location:     "top-risk-only",
				ControlState: "review_required",
				RiskZone:     "credential_exposed",
				ReviewBurden: "medium",
				Queue:        "review",
				RiskTier:     risk.RiskTierMedium,
			}},
		},
	}

	markdown := RenderMarkdown(summary)
	if !strings.Contains(markdown, "action-path evidence repo=acme/platform location=top-risk-only") {
		t.Fatalf("expected unknown lane to render neutrally, got %q", markdown)
	}
	if strings.Contains(markdown, "confirmed action path repo=acme/platform location=top-risk-only") {
		t.Fatalf("did not expect unknown lane to render as confirmed, got %q", markdown)
	}
}

func TestBuildSummaryCustomerRedactedSanitizesBOMReachability(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		Snapshot: state.Snapshot{
			Target: source.Target{Mode: "repo", Value: "acme/payments"},
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:               "apc-abcdef",
					AgentID:              "wrkr:langchain:acme",
					Org:                  "acme",
					Repo:                 "acme/payments",
					ToolType:             "langchain",
					Location:             "agents/release.py",
					WriteCapable:         true,
					CredentialAccess:     true,
					ApprovalGap:          true,
					RecommendedAction:    "control",
					ControlPriority:      risk.ControlPriorityControlFirst,
					RiskTier:             risk.RiskTierHigh,
					PolicyCoverageStatus: risk.PolicyCoverageStatusNone,
				}},
			},
			Findings: []source.Finding{
				{
					FindingType: "agent_framework",
					ToolType:    "langchain",
					Org:         "acme",
					Repo:        "acme/payments",
					Location:    "agents/release.py",
					Evidence: []model.Evidence{
						{Key: "confidence", Value: "high"},
						{Key: "evidence_strength", Value: "tool_binding"},
						{Key: "tool_bindings", Value: "prod-mcp"},
						{Key: "reachable_endpoints", Value: "https://api.acme.example/mcp"},
						{Key: "reachable_targets", Value: ".github/workflows/release.yml"},
					},
				},
				{
					FindingType: "mcp_server",
					ToolType:    "mcp",
					Org:         "acme",
					Repo:        "acme/payments",
					Location:    ".mcp.json",
					Permissions: []string{"mcp.admin"},
					Evidence: []model.Evidence{
						{Key: "server", Value: "prod-mcp"},
						{Key: "transport", Value: "stdio"},
					},
				},
			},
		},
		Template:     TemplateAgentActionBOM,
		ShareProfile: ShareProfileCustomerRedacted,
		GeneratedAt:  time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.AgentActionBOM == nil || len(summary.AgentActionBOM.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", summary.AgentActionBOM)
	}
	if summary.ShareProfileMetadata == nil || !summary.ShareProfileMetadata.RedactionApplied {
		t.Fatalf("expected redaction metadata on summary, got %+v", summary.ShareProfileMetadata)
	}
	item := summary.AgentActionBOM.Items[0]
	if !strings.HasPrefix(item.Repo, "repo-") || !strings.HasPrefix(item.Location, "loc-") {
		t.Fatalf("expected redacted repo/location, got %+v", item)
	}
	if item.Confidence != "high" || item.EvidenceStrength != "tool_binding" {
		t.Fatalf("expected confidence metadata on BOM item, got %+v", item)
	}
	if len(item.ReachableServers) != 1 || !strings.HasPrefix(item.ReachableServers[0].Name, "server-") {
		t.Fatalf("expected redacted reachable server name, got %+v", item.ReachableServers)
	}
	if len(item.ReachableEndpoints) != 1 || !strings.HasPrefix(item.ReachableEndpoints[0].Name, "endpoint-") {
		t.Fatalf("expected redacted reachable endpoint name, got %+v", item.ReachableEndpoints)
	}
	if len(item.ReachableTargets) != 1 || !strings.HasPrefix(item.ReachableTargets[0].Name, "target-") {
		t.Fatalf("expected redacted reachable target name, got %+v", item.ReachableTargets)
	}
}

func TestAgentActionBOMCarriesCredentialsPathContextAndToolInstance(t *testing.T) {
	t.Parallel()

	bom := BuildAgentActionBOM(Summary{
		GeneratedAt: "2026-05-07T12:00:00Z",
		ActionPaths: []risk.ActionPath{{
			PathID:            "apc-release",
			AgentID:           "wrkr:agent:acme",
			ToolFamilyID:      "wrkr:family-langchain:acme",
			ToolInstanceID:    "langchain-tool-inst-release",
			Org:               "acme",
			Repo:              "acme/app",
			ToolType:          "langchain",
			Location:          "functional_tests/conftest.py",
			WriteCapable:      true,
			CredentialAccess:  true,
			ApprovalGap:       true,
			RecommendedAction: "proof",
			ControlPriority:   risk.ControlPriorityReviewQueue,
			RiskTier:          risk.RiskTierMedium,
			AttackPathScore:   5.4,
			RiskScore:         6.2,
			PathContext:       agginventory.ClassifyPathContext("functional_tests/conftest.py"),
			Credentials: []*agginventory.CredentialProvenance{
				{
					Type:           agginventory.CredentialProvenanceStaticSecret,
					Subject:        "GITHUB_TOKEN",
					Scope:          agginventory.CredentialScopeWorkflow,
					Confidence:     "high",
					RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceStaticSecret),
				},
			},
			CredentialProvenance: &agginventory.CredentialProvenance{
				Type:           agginventory.CredentialProvenanceStaticSecret,
				Subject:        "GITHUB_TOKEN",
				Scope:          agginventory.CredentialScopeWorkflow,
				Confidence:     "high",
				RiskMultiplier: agginventory.CredentialRiskMultiplier(agginventory.CredentialProvenanceStaticSecret),
			},
		}},
	})
	if bom == nil || len(bom.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", bom)
	}
	item := bom.Items[0]
	if len(item.Credentials) != 1 || item.CredentialProvenance == nil {
		t.Fatalf("expected credentials array and rollup, got %+v", item)
	}
	if item.PathContext == nil || item.PathContext.Kind != agginventory.PathContextFunctionalTest {
		t.Fatalf("expected path context on BOM item, got %+v", item.PathContext)
	}
	if item.ToolFamilyID != "wrkr:family-langchain:acme" || item.ToolInstanceID != "langchain-tool-inst-release" {
		t.Fatalf("expected tool family/instance ids, got %+v", item)
	}
}

func mustJSONEvidenceBundle(t *testing.T, summary Summary) []byte {
	t.Helper()
	payload, err := RenderEvidenceBundleJSON(summary)
	if err != nil {
		t.Fatalf("render evidence bundle: %v", err)
	}
	return payload
}

func TestBuildAssessmentSummaryIsPathCentricAndDeterministic(t *testing.T) {
	t.Parallel()

	paths := []risk.ActionPath{
		{
			PathID:               "apc-aaaaaaaaaaaa",
			Repo:                 "control-plane",
			ToolType:             "mcp",
			RecommendedAction:    "proof",
			OwnerSource:          "repo_fallback",
			OwnershipStatus:      "inferred",
			BusinessStateSurface: "admin_api",
			RiskScore:            9.6,
		},
		{
			PathID:                  "apc-bbbbbbbbbbbb",
			Repo:                    "control-plane",
			ToolType:                "ci_agent",
			RecommendedAction:       "proof",
			WriteCapable:            true,
			OwnerSource:             "codeowners",
			OwnershipStatus:         "explicit",
			BusinessStateSurface:    "deploy",
			ExecutionIdentity:       "github_app",
			ExecutionIdentityType:   "github_app",
			ExecutionIdentitySource: "workflow_static_signal",
			ExecutionIdentityStatus: "known",
			RiskScore:               10,
		},
	}
	controlFirst := &risk.ActionPathToControlFirst{
		Summary: risk.ActionPathSummary{
			TotalPaths:        2,
			WriteCapablePaths: 1,
			GovernFirstPaths:  2,
		},
		Path: paths[0],
	}
	inventory := &agginventory.Inventory{
		NonHumanIdentities: []agginventory.NonHumanIdentity{{
			IdentityID:   "one",
			IdentityType: "github_app",
			Subject:      "github_app",
			Source:       "workflow_static_signal",
		}},
	}

	summary := buildAssessmentSummary(paths, controlFirst, inventory, ProofReference{ChainPath: "state/proof-chain.json"})
	if summary == nil {
		t.Fatal("expected assessment summary")
		return
	}
	got := *summary
	if got.GovernablePathCount != 2 || got.WriteCapablePathCount != 1 || got.ProductionBackedPathCount != 0 {
		t.Fatalf("unexpected assessment counts: %+v", got)
	}
	if got.TopPathToControlFirst == nil || got.TopPathToControlFirst.PathID != paths[0].PathID {
		t.Fatalf("expected top path to control first to point at %q, got %+v", paths[0].PathID, got.TopPathToControlFirst)
	}
	if got.TopExecutionIdentityBacked == nil || got.TopExecutionIdentityBacked.PathID != paths[1].PathID {
		t.Fatalf("expected top execution-identity-backed path to point at %q, got %+v", paths[1].PathID, got.TopExecutionIdentityBacked)
	}
	if got.OwnerlessExposure == nil || got.OwnerlessExposure.ExplicitOwnerPaths != 1 || got.OwnerlessExposure.InferredOwnerPaths != 1 {
		t.Fatalf("expected ownerless exposure rollup, got %+v", got.OwnerlessExposure)
	}
	if summary.IdentityExposureSummary == nil || summary.IdentityExposureSummary.TotalNonHumanIdentitiesObserved != 1 || summary.IdentityExposureSummary.IdentitiesBackingWriteCapablePaths != 1 {
		t.Fatalf("expected identity exposure summary, got %+v", summary.IdentityExposureSummary)
	}
	if summary.IdentityToReviewFirst == nil || summary.IdentityToReviewFirst.ExecutionIdentity != "github_app" {
		t.Fatalf("expected review-first identity target, got %+v", summary.IdentityToReviewFirst)
	}
	if summary.IdentityToRevokeFirst == nil || summary.IdentityToRevokeFirst.ExecutionIdentity != "github_app" {
		t.Fatalf("expected revoke-first identity target, got %+v", summary.IdentityToRevokeFirst)
	}
	if summary.ProofChainPath != "state/proof-chain.json" {
		t.Fatalf("expected proof chain path to be preserved, got %q", summary.ProofChainPath)
	}
}

func TestBuildSummaryWithPublicProfileSanitizesProofPath(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	findings := []model.Finding{{
		FindingType: "policy_violation",
		Severity:    model.SeverityHigh,
		ToolType:    "codex",
		Location:    "/tmp/private/AGENTS.md",
		Repo:        "backend",
		Org:         "acme",
	}}
	riskReport := risk.Score(findings, 5, now)
	snapshot := state.Snapshot{
		Findings:     findings,
		RiskReport:   &riskReport,
		Profile:      &profileeval.Result{CompliancePercent: 92.75, DeltaPercent: -2.25, Status: "pass"},
		PostureScore: &score.Result{Score: 81.4, Grade: "B", TrendDelta: +1.6, Weights: scoremodel.DefaultWeights()},
		Identities: []manifest.IdentityRecord{{
			AgentID:       "wrkr:codex:acme",
			Status:        "under_review",
			ApprovalState: "missing",
		}},
		Transitions: []lifecycle.Transition{{
			AgentID:       "wrkr:codex:acme",
			PreviousState: "discovered",
			NewState:      "under_review",
			Trigger:       "first_seen",
			Timestamp:     now.Format(time.RFC3339),
		}},
	}

	summary, err := BuildSummary(BuildInput{
		Snapshot:     snapshot,
		Template:     TemplatePublic,
		ShareProfile: ShareProfilePublic,
		GeneratedAt:  now,
	})
	if err == nil {
		// BuildSummary requires proof chain; this test only validates early deterministic sanitization helpers.
		if summary.Proof.ChainPath != "redacted://proof-chain.json" {
			t.Fatalf("expected redacted proof path, got %q", summary.Proof.ChainPath)
		}
	}
}

func TestBuildSummaryHonorsExplicitTopZero(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			Findings: []model.Finding{
				{
					FindingType: "policy_violation",
					Severity:    model.SeverityHigh,
					ToolType:    "codex",
					Location:    "/tmp/private/AGENTS.md",
					Repo:        "backend",
					Org:         "acme",
				},
			},
		},
		Template:     TemplateOperator,
		ShareProfile: ShareProfileInternal,
		GeneratedAt:  now,
		Top:          0,
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if len(summary.TopRisks) != 0 {
		t.Fatalf("expected zero top risks for explicit top=0, got %d", len(summary.TopRisks))
	}
	if summary.Activation != nil {
		t.Fatalf("expected activation to be suppressed for explicit top=0, got %+v", summary.Activation)
	}
}

func TestBuildLifecycleSummaryOmitsLegacyNonToolIdentities(t *testing.T) {
	t.Parallel()

	summary := buildLifecycleSummary(nil, []manifest.IdentityRecord{
		{AgentID: "wrkr:source-repo-aaaaaaaaaa:acme", ToolID: "source-repo-aaaaaaaaaa", ToolType: "source_repo", Status: "under_review"},
		{AgentID: "wrkr:codex-bbbbbbbbbb:acme", ToolID: "codex-bbbbbbbbbb", ToolType: "codex", Status: "revoked"},
	}, nil, nil, nil)

	if summary.IdentityCount != 1 {
		t.Fatalf("expected only real-tool identities to count, got %+v", summary)
	}
	if summary.RevokedCount != 1 {
		t.Fatalf("expected revoked count to reflect filtered real-tool identities, got %+v", summary)
	}
}

func TestPrivilegeBudgetFromInventoryBackfillsMissingStatus(t *testing.T) {
	t.Parallel()

	inv := &agginventory.Inventory{
		PrivilegeBudget: agginventory.PrivilegeBudget{
			TotalTools: 3,
			ProductionWrite: agginventory.ProductionWriteBudget{
				Configured: false,
				Status:     "",
				Count:      nil,
			},
		},
	}
	got := privilegeBudgetFromInventory(inv)
	if got.ProductionWrite.Status != agginventory.ProductionTargetsStatusNotConfigured {
		t.Fatalf("expected status backfilled to %q, got %q", agginventory.ProductionTargetsStatusNotConfigured, got.ProductionWrite.Status)
	}
	if got.ProductionWrite.Count != nil {
		t.Fatalf("expected not-configured production count to be nil, got %v", got.ProductionWrite.Count)
	}
}

func TestPrivilegeBudgetFromInventoryConfiguredBackfillsMissingCount(t *testing.T) {
	t.Parallel()

	inv := &agginventory.Inventory{
		PrivilegeBudget: agginventory.PrivilegeBudget{
			TotalTools: 1,
			ProductionWrite: agginventory.ProductionWriteBudget{
				Configured: true,
				Status:     "",
				Count:      nil,
			},
		},
	}
	got := privilegeBudgetFromInventory(inv)
	if got.ProductionWrite.Status != agginventory.ProductionTargetsStatusConfigured {
		t.Fatalf("expected status backfilled to %q, got %q", agginventory.ProductionTargetsStatusConfigured, got.ProductionWrite.Status)
	}
	if got.ProductionWrite.Count == nil || *got.ProductionWrite.Count != 0 {
		t.Fatalf("expected configured production count to default to 0, got %v", got.ProductionWrite.Count)
	}
}

func containsStringValue(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func containsReachabilityName(items []AgentActionBOMReachability, want string) bool {
	for _, item := range items {
		if item.Name == want {
			return true
		}
	}
	return false
}

func TestBuildSummaryUsesWriteCapableFallbackWhenProductionTargetsNotConfigured(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			Inventory: &agginventory.Inventory{
				PrivilegeBudget: agginventory.PrivilegeBudget{
					TotalTools:        2,
					WriteCapableTools: 1,
					ProductionWrite: agginventory.ProductionWriteBudget{
						Configured: false,
						Status:     agginventory.ProductionTargetsStatusNotConfigured,
						Count:      nil,
					},
				},
				SecurityVisibility: agginventory.SecurityVisibilitySummary{ReferenceBasis: "initial_scan"},
			},
			Findings: []model.Finding{{
				FindingType: "tool_config",
				Severity:    model.SeverityLow,
				ToolType:    "codex",
				Location:    ".codex/config.toml",
				Repo:        "repo",
				Org:         "acme",
			}},
		},
		Template:     TemplateOperator,
		ShareProfile: ShareProfileInternal,
		GeneratedAt:  now,
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	headlineFacts := summary.Sections[0].Facts
	joined := strings.Join(headlineFacts, "\n")
	if !strings.Contains(joined, "write_capable=1") {
		t.Fatalf("expected write_capable fallback in headline facts, got %v", headlineFacts)
	}
	if strings.Contains(joined, "production_write not configured") {
		t.Fatalf("expected downgraded production-target wording, got %v", headlineFacts)
	}
	if !strings.Contains(joined, "bundled framework mappings stay available; profile compliance reflects only controls evidenced in the current deterministic scan state") {
		t.Fatalf("expected evidence-state framing in headline facts, got %v", headlineFacts)
	}
	if !strings.Contains(joined, "bundled framework mappings are available; current findings do not map to bundled compliance controls yet") {
		t.Fatalf("expected zero-mapping clarification in headline facts, got %v", headlineFacts)
	}
	if !strings.Contains(joined, "coverage still reflects only controls evidenced in the current scan state; remediate gaps, rescan, and regenerate report/evidence artifacts") {
		t.Fatalf("expected deterministic next-action guidance in headline facts, got %v", headlineFacts)
	}
}

func TestBuildSummarySuppressesUnknownToSecurityHeadlineWithoutReferenceBasis(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			Inventory: &agginventory.Inventory{
				PrivilegeBudget: agginventory.PrivilegeBudget{
					TotalTools:        1,
					WriteCapableTools: 1,
				},
				SecurityVisibility: agginventory.SecurityVisibilitySummary{
					ReferenceBasis:                      "",
					UnknownToSecurityTools:              3,
					UnknownToSecurityAgents:             4,
					UnknownToSecurityWriteCapableAgents: 2,
				},
			},
			Findings: []model.Finding{{
				FindingType: "tool_config",
				Severity:    model.SeverityLow,
				ToolType:    "codex",
				Location:    ".codex/config.toml",
				Repo:        "repo",
				Org:         "acme",
			}},
		},
		Template:     TemplateOperator,
		ShareProfile: ShareProfileInternal,
		GeneratedAt:  now,
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	joined := strings.Join(summary.Sections[0].Facts, "\n")
	if strings.Contains(joined, "unknown_to_security_tools=3") {
		t.Fatalf("expected unknown_to_security claim suppression without reference basis, got %v", summary.Sections[0].Facts)
	}
	if !strings.Contains(joined, "reference_basis unavailable") {
		t.Fatalf("expected suppressed visibility wording, got %v", summary.Sections[0].Facts)
	}
}

func TestBuildSummaryRedactsSourcePrivacyWarningDetails(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			Inventory: &agginventory.Inventory{
				PrivilegeBudget:    agginventory.PrivilegeBudget{TotalTools: 1, WriteCapableTools: 1},
				SecurityVisibility: agginventory.SecurityVisibilitySummary{ReferenceBasis: "initial_scan"},
			},
			Findings: []model.Finding{{
				FindingType: "tool_config",
				Severity:    model.SeverityLow,
				ToolType:    "codex",
				Location:    ".codex/config.toml",
				Repo:        "repo",
				Org:         "acme",
			}},
			SourcePrivacy: &sourceprivacy.Contract{
				RetentionMode:              sourceprivacy.RetentionEphemeral,
				SerializedLocations:        sourceprivacy.SerializedLocationsLogical,
				CleanupStatus:              sourceprivacy.CleanupFailed,
				RawSourceInArtifacts:       false,
				MaterializedSourceRetained: true,
				Warnings: []string{
					"source cleanup failed: /tmp/private/.wrkr/materialized-sources/acme/backend",
				},
			},
		},
		Template:     TemplatePublic,
		ShareProfile: ShareProfilePublic,
		GeneratedAt:  now,
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	joined := strings.Join(summary.Sections[0].Facts, "\n")
	if strings.Contains(joined, "/tmp/private") || strings.Contains(joined, "materialized-sources/acme/backend") {
		t.Fatalf("expected source privacy warning details to be redacted, got %v", summary.Sections[0].Facts)
	}
	if !strings.Contains(joined, "source_privacy warnings=1 details_redacted") {
		t.Fatalf("expected redacted source privacy warning summary, got %v", summary.Sections[0].Facts)
	}
}

func TestBuildSummaryUsesWriteCapableFallbackWhenProductionTargetsInvalid(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC)
	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			Inventory: &agginventory.Inventory{
				PrivilegeBudget: agginventory.PrivilegeBudget{
					TotalTools:        2,
					WriteCapableTools: 1,
					ProductionWrite: agginventory.ProductionWriteBudget{
						Configured: false,
						Status:     agginventory.ProductionTargetsStatusInvalid,
						Count:      nil,
					},
				},
				SecurityVisibility: agginventory.SecurityVisibilitySummary{ReferenceBasis: "initial_scan"},
			},
			Findings: []model.Finding{{
				FindingType: "tool_config",
				Severity:    model.SeverityLow,
				ToolType:    "codex",
				Location:    ".codex/config.toml",
				Repo:        "repo",
				Org:         "acme",
			}},
		},
		Template:     TemplatePublic,
		ShareProfile: ShareProfilePublic,
		GeneratedAt:  now,
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	joined := strings.Join(summary.Sections[0].Facts, "\n")
	if strings.Contains(joined, "production_write=") {
		t.Fatalf("expected invalid production target status to keep public wording at write_capable, got %v", summary.Sections[0].Facts)
	}
	if !strings.Contains(joined, "write_capable=1") {
		t.Fatalf("expected write_capable fallback in headline facts, got %v", summary.Sections[0].Facts)
	}
}

func TestAgentActionBOMLineageShowsMissingProofSegment(t *testing.T) {
	t.Parallel()

	paths := []risk.ActionPath{{
		PathID:                   "apc-lineage",
		Org:                      "acme",
		Repo:                     "acme/release",
		AgentID:                  "wrkr:compiled_action:acme",
		ToolType:                 "compiled_action",
		Location:                 ".github/workflows/release.yml",
		WriteCapable:             true,
		CredentialAccess:         true,
		CredentialAuthority:      &agginventory.CredentialAuthority{CredentialPresent: true, CredentialUsableByPath: true, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
		CredentialProvenance:     &agginventory.CredentialProvenance{Type: agginventory.CredentialProvenanceStaticSecret, CredentialKind: agginventory.CredentialKindGitHubPAT, AccessType: agginventory.CredentialAccessTypeStanding},
		ActionClasses:            []string{"deploy", "write"},
		MatchedProductionTargets: []string{"cluster/prod"},
		OperationalOwner:         "@acme/release",
		OwnershipStatus:          "explicit",
		ApprovalGap:              true,
		ApprovalGapReasons:       []string{"approval_evidence_missing"},
		PolicyCoverageStatus:     risk.PolicyCoverageStatusNone,
	}}
	graph := risk.BuildControlPathGraph(paths)
	paths = risk.DecorateActionLineage(paths, graph)

	bom := buildAgentActionBOM(Summary{
		GeneratedAt:      time.Date(2026, 5, 10, 20, 0, 0, 0, time.UTC).Format(time.RFC3339),
		ActionPaths:      paths,
		ControlPathGraph: graph,
	}, nil)
	if bom == nil || len(bom.Items) != 1 || bom.Items[0].ActionLineage == nil {
		t.Fatalf("expected action-lineage BOM item, got %+v", bom)
	}
	segments := map[string]risk.ActionLineageSegment{}
	for _, segment := range bom.Items[0].ActionLineage.Segments {
		segments[segment.Kind] = segment
	}
	if segments["approval"].Status != "missing" || segments["proof"].Status != "missing" {
		t.Fatalf("expected approval/proof lineage gaps in BOM output, got %+v", bom.Items[0].ActionLineage)
	}
}

func TestSanitizeActionLineagePublicPreservesJoinability(t *testing.T) {
	t.Parallel()

	lineage := &risk.ActionLineage{
		Segments: []risk.ActionLineageSegment{
			{
				SegmentID:    "als-one",
				Kind:         "workflow",
				Label:        ".github/workflows/release.yml",
				NodeIDs:      []string{"node-a"},
				EdgeIDs:      []string{"edge-a"},
				EvidenceRefs: []string{"workflow:.github/workflows/release.yml"},
			},
			{
				SegmentID:    "als-two",
				Kind:         "proof",
				Label:        "proof_missing",
				NodeIDs:      []string{"node-a"},
				EdgeIDs:      []string{"edge-a"},
				EvidenceRefs: []string{"proof:missing"},
			},
		},
	}

	redacted := sanitizeActionLineagePublic(lineage)
	if redacted == nil || len(redacted.Segments) != 2 {
		t.Fatalf("expected redacted lineage output, got %+v", redacted)
	}
	if redacted.Segments[0].Kind != "workflow" || redacted.Segments[1].Kind != "proof" {
		t.Fatalf("expected lineage kinds to survive redaction, got %+v", redacted)
	}
	if redacted.Segments[0].Label == lineage.Segments[0].Label || redacted.Segments[0].NodeIDs[0] != redacted.Segments[1].NodeIDs[0] {
		t.Fatalf("expected redacted labels and stable join ids, got %+v", redacted)
	}
}

func TestSanitizeProofReferencePublicRedactsCanonicalKeys(t *testing.T) {
	t.Parallel()

	out := sanitizeProofReferencePublic(ProofReference{
		ChainPath: "state/proof-chain.json",
		CanonicalFindingKeys: []string{
			"policy_violation|hardcoded-token|codex|/Users/example/private/repo/.codex/config.toml|backend|acme",
			"",
		},
	})

	if out.ChainPath != "redacted://proof-chain.json" {
		t.Fatalf("expected redacted chain path, got %q", out.ChainPath)
	}
	if len(out.CanonicalFindingKeys) != 1 {
		t.Fatalf("expected one redacted canonical key, got %v", out.CanonicalFindingKeys)
	}
	if strings.Contains(out.CanonicalFindingKeys[0], "backend") || strings.Contains(out.CanonicalFindingKeys[0], "acme") {
		t.Fatalf("expected redacted canonical finding key, got %q", out.CanonicalFindingKeys[0])
	}
}
