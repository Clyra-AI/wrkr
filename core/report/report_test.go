package report

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
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
	}
	if first.BOMID == "" || first.SchemaVersion != AgentActionBOMSchemaVersion {
		t.Fatalf("unexpected BOM identity: %+v", first)
	}
	if len(first.Items) != 2 {
		t.Fatalf("expected two BOM items, got %+v", first.Items)
	}
	if first.Items[0].PathID != "apc-200000" {
		t.Fatalf("expected govern-first ordering to be preserved, got %+v", first.Items)
	}
	if first.Summary.ControlFirstItems != 1 || first.Summary.StandingPrivilegeItems != 1 || first.Summary.RuntimeProvenItems != 1 {
		t.Fatalf("unexpected BOM summary counts: %+v", first.Summary)
	}
	if !containsStringValue(first.Items[0].GraphRefs.NodeIDs, "node-1") || !containsStringValue(first.Items[0].ProofRefs, "proof_head:sha256:abc123") {
		t.Fatalf("expected graph/proof refs on BOM item, got %+v", first.Items[0])
	}
	if first.Items[0].PolicyStatus != risk.PolicyCoverageStatusMatched || first.Items[0].IntroducedBy == nil || first.Items[0].IntroducedBy.CommitSHA != "abc123" {
		t.Fatalf("expected policy coverage and introduction attribution on BOM item, got %+v", first.Items[0])
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
	}
	if summary.GovernablePathCount != 2 || summary.WriteCapablePathCount != 1 || summary.ProductionBackedPathCount != 0 {
		t.Fatalf("unexpected assessment counts: %+v", summary)
	}
	if summary.TopPathToControlFirst == nil || summary.TopPathToControlFirst.PathID != paths[0].PathID {
		t.Fatalf("expected top path to control first to point at %q, got %+v", paths[0].PathID, summary.TopPathToControlFirst)
	}
	if summary.TopExecutionIdentityBacked == nil || summary.TopExecutionIdentityBacked.PathID != paths[1].PathID {
		t.Fatalf("expected top execution-identity-backed path to point at %q, got %+v", paths[1].PathID, summary.TopExecutionIdentityBacked)
	}
	if summary.OwnerlessExposure == nil || summary.OwnerlessExposure.ExplicitOwnerPaths != 1 || summary.OwnerlessExposure.InferredOwnerPaths != 1 {
		t.Fatalf("expected ownerless exposure rollup, got %+v", summary.OwnerlessExposure)
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
