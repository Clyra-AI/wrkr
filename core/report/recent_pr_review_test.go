package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/attribution"
)

func TestBuildRecentPRReviewRanksHigherRiskPathsFirst(t *testing.T) {
	t.Parallel()

	review := BuildRecentPRReview(Summary{
		AgentActionBOM: &AgentActionBOM{
			Items: []AgentActionBOMItem{
				{
					PathID:                   "apc-low",
					Repo:                     "acme/docs",
					Location:                 ".github/workflows/docs.yml",
					ActionPathType:           "ai_assisted_workflow",
					AutonomyTier:             "tier_1_low_risk_internal",
					DelegationReadinessState: "safe_to_delegate",
					RecommendedControl:       "allow",
					TargetClass:              "developer_productivity",
					IntroducedBy: &attribution.Result{
						Reference: "pr/41",
						Timestamp: "2026-05-25T10:00:00Z",
						Provenance: &attribution.Provenance{
							Reference:  "pr/41",
							AIAssisted: true,
							Checks:     []attribution.ProvenanceCheck{{Name: "fast-lane"}},
							Approvals:  []attribution.ProvenanceActor{{Name: "docs-owner"}},
						},
					},
				},
				{
					PathID:                             "apc-high",
					Repo:                               "acme/payments",
					Location:                           ".github/workflows/release.yml",
					ActionPathType:                     "automation_bot",
					AutonomyTier:                       "tier_4_prod_privileged_or_customer_impacting",
					DelegationReadinessState:           "approval_required",
					RecommendedControl:                 "approval_required",
					TargetClass:                        "production_impacting",
					EvidencePacketMissingEvidenceState: "missing",
					EvidencePacketStatus:               "matched",
					IntroducedBy: &attribution.Result{
						Reference: "pr/42",
						Timestamp: "2026-05-26T10:00:00Z",
						Provenance: &attribution.Provenance{
							Reference:          "pr/42",
							AIAssisted:         true,
							AutomationAssisted: true,
							Checks:             []attribution.ProvenanceCheck{{Name: "fast-lane"}, {Name: "windows-smoke"}},
							Approvals:          []attribution.ProvenanceActor{{Name: "release-owner"}},
							Deployments:        []attribution.ProvenanceDeployment{{Environment: "production"}},
							MissingEvidence:    []string{"branch_protection_missing"},
						},
					},
				},
			},
		},
	}, RecentPRReviewOptions{Limit: 10})
	if review == nil || len(review.Ranked) != 2 {
		t.Fatalf("expected two ranked review items, got %+v", review)
	}
	if review.Ranked[0].PathID != "apc-high" || review.Ranked[1].PathID != "apc-low" {
		t.Fatalf("expected higher-risk path first, got %+v", review.Ranked)
	}
}

func TestBuildRecentPRReviewFiltersByIDsAndDateRange(t *testing.T) {
	t.Parallel()

	review := BuildRecentPRReview(Summary{
		AgentActionBOM: &AgentActionBOM{
			Items: []AgentActionBOMItem{
				{
					PathID:         "apc-keep",
					Repo:           "acme/payments",
					Location:       ".github/workflows/release.yml",
					ActionPathType: "ai_assisted_workflow",
					IntroducedBy: &attribution.Result{
						Reference: "pr/42",
						Timestamp: "2026-05-26T10:00:00Z",
						Provenance: &attribution.Provenance{
							Reference:  "pr/42",
							AIAssisted: true,
						},
					},
				},
				{
					PathID:         "apc-drop",
					Repo:           "acme/payments",
					Location:       ".github/workflows/release.yml",
					ActionPathType: "ai_assisted_workflow",
					IntroducedBy: &attribution.Result{
						Reference: "pr/41",
						Timestamp: "2026-05-20T10:00:00Z",
						Provenance: &attribution.Provenance{
							Reference:  "pr/41",
							AIAssisted: true,
						},
					},
				},
			},
		},
	}, RecentPRReviewOptions{
		IDs:         []string{"pr/42"},
		DateFrom:    time.Date(2026, 5, 25, 0, 0, 0, 0, time.UTC),
		HasDateFrom: true,
		Limit:       10,
	})
	if review == nil || len(review.Ranked) != 1 || review.Ranked[0].PathID != "apc-keep" {
		t.Fatalf("expected filtered review result, got %+v", review)
	}
}

func TestRenderMarkdownIncludesRecentPRReviewSection(t *testing.T) {
	t.Parallel()

	markdown := RenderMarkdown(Summary{
		GeneratedAt:    "2026-05-26T15:00:00Z",
		Template:       string(TemplateAgentActionBOM),
		ShareProfile:   string(ShareProfileInternal),
		AgentActionBOM: &AgentActionBOM{BOMID: "bom-1", Summary: AgentActionBOMSummary{CoverageConfidence: "complete"}},
		RecentPRReview: &RecentPRReview{
			Mode:            "local_sidecars",
			Limit:           10,
			TotalCandidates: 1,
			Ranked: []RecentPRReviewItem{{
				Rank:               1,
				Reference:          "pr/42",
				Repo:               "acme/payments",
				Workflow:           ".github/workflows/release.yml",
				FocusBOMPathID:     "apc-release-1",
				ProofRefs:          []string{"proof://release"},
				EvidencePacketRefs: []string{"pkt-1"},
			}},
		},
	})
	if !strings.Contains(markdown, "## Recent PR Review") || !strings.Contains(markdown, "pr/42") {
		t.Fatalf("expected recent review markdown section, got %q", markdown)
	}
}
