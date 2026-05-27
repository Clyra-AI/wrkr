package report

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestBuildSummaryIncludesWorkflowChainsAndBOMRefs(t *testing.T) {
	t.Parallel()

	summary, err := BuildSummary(BuildInput{
		StatePath: filepath.Join(t.TempDir(), "state.json"),
		Snapshot: state.Snapshot{
			RiskReport: &risk.Report{
				ActionPaths: []risk.ActionPath{{
					PathID:                   "apc-wave2-summary",
					AgentID:                  "wrkr:ci:acme",
					Org:                      "acme",
					Repo:                     "acme/release",
					ToolType:                 "compiled_action",
					Location:                 ".github/workflows/release.yml",
					Purpose:                  "release automation",
					PurposeSource:            "workflow_name",
					WriteCapable:             true,
					PullRequestWrite:         true,
					DeployWrite:              true,
					ProductionWrite:          true,
					RecommendedAction:        "proof",
					BusinessStateSurface:     "deploy",
					PolicyCoverageStatus:     risk.PolicyCoverageStatusMatched,
					IntroducedBy:             &attribution.Result{Source: attribution.SourceSidecar, Confidence: attribution.ConfidenceHigh, PRNumber: 17, Author: "octocat"},
					AutonomyTier:             "tier_4_prod_privileged_or_customer_impacting",
					DelegationReadinessState: "approval_required",
					RecommendedControl:       "approval_required",
				}},
			},
		},
		GeneratedAt: time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("build summary: %v", err)
	}
	if summary.WorkflowChains == nil || len(summary.WorkflowChains.Chains) == 0 {
		t.Fatalf("expected workflow chains on summary, got %+v", summary.WorkflowChains)
	}
	if len(summary.ActionPaths) != 1 || len(summary.ActionPaths[0].WorkflowChainRefs) == 0 {
		t.Fatalf("expected workflow chain refs on action paths, got %+v", summary.ActionPaths)
	}
	if summary.AgentActionBOM == nil || len(summary.AgentActionBOM.Items) != 1 || len(summary.AgentActionBOM.Items[0].WorkflowChainRefs) == 0 {
		t.Fatalf("expected workflow chain refs on BOM items, got %+v", summary.AgentActionBOM)
	}
}

func TestSanitizeWorkflowChainsPublicRedactsSummaryRollups(t *testing.T) {
	t.Parallel()

	input := &agentresolver.WorkflowChainArtifact{
		Version: agentresolver.WorkflowChainVersion,
		Summary: agentresolver.WorkflowChainSummary{
			TotalChains: 1,
			Repos: []agentresolver.WorkflowChainRollup{
				{Value: "acme/release", Count: 1},
			},
			Workflows: []agentresolver.WorkflowChainRollup{
				{Value: ".github/workflows/release.yml", Count: 1},
			},
			AutonomyTiers: []agentresolver.WorkflowChainRollup{
				{Value: "tier_4_prod_privileged_or_customer_impacting", Count: 1},
			},
		},
	}

	redacted := sanitizeWorkflowChainsPublic(input)
	if redacted == nil {
		t.Fatal("expected redacted workflow chains")
	}
	if redacted.Summary.Repos[0].Value == input.Summary.Repos[0].Value {
		t.Fatalf("expected repo summary rollup to redact, got %+v", redacted.Summary.Repos)
	}
	if redacted.Summary.Workflows[0].Value == input.Summary.Workflows[0].Value {
		t.Fatalf("expected workflow summary rollup to redact, got %+v", redacted.Summary.Workflows)
	}
	if redacted.Summary.AutonomyTiers[0].Value != input.Summary.AutonomyTiers[0].Value {
		t.Fatalf("expected enum rollup to remain visible, got %+v", redacted.Summary.AutonomyTiers)
	}
}

func TestSanitizeWorkflowChainsWithConfigRedactsSummaryRollups(t *testing.T) {
	t.Parallel()

	input := &agentresolver.WorkflowChainArtifact{
		Version: agentresolver.WorkflowChainVersion,
		Summary: agentresolver.WorkflowChainSummary{
			TotalChains: 1,
			Repos: []agentresolver.WorkflowChainRollup{
				{Value: "acme/release", Count: 1},
			},
			Workflows: []agentresolver.WorkflowChainRollup{
				{Value: ".github/workflows/release.yml", Count: 1},
			},
		},
	}

	config := ResolveRedactionConfig(ShareProfileInternal, []RedactionField{RedactionRepos, RedactionPaths})
	redacted := sanitizeWorkflowChainsWithConfig(input, config)
	if redacted == nil {
		t.Fatal("expected redacted workflow chains")
	}
	if redacted.Summary.Repos[0].Value == input.Summary.Repos[0].Value {
		t.Fatalf("expected repo summary rollup to redact with config, got %+v", redacted.Summary.Repos)
	}
	if redacted.Summary.Workflows[0].Value == input.Summary.Workflows[0].Value {
		t.Fatalf("expected workflow summary rollup to redact with config, got %+v", redacted.Summary.Workflows)
	}
}
