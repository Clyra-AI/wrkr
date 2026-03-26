package fixintegration

import (
	"encoding/json"
	"strings"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/fix"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestIntegrationBuildPlanProducesTopThreeDeterministicRemediations(t *testing.T) {
	t.Parallel()

	ranked := []risk.ScoredFinding{
		{Score: 9.8, Finding: model.Finding{FindingType: "policy_violation", RuleID: "WRKR-004", ToolType: "ci", Location: ".github/workflows/pr.yml", Repo: "backend", Org: "acme"}, Reasons: []string{"autonomy_multiplier=1.3"}},
		{Score: 9.4, Finding: model.Finding{FindingType: "skill_policy_conflict", ToolType: "skill", Location: ".agents/skills/release/SKILL.md", Repo: "backend", Org: "acme"}, Reasons: []string{"skill_policy_conflict_high_severity"}},
		{Score: 8.7, Finding: model.Finding{FindingType: "ai_dependency", ToolType: "dependency", Location: "go.mod", Repo: "backend", Org: "acme"}, Reasons: []string{"trust_deficit=2.1"}},
		{Score: 8.1, Finding: model.Finding{FindingType: "mcp_server", ToolType: "mcp", Location: ".codex/config.toml", Repo: "backend", Org: "acme"}, Reasons: []string{"blast_radius=4.5"}},
	}

	planA, err := fix.BuildPlan(ranked, 3)
	if err != nil {
		t.Fatalf("build plan A: %v", err)
	}
	planB, err := fix.BuildPlan(ranked, 3)
	if err != nil {
		t.Fatalf("build plan B: %v", err)
	}
	if len(planA.Remediations) != 3 {
		t.Fatalf("expected 3 remediations, got %d", len(planA.Remediations))
	}
	for _, item := range planA.Remediations {
		if item.PatchPreview == "" {
			t.Fatalf("expected patch preview for %+v", item)
		}
		if item.CommitMessage == "" {
			t.Fatalf("expected commit message for %+v", item)
		}
	}

	blobA, _ := json.Marshal(planA)
	blobB, _ := json.Marshal(planB)
	if string(blobA) != string(blobB) {
		t.Fatalf("expected deterministic plan output\nA=%s\nB=%s", blobA, blobB)
	}
}

func TestIntegrationUnsupportedFindingsReturnReasonCodes(t *testing.T) {
	t.Parallel()

	ranked := []risk.ScoredFinding{
		{Score: 9.9, Finding: model.Finding{FindingType: "unknown", ToolType: "misc", Location: "README.md", Repo: "backend", Org: "acme"}},
	}
	plan, err := fix.BuildPlan(ranked, 1)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}
	if len(plan.Remediations) != 0 {
		t.Fatalf("expected no remediations, got %d", len(plan.Remediations))
	}
	if len(plan.Skipped) != 1 {
		t.Fatalf("expected one skipped finding, got %d", len(plan.Skipped))
	}
	if plan.Skipped[0].ReasonCode != fix.ReasonUnsupportedFindingType {
		t.Fatalf("expected unsupported reason code, got %+v", plan.Skipped[0])
	}
}

func TestIntegrationBuildApplyArtifactsProducesManifestFile(t *testing.T) {
	t.Parallel()

	now := "2026-03-26T12:00:00Z"
	snapshot := state.Snapshot{
		Version: state.SnapshotVersion,
		Target:  source.Target{Mode: "repo", Value: "acme/backend"},
		Inventory: &agginventory.Inventory{
			Org: "acme",
			Tools: []agginventory.Tool{
				{
					ToolID:          "codex-config",
					AgentID:         "wrkr:codex-config:acme",
					ToolType:        "codex",
					Org:             "acme",
					DiscoveryMethod: "static",
					EndpointClass:   "fs.read",
					DataClass:       "source_code",
					AutonomyLevel:   "interactive",
					RiskScore:       7.7,
					ApprovalStatus:  "missing",
					ApprovalClass:   "under_review",
					LifecycleState:  "discovered",
					Locations: []agginventory.ToolLocation{
						{Repo: "backend", Location: ".codex/config.toml"},
					},
				},
			},
		},
		Identities: []manifest.IdentityRecord{
			{
				AgentID:       "wrkr:codex-config:acme",
				ToolID:        "codex-config",
				ToolType:      "codex",
				Org:           "acme",
				Repo:          "backend",
				Location:      ".codex/config.toml",
				Status:        "discovered",
				ApprovalState: "missing",
				FirstSeen:     now,
				LastSeen:      now,
				Present:       true,
				DataClass:     "source_code",
				EndpointClass: "fs.read",
				AutonomyLevel: "interactive",
				RiskScore:     7.7,
			},
		},
		RiskReport: &risk.Report{GeneratedAt: now},
	}
	plan := fix.Plan{
		RequestedTop: 1,
		Remediations: []fix.Remediation{
			{
				ID:             "apply-manifest",
				TemplateID:     "MANIFEST-GENERATE",
				Category:       "manifest_generation",
				ApplySupported: true,
				CommitMessage:  "fix(manifest): regenerate manifest",
				Finding:        model.Finding{FindingType: "tool_config", ToolType: "codex", Location: ".codex/config.toml", Repo: "backend", Org: "acme"},
			},
		},
	}

	artifacts, err := fix.BuildApplyArtifacts(snapshot, plan)
	if err != nil {
		t.Fatalf("build apply artifacts: %v", err)
	}
	if len(artifacts) != 1 {
		t.Fatalf("expected one apply artifact, got %d", len(artifacts))
	}
	if artifacts[0].Path != ".wrkr/wrkr-manifest.yaml" {
		t.Fatalf("unexpected apply artifact path %q", artifacts[0].Path)
	}
	if !strings.Contains(string(artifacts[0].Content), "agent_id: wrkr:codex-config:acme") {
		t.Fatalf("unexpected apply manifest content: %s", artifacts[0].Content)
	}
}
