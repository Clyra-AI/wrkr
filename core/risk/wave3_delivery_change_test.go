package risk

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/attribution"
)

func TestProjectActionPathBuildsAgenticDeliverySystemChange(t *testing.T) {
	t.Parallel()

	path := ProjectActionPath(ActionPath{
		PathID:             "apc-skill-release",
		Org:                "acme",
		Repo:               "acme/platform",
		ToolType:           "skill",
		Location:           ".agents/skills/release/SKILL.md",
		WriteCapable:       true,
		DeployWrite:        true,
		CredentialAccess:   true,
		ApprovalGap:        true,
		ApprovalGapReasons: []string{"approval_source_missing"},
		RecommendedControl: RecommendedControlApprovalRequired,
		ControlPriority:    ControlPriorityControlFirst,
		HighStakesPresets:  []HighStakesPreset{{Preset: HighStakesPresetReleaseAutomation}},
		MatchedProductionTargets: []string{
			"prod-release",
		},
	})

	if path.AgenticDeliverySystemChange == nil {
		t.Fatalf("expected agentic delivery change, got %+v", path)
	}
	change := path.AgenticDeliverySystemChange
	if change.SurfaceType != AgenticDeliverySurfaceSkillpack {
		t.Fatalf("expected skillpack surface, got %+v", change)
	}
	if change.AuthorityImpact != AgenticAuthorityImpactRelease {
		t.Fatalf("expected release authority impact, got %+v", change)
	}
	if change.ReviewState != AgenticReviewStateMissing {
		t.Fatalf("expected missing review state, got %+v", change)
	}
	if !change.HighImpact {
		t.Fatalf("expected high-impact change, got %+v", change)
	}
	if change.RecommendedControl == "" {
		t.Fatalf("expected recommended control carry-through, got %+v", change)
	}
}

func TestProjectActionPathDerivesReviewBypassRiskFromProvenance(t *testing.T) {
	t.Parallel()

	path := ProjectActionPath(ActionPath{
		PathID:       "apc-bypass-risk",
		Org:          "acme",
		Repo:         "acme/release",
		ToolType:     "codex",
		Location:     ".codex/config.toml",
		WriteCapable: true,
		MergeExecute: true,
		IntroducedBy: &attribution.Result{
			Confidence: "high",
			Reference:  "pr/42",
			Provenance: &attribution.Provenance{
				ConflictState:     "partial",
				MissingEvidence:   []string{"branch_protection_missing", "checks_missing"},
				BranchProtections: nil,
			},
		},
	})

	if path.AgenticDeliverySystemChange == nil {
		t.Fatalf("expected agentic delivery change, got %+v", path)
	}
	change := path.AgenticDeliverySystemChange
	if change.ReviewState != AgenticReviewStateBypassRisk {
		t.Fatalf("expected review bypass risk, got %+v", change)
	}
	if change.AuthorityImpact != AgenticAuthorityImpactReviewBypass {
		t.Fatalf("expected review-bypass authority impact, got %+v", change)
	}
}

func TestInstructionSurfaceWithReachableAuthorityOutranksBareInstructionChange(t *testing.T) {
	t.Parallel()

	paths := ProjectActionPaths([]ActionPath{
		{
			PathID:   "apc-bare-instruction",
			Org:      "acme",
			Repo:     "acme/release",
			ToolType: "prompt_channel",
			Location: "AGENTS.md",
		},
		{
			PathID:           "apc-release-skill",
			Org:              "acme",
			Repo:             "acme/release",
			ToolType:         "skill",
			Location:         ".agents/skills/release/SKILL.md",
			WriteCapable:     true,
			DeployWrite:      true,
			CredentialAccess: true,
			ApprovalGap:      true,
			ApprovalGapReasons: []string{
				"approval_source_missing",
			},
			HighStakesPresets: []HighStakesPreset{{Preset: HighStakesPresetReleaseAutomation}},
		},
	})

	if len(paths) != 2 {
		t.Fatalf("expected two projected paths, got %+v", paths)
	}
	if paths[0].PathID != "apc-release-skill" {
		t.Fatalf("expected release skill to outrank bare instruction change, got %+v", paths)
	}
	if paths[1].AgenticDeliverySystemChange == nil {
		t.Fatalf("expected lower-ranked instruction path to retain agentic projection, got %+v", paths[1])
	}
}
