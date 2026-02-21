package action

import (
	"testing"

	coreaction "github.com/Clyra-AI/wrkr/core/action"
	"github.com/Clyra-AI/wrkr/core/action/changes"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestDocsOnlyPRE2EDoesNotTriggerComment(t *testing.T) {
	t.Parallel()

	docsOnly := []string{"README.md", "docs/usage.md"}
	if changes.HasRelevantChanges(docsOnly) {
		t.Fatal("expected docs-only PR to skip action comments")
	}
}

func TestAIConfigChangeE2ETriggersComment(t *testing.T) {
	t.Parallel()

	paths := []string{"README.md", ".codex/config.toml"}
	if !changes.HasRelevantChanges(paths) {
		t.Fatal("expected AI config path to trigger action comments")
	}
}

func TestPRModeE2ECommentsOnlyForRelevantChanges(t *testing.T) {
	t.Parallel()

	docsOnly := coreaction.RunPRMode(coreaction.PRModeInput{
		ChangedPaths:    []string{"README.md", "docs/usage.md"},
		RiskDelta:       4.0,
		ComplianceDelta: -1.5,
		BlockThreshold:  5.0,
	})
	if docsOnly.ShouldComment {
		t.Fatalf("expected docs-only PR to suppress comment, got %+v", docsOnly)
	}

	relevant := coreaction.RunPRMode(coreaction.PRModeInput{
		ChangedPaths:    []string{"README.md", ".codex/config.toml"},
		RiskDelta:       6.1,
		ComplianceDelta: -3.2,
		BlockThreshold:  6.0,
	})
	if !relevant.ShouldComment {
		t.Fatalf("expected relevant changes to trigger comment, got %+v", relevant)
	}
	if !relevant.BlockMerge {
		t.Fatalf("expected threshold breach to block merge, got %+v", relevant)
	}
}

func TestScheduledModeE2EIncludesDeterministicDeltas(t *testing.T) {
	t.Parallel()

	snapshot := state.Snapshot{
		Profile:      &profileeval.Result{CompliancePercent: 92.75, DeltaPercent: -2.25},
		PostureScore: &score.Result{Score: 81.40, TrendDelta: +1.60},
	}
	result := coreaction.RunScheduled(snapshot)
	if result.ScoreDeltaText != "posture score delta +1.60 (current 81.40)" {
		t.Fatalf("unexpected score delta text: %q", result.ScoreDeltaText)
	}
	if result.ComplianceDeltaText != "profile compliance delta -2.25% (current 92.75%)" {
		t.Fatalf("unexpected compliance delta text: %q", result.ComplianceDeltaText)
	}
}
