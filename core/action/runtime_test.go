package action

import (
	"testing"

	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestRunScheduledDeterministicSummary(t *testing.T) {
	t.Parallel()

	snapshot := state.Snapshot{
		Profile:      &profileeval.Result{CompliancePercent: 91.25, DeltaPercent: -1.75},
		PostureScore: &score.Result{Score: 83.40, TrendDelta: 2.10},
	}
	first := RunScheduled(snapshot)
	second := RunScheduled(snapshot)

	if first != second {
		t.Fatalf("expected deterministic scheduled result\nfirst=%+v\nsecond=%+v", first, second)
	}
	if first.ScoreDeltaText != "posture score delta +2.10 (current 83.40)" {
		t.Fatalf("unexpected score delta text: %q", first.ScoreDeltaText)
	}
	if first.ComplianceDeltaText != "profile compliance delta -1.75% (current 91.25%)" {
		t.Fatalf("unexpected compliance delta text: %q", first.ComplianceDeltaText)
	}
}

func TestRunPRModeCommentsOnlyForRelevantChanges(t *testing.T) {
	t.Parallel()

	noComment := RunPRMode(PRModeInput{ChangedPaths: []string{"README.md", "docs/usage.md"}, RiskDelta: 4.5, ComplianceDelta: -3.0, BlockThreshold: 5.0})
	if noComment.ShouldComment {
		t.Fatalf("expected docs-only changes to suppress comments, got %+v", noComment)
	}

	comment := RunPRMode(PRModeInput{ChangedPaths: []string{"README.md", ".codex/config.toml"}, RiskDelta: 6.2, ComplianceDelta: -4.5, BlockThreshold: 6.0})
	if !comment.ShouldComment {
		t.Fatalf("expected comment for AI config changes, got %+v", comment)
	}
	if !comment.BlockMerge {
		t.Fatalf("expected block merge when threshold crossed, got %+v", comment)
	}
}
