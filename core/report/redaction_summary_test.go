package report

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestSanitizeComposedActionPathsPublicKeepsTransitionStageRefsAligned(t *testing.T) {
	t.Parallel()

	input := []risk.ComposedActionPath{{
		CompositionID: "cap-1",
		Stages: []risk.CompositionStage{
			{StageID: "stage-source", Role: risk.CompositionStageRoleSource},
			{StageID: "stage-sink", Role: risk.CompositionStageRoleExternalSink},
		},
		Transitions: []risk.CompositionTransition{{
			TransitionID: "transition-1",
			FromStageID:  "stage-source",
			ToStageID:    "stage-sink",
		}},
	}}

	checkAlignment := func(paths []risk.ComposedActionPath) {
		t.Helper()
		if len(paths) != 1 || len(paths[0].Transitions) != 1 {
			t.Fatalf("expected one sanitized composition transition, got %+v", paths)
		}
		stageSet := map[string]struct{}{}
		for _, stage := range paths[0].Stages {
			stageSet[stage.StageID] = struct{}{}
		}
		transition := paths[0].Transitions[0]
		if _, ok := stageSet[transition.FromStageID]; !ok {
			t.Fatalf("expected from_stage_id %q to match a sanitized stage id, got %+v", transition.FromStageID, paths[0])
		}
		if _, ok := stageSet[transition.ToStageID]; !ok {
			t.Fatalf("expected to_stage_id %q to match a sanitized stage id, got %+v", transition.ToStageID, paths[0])
		}
	}

	checkAlignment(sanitizeComposedActionPathsPublic(input))
	checkAlignment(sanitizeComposedActionPathsWithConfig(input, ResolveRedactionConfig(ShareProfileInternal, []RedactionField{RedactionPaths})))
}
