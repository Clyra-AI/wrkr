package regress

import (
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestRemovedImportedBranchProtectionReopensControlGap(t *testing.T) {
	t.Parallel()

	baseline := BuildBaseline(state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:                       "apc-release-old",
				Org:                          "acme",
				Repo:                         "acme/release",
				ToolType:                     "compiled_action",
				Location:                     ".github/workflows/release.yml",
				WriteCapable:                 true,
				ProductionWrite:              true,
				ApprovalGap:                  false,
				ActionClasses:                []string{"deploy"},
				TargetClass:                  risk.TargetClassProductionImpacting,
				ResolutionKey:                "rk-release",
				ControlResolutionState:       risk.ControlResolutionStateExternalControlReference,
				ApprovalEvidenceState:        risk.EvidenceStateVerified,
				ReviewLifecycleState:         risk.ReviewLifecycleStateCoveredByImportedControl,
				ControlEvidenceRefs:          []string{"provider://github/branch-protection/release"},
				ResolvedVisibility:           risk.ReviewResolvedVisibilityAppendix,
				PreviousReviewLifecycleState: "",
			}},
		},
	}, time.Time{})

	current := state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:                       "apc-release-new",
				Org:                          "acme",
				Repo:                         "acme/release",
				ToolType:                     "compiled_action",
				Location:                     ".github/workflows/release.yml",
				WriteCapable:                 true,
				ProductionWrite:              true,
				ApprovalGap:                  true,
				ActionClasses:                []string{"deploy"},
				TargetClass:                  risk.TargetClassProductionImpacting,
				ResolutionKey:                "rk-release",
				ControlResolutionState:       risk.ControlResolutionStateNoVisibleControl,
				ApprovalEvidenceState:        risk.EvidenceStateUnknown,
				ReviewLifecycleState:         risk.ReviewLifecycleStateReopenedByDrift,
				PreviousReviewLifecycleState: risk.ReviewLifecycleStateCoveredByImportedControl,
				ReopenState:                  risk.ReviewReopenStateReopened,
				ReopenReasons:                []string{"imported_control_disappeared"},
				ReopenEvidenceRefs:           []string{"provider://github/branch-protection/release"},
				ResolvedVisibility:           risk.ReviewResolvedVisibilityPrimary,
			}},
		},
	}

	categories, status, issues := compareActionPathDrift(baseline, current)
	if status != DriftComparisonStatusOK {
		t.Fatalf("expected imported-control reopen drift comparison to stay healthy, status=%q issues=%v categories=%+v", status, issues, categories)
	}
	if len(categories) == 0 {
		t.Fatalf("expected removed imported control to surface as drift, got %+v", categories)
	}
}
