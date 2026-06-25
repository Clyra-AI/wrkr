package regress

import (
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestResolutionKeyDriftMatchingSurvivesPathIDChurn(t *testing.T) {
	t.Parallel()

	baseline := BuildBaseline(state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:                 "apc-old",
				Org:                    "acme",
				Repo:                   "acme/release",
				ToolType:               "compiled_action",
				Location:               ".github/workflows/release.yml",
				WriteCapable:           true,
				ActionClasses:          []string{"deploy"},
				ResolutionKey:          "rk-release",
				ApprovalGap:            true,
				TargetClass:            risk.TargetClassProductionImpacting,
				ControlResolutionState: risk.ControlResolutionStateNoVisibleControl,
			}},
		},
	}, time.Time{})

	current := state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:                 "apc-new",
				Org:                    "acme",
				Repo:                   "acme/release",
				ToolType:               "compiled_action",
				Location:               ".github/workflows/release-renamed.yml",
				WriteCapable:           true,
				ActionClasses:          []string{"deploy"},
				ResolutionKey:          "rk-release",
				ApprovalGap:            true,
				TargetClass:            risk.TargetClassProductionImpacting,
				ControlResolutionState: risk.ControlResolutionStateNoVisibleControl,
			}},
		},
	}

	categories, status, issues := compareActionPathDrift(baseline, current)
	if status != DriftComparisonStatusOK {
		t.Fatalf("expected resolution-key churn to compare cleanly, status=%q issues=%v categories=%+v", status, issues, categories)
	}
	if len(categories) != 0 {
		t.Fatalf("expected no drift categories when only path_id churned, got %+v", categories)
	}
}
