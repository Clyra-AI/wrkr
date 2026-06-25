package regress

import (
	"testing"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
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

func TestLegacyBaselineMatchKeyStillMatchesCurrentResolutionKeyPath(t *testing.T) {
	t.Parallel()

	legacyPath := risk.ActionPath{
		PathID:                  "apc-old",
		Org:                     "acme",
		Repo:                    "acme/release",
		ToolType:                "compiled_action",
		Location:                ".github/workflows/release.yml",
		WriteCapable:            true,
		DeployWrite:             true,
		ProductionWrite:         true,
		ApprovalGap:             true,
		ActionPathType:          "ci_cd_workflow",
		TargetClass:             risk.TargetClassProductionImpacting,
		BoundaryLabel:           "approval_capable",
		ControlResolutionState:  risk.ControlResolutionStateDetectedControl,
		ApprovalEvidenceState:   risk.EvidenceStateUnknown,
		OwnerEvidenceState:      risk.EvidenceStateVerified,
		ProofEvidenceState:      risk.EvidenceStateVerified,
		RuntimeEvidenceState:    risk.EvidenceStateUnknown,
		TargetEvidenceState:     risk.EvidenceStateVerified,
		CredentialEvidenceState: risk.EvidenceStateVerified,
		ActionClasses:           []string{"deploy"},
		CredentialProvenance:    &agginventory.CredentialProvenance{Subject: "prod-release-token"},
	}
	baselineState := newActionPathState(legacyPath)
	baselineState.ResolutionKey = ""
	baseline := Baseline{
		Version:             BaselineVersion,
		GeneratedAt:         "2026-06-25T12:00:00Z",
		ActionPathsCaptured: true,
		ActionPaths:         []ActionPathState{baselineState},
	}

	current := state.Snapshot{
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:                  "apc-new",
				Org:                     "acme",
				Repo:                    "acme/release",
				ToolType:                "compiled_action",
				Location:                ".github/workflows/release.yml",
				WriteCapable:            true,
				ProductionWrite:         true,
				ApprovalGap:             true,
				ActionPathType:          "ci_cd_workflow",
				TargetClass:             risk.TargetClassProductionImpacting,
				BoundaryLabel:           "approval_capable",
				ControlResolutionState:  risk.ControlResolutionStateDetectedControl,
				ApprovalEvidenceState:   risk.EvidenceStateUnknown,
				OwnerEvidenceState:      risk.EvidenceStateVerified,
				ProofEvidenceState:      risk.EvidenceStateVerified,
				RuntimeEvidenceState:    risk.EvidenceStateUnknown,
				TargetEvidenceState:     risk.EvidenceStateVerified,
				CredentialEvidenceState: risk.EvidenceStateVerified,
				ActionClasses:           []string{"deploy"},
				CredentialProvenance:    &agginventory.CredentialProvenance{Subject: "prod-release-token"},
				ResolutionKey:           "rk-release",
			}},
		},
	}

	categories, status, issues := compareActionPathDrift(baseline, current)
	if status != DriftComparisonStatusOK {
		t.Fatalf("expected legacy match_key comparison to stay ok, status=%q issues=%v categories=%+v", status, issues, categories)
	}
	if len(categories) != 0 {
		t.Fatalf("expected no drift for equivalent legacy match_key path, got %+v", categories)
	}
}
