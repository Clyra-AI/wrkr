package risk

import "testing"

func TestBuildClosureActionsForGovernedCIIncludesConcreteImports(t *testing.T) {
	t.Parallel()

	actions := BuildClosureActionsForPath(ActionPath{
		PathID:                "apc-governed",
		ResolutionKey:         "rk-governed",
		Repo:                  "acme/payments",
		Location:              ".github/workflows/release.yml",
		ActionPathEligible:    true,
		ActionPathType:        ActionPathTypeCICDWorkflow,
		CIFlowClass:           CIFlowClassStandardGovernedCI,
		ApprovalEvidenceState: EvidenceStateUnknown,
		TargetClass:           TargetClassReleaseAdjacent,
		ProductionWrite:       true,
		ControlPriority:       ControlPriorityControlFirst,
		RecommendedControl:    RecommendedControlAllow,
	})

	if !hasClosureAction(actions, ClosureActionImportPRReviewEvidence) {
		t.Fatalf("expected PR review import closure action, got %+v", actions)
	}
	if !hasClosureAction(actions, ClosureActionImportBranchProtection) {
		t.Fatalf("expected branch protection closure action, got %+v", actions)
	}
	if !hasClosureAction(actions, ClosureActionImportEnvironmentApproval) {
		t.Fatalf("expected environment approval closure action, got %+v", actions)
	}
}

func TestBuildClosureActionsIncludesReviewDispositionExports(t *testing.T) {
	t.Parallel()

	actions := BuildClosureActionsForPath(ActionPath{
		PathID:                 "apc-review",
		ResolutionKey:          "rk-review",
		Repo:                   "acme/app",
		ToolType:               "codex",
		Location:               ".codex/config.toml",
		ActionPathEligible:     true,
		ActionPathType:         ActionPathTypeAgentInstruction,
		ControlPriority:        ControlPriorityControlFirst,
		ControlResolutionState: ControlResolutionStateNoVisibleControl,
		ApprovalEvidenceState:  EvidenceStateUnknown,
		RecommendedControl:     RecommendedControlApprovalRequired,
		ConfidenceLane:         ConfidenceLaneConfirmedActionPath,
	})

	if !hasClosureAction(actions, ClosureActionAcceptRiskWithExpiry) {
		t.Fatalf("expected accepted-risk closure action, got %+v", actions)
	}
	if !hasClosureAction(actions, ClosureActionMarkFalsePositive) {
		t.Fatalf("expected false-positive closure action, got %+v", actions)
	}
}

func hasClosureAction(actions []ClosureAction, actionType string) bool {
	for _, action := range actions {
		if action.ActionType == actionType {
			return true
		}
	}
	return false
}
