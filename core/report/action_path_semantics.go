package report

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/risk"
)

func bomItemEligible(item AgentActionBOMItem) bool {
	if item.ActionPathEligible {
		return true
	}
	if strings.TrimSpace(item.ActionBindingState) != "" {
		return item.ActionPathEligible
	}
	if strings.TrimSpace(item.ExclusionReason) != "" {
		return false
	}
	return strings.TrimSpace(item.ConfidenceLane) != risk.ConfidenceLaneContextOnly
}

func bomItemBindingState(item AgentActionBOMItem) string {
	if strings.TrimSpace(item.ActionBindingState) != "" {
		return strings.TrimSpace(item.ActionBindingState)
	}
	if bomItemEligible(item) {
		if strings.TrimSpace(item.ConfidenceLane) == risk.ConfidenceLaneSemanticReviewCandidate {
			return risk.ActionBindingStatePartiallyBound
		}
		return risk.ActionBindingStateBound
	}
	return risk.ActionBindingStateUnboundContext
}
