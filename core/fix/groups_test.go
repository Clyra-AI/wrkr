package fix

import "testing"

func TestSplitPlanForPRsUsesEmittedGroupCountAsTotal(t *testing.T) {
	t.Parallel()

	plan := Plan{
		Remediations: []Remediation{
			{ID: "fix-1"},
			{ID: "fix-2"},
			{ID: "fix-3"},
			{ID: "fix-4"},
		},
	}

	groups := SplitPlanForPRs(plan, 3)
	if len(groups) != 2 {
		t.Fatalf("expected two groups, got %d", len(groups))
	}

	for idx, group := range groups {
		if group.Index != idx {
			t.Fatalf("expected group index %d, got %d", idx, group.Index)
		}
		if group.Total != len(groups) {
			t.Fatalf("expected group total %d, got %d", len(groups), group.Total)
		}
	}
	if len(groups[0].Plan.Remediations) != 2 || len(groups[1].Plan.Remediations) != 2 {
		t.Fatalf("expected even deterministic split, got %d and %d", len(groups[0].Plan.Remediations), len(groups[1].Plan.Remediations))
	}
}
