package model

import "testing"

func TestIsIdentityBearingFinding(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   Finding
		want bool
	}{
		{
			name: "regular finding with tool type",
			in: Finding{
				FindingType: "source_discovery",
				ToolType:    "source_repo",
			},
			want: true,
		},
		{
			name: "policy check excluded",
			in: Finding{
				FindingType: "policy_check",
				ToolType:    "policy",
			},
			want: false,
		},
		{
			name: "policy violation excluded",
			in: Finding{
				FindingType: "policy_violation",
				ToolType:    "policy",
			},
			want: false,
		},
		{
			name: "parse error excluded",
			in: Finding{
				FindingType: "parse_error",
				ToolType:    "yaml",
			},
			want: false,
		},
		{
			name: "skill metrics excluded",
			in: Finding{
				FindingType: "skill_metrics",
				ToolType:    "skill",
			},
			want: false,
		},
		{
			name: "project signal excluded",
			in: Finding{
				FindingType: "ai_project_signal",
				ToolType:    "dependency",
			},
			want: false,
		},
		{
			name: "missing tool type excluded",
			in: Finding{
				FindingType: "source_discovery",
			},
			want: false,
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsIdentityBearingFinding(tc.in); got != tc.want {
				t.Fatalf("unexpected classifier result: got=%v want=%v finding=%+v", got, tc.want, tc.in)
			}
		})
	}
}

func TestIdentityBearing_ExcludesCorrelationOnlyFindings(t *testing.T) {
	t.Parallel()

	for _, findingType := range []string{"ai_project_signal", "skill_metrics", "skill_contribution", "mcp_gateway_posture"} {
		findingType := findingType
		t.Run(findingType, func(t *testing.T) {
			t.Parallel()
			if IsIdentityBearingFinding(Finding{FindingType: findingType, ToolType: "skill"}) {
				t.Fatalf("expected %s to be non-identity-bearing", findingType)
			}
		})
	}
}

func TestIsInventoryBearingFinding(t *testing.T) {
	t.Parallel()

	if !IsInventoryBearingFinding(Finding{FindingType: "tool_config", ToolType: "codex"}) {
		t.Fatal("expected canonical finding to be inventory-bearing")
	}
	if IsInventoryBearingFinding(Finding{FindingType: "skill_metrics", ToolType: "skill"}) {
		t.Fatal("expected skill_metrics to be excluded from inventory-bearing classification")
	}
}
