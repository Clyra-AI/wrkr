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
