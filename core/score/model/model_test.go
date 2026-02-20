package model

import "testing"

func TestDefaultWeightsValidate(t *testing.T) {
	t.Parallel()
	weights := DefaultWeights()
	if err := weights.Validate(); err != nil {
		t.Fatalf("default weights must validate: %v", err)
	}
}

func TestGradeBands(t *testing.T) {
	t.Parallel()
	cases := []struct {
		score float64
		want  string
	}{
		{95, "A"},
		{85, "B"},
		{75, "C"},
		{65, "D"},
		{55, "F"},
	}
	for _, tc := range cases {
		if got := Grade(tc.score); got != tc.want {
			t.Fatalf("grade(%v): got %s want %s", tc.score, got, tc.want)
		}
	}
}
