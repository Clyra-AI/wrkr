package attackpath

import (
	"reflect"
	"testing"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
)

func TestScoreDeterministicOrdering(t *testing.T) {
	t.Parallel()

	graphs := []aggattack.Graph{
		{
			Org:  "acme",
			Repo: "repo",
			Nodes: []aggattack.Node{
				{NodeID: "entry::prompt_channel_untrusted_context::prompt_channel::.github/workflows/release.yml", Kind: "entry", FindingType: "prompt_channel_untrusted_context", CanonicalKey: "entry"},
				{NodeID: "pivot::ci_autonomy::ci_agent::.github/workflows/release.yml", Kind: "pivot", FindingType: "ci_autonomy", CanonicalKey: "pivot"},
				{NodeID: "target::secret_presence::secret::.env", Kind: "target", FindingType: "secret_presence", CanonicalKey: "target"},
			},
			Edges: []aggattack.Edge{
				{FromNodeID: "entry::prompt_channel_untrusted_context::prompt_channel::.github/workflows/release.yml", ToNodeID: "pivot::ci_autonomy::ci_agent::.github/workflows/release.yml", Rationale: "entry_to_pivot"},
				{FromNodeID: "pivot::ci_autonomy::ci_agent::.github/workflows/release.yml", ToNodeID: "target::secret_presence::secret::.env", Rationale: "pivot_to_target"},
			},
		},
	}

	first := Score(graphs)
	if len(first) != 1 {
		t.Fatalf("expected one scored path, got %d", len(first))
	}
	if first[0].PathScore <= 0 {
		t.Fatalf("expected positive path score, got %.2f", first[0].PathScore)
	}

	for i := 0; i < 32; i++ {
		next := Score(graphs)
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("non-deterministic path scoring at run %d", i+1)
		}
	}
}
