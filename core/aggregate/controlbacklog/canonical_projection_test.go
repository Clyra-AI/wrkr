package controlbacklog

import (
	"fmt"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
)

func TestStripCanonicalProjectionDetailsDoesNotMutateNestedEvidenceRefs(t *testing.T) {
	contradictionRefs := makeBacklogEvidenceRefs("contradiction", 80)
	recipeRefs := makeBacklogEvidenceRefs("recipe", 80)
	backlog := &Backlog{Items: []Item{{
		ID: "gap-mutation",
		Contradictions: []evidencepolicy.Contradiction{{
			Class:        "target",
			EvidenceRefs: contradictionRefs,
		}},
		SecurityTestRecipes: []SecurityTestRecipe{{
			ID:           "test-mutation",
			EvidenceRefs: recipeRefs,
		}},
	}}}

	stripped := StripCanonicalProjectionDetails(backlog)

	if got, want := len(stripped.Items[0].Contradictions[0].EvidenceRefs), maxBacklogOutputEvidenceRefs; got != want {
		t.Fatalf("expected stripped contradiction refs to be capped, got %d want %d", got, want)
	}
	if got, want := len(stripped.Items[0].SecurityTestRecipes[0].EvidenceRefs), maxBacklogOutputEvidenceRefs; got != want {
		t.Fatalf("expected stripped security-test refs to be capped, got %d want %d", got, want)
	}
	if got, want := len(backlog.Items[0].Contradictions[0].EvidenceRefs), len(contradictionRefs); got != want {
		t.Fatalf("expected source contradiction refs to stay intact, got %d want %d", got, want)
	}
	if got, want := len(backlog.Items[0].SecurityTestRecipes[0].EvidenceRefs), len(recipeRefs); got != want {
		t.Fatalf("expected source security-test refs to stay intact, got %d want %d", got, want)
	}
}

func makeBacklogEvidenceRefs(prefix string, count int) []string {
	refs := make([]string, 0, count)
	for idx := 0; idx < count; idx++ {
		refs = append(refs, fmt.Sprintf("%s-ref-%03d", prefix, idx))
	}
	return refs
}
