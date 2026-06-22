package risk

import (
	"fmt"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
)

func TestCloneProductionContextPreservesCaseSensitiveEndpointOperations(t *testing.T) {
	ctx := CloneProductionContext(&ProductionContext{
		MutableEndpointOperations: []string{
			"POST /v1/Users",
			"POST /v1/users",
			" POST /v1/Users ",
		},
	})

	if got, want := len(ctx.MutableEndpointOperations), 2; got != want {
		t.Fatalf("expected case-sensitive endpoint operations to be preserved and exact duplicates removed, got %d want %d: %#v", got, want, ctx.MutableEndpointOperations)
	}
	if ctx.MutableEndpointOperations[0] != "POST /v1/Users" || ctx.MutableEndpointOperations[1] != "POST /v1/users" {
		t.Fatalf("unexpected endpoint operation order/content: %#v", ctx.MutableEndpointOperations)
	}
}

func TestStripCanonicalProjectionDetailsDoesNotMutateContradictionRefs(t *testing.T) {
	refs := makeEvidenceRefs(80)
	paths := []ActionPath{{
		PathID: "apc-mutation",
		Contradictions: []evidencepolicy.Contradiction{{
			Class:        "target",
			EvidenceRefs: refs,
		}},
	}}

	stripped := StripCanonicalProjectionDetails(paths)

	if got, want := len(stripped[0].Contradictions[0].EvidenceRefs), maxOutputEvidenceRefs; got != want {
		t.Fatalf("expected stripped contradiction refs to be capped, got %d want %d", got, want)
	}
	if got, want := len(paths[0].Contradictions[0].EvidenceRefs), len(refs); got != want {
		t.Fatalf("expected source contradiction refs to stay intact, got %d want %d", got, want)
	}
}

func makeEvidenceRefs(count int) []string {
	refs := make([]string, 0, count)
	for idx := 0; idx < count; idx++ {
		refs = append(refs, fmt.Sprintf("ref-%03d", idx))
	}
	return refs
}
