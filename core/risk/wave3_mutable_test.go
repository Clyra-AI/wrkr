package risk

import (
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

func TestMutableEndpointInfluencesGovernFirstRanking(t *testing.T) {
	t.Parallel()

	paths := ProjectActionPaths([]ActionPath{
		{
			PathID:       "generic-write",
			Org:          "local",
			Repo:         "demo",
			ToolType:     "ci_agent",
			Location:     ".github/workflows/release.yml",
			WriteCapable: true,
			ActionClasses: []string{
				"write",
			},
			PathContext: &agginventory.PathContext{Kind: agginventory.PathContextRuntimeSource, Confidence: "high"},
		},
		{
			PathID:           "payment-endpoint",
			Org:              "local",
			Repo:             "demo",
			ToolType:         "openapi",
			Location:         "openapi.yaml",
			WriteCapable:     true,
			CredentialAccess: true,
			ActionClasses: []string{
				"write",
			},
			MutableEndpointSemantics: []agginventory.MutableEndpointSemantic{{
				Semantic:   agginventory.EndpointSemanticPayment,
				Confidence: "high",
				Surface:    "openapi",
				Operation:  "POST /v1/payments",
			}},
			PathContext: &agginventory.PathContext{Kind: agginventory.PathContextRuntimeSource, Confidence: "high"},
		},
	})

	if len(paths) != 2 {
		t.Fatalf("expected two ranked paths, got %d", len(paths))
	}
	if paths[0].PathID != "payment-endpoint" {
		t.Fatalf("expected mutable payment path to outrank generic write path, got %+v", paths)
	}
	if paths[0].RiskZone != RiskZoneProductionData {
		t.Fatalf("expected payment endpoint to project to production_data risk zone, got %+v", paths[0])
	}
	if len(paths[0].HighStakesPresets) == 0 {
		t.Fatalf("expected high-stakes presets for mutable payment path, got %+v", paths[0])
	}
}

func TestProjectActionPathCanonicalizesMutableEndpointSemantics(t *testing.T) {
	t.Parallel()

	path := ProjectActionPath(ActionPath{
		PathID:   "endpoint-canonicalization",
		Org:      "local",
		Repo:     "demo",
		ToolType: "openapi",
		MutableEndpointSemantics: []agginventory.MutableEndpointSemantic{
			{
				Semantic:     agginventory.EndpointSemanticWrite,
				Confidence:   " high ",
				Surface:      " openapi ",
				Operation:    " PATCH /v1/users ",
				EvidenceRefs: []string{" evidence://two ", "evidence://one"},
			},
			{
				Semantic:     agginventory.EndpointSemanticPayment,
				Confidence:   "high",
				Surface:      "openapi",
				Operation:    "POST /v1/payments",
				EvidenceRefs: []string{"evidence://payment"},
			},
			{
				Semantic:     agginventory.EndpointSemanticWrite,
				Confidence:   "high",
				Surface:      "openapi",
				Operation:    "PATCH /v1/users",
				EvidenceRefs: []string{"evidence://one", "evidence://three"},
			},
		},
	})

	if len(path.MutableEndpointSemantics) != 2 {
		t.Fatalf("expected duplicate endpoint semantics to merge, got %+v", path.MutableEndpointSemantics)
	}
	if path.MutableEndpointSemantics[0].Semantic != agginventory.EndpointSemanticPayment ||
		path.MutableEndpointSemantics[1].Semantic != agginventory.EndpointSemanticWrite {
		t.Fatalf("expected deterministic semantic ordering, got %+v", path.MutableEndpointSemantics)
	}
	gotRefs := path.MutableEndpointSemantics[1].EvidenceRefs
	if len(gotRefs) != 3 ||
		gotRefs[0] != "evidence://one" ||
		gotRefs[1] != "evidence://three" ||
		gotRefs[2] != "evidence://two" {
		t.Fatalf("expected merged deterministic evidence refs, got %v", gotRefs)
	}
}
