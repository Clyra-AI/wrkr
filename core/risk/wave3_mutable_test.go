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
			PathID:       "payment-endpoint",
			Org:          "local",
			Repo:         "demo",
			ToolType:     "openapi",
			Location:     "openapi.yaml",
			WriteCapable: true,
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
}
