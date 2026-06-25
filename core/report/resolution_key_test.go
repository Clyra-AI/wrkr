package report

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestBuildAgentActionBOMCarriesResolutionKeySelectorMetadata(t *testing.T) {
	t.Parallel()

	bom := BuildAgentActionBOM(Summary{
		ActionPaths: []risk.ActionPath{{
			PathID:                    "apc-resolution",
			Org:                       "acme",
			Repo:                      "acme/release",
			ToolType:                  "compiled_action",
			Location:                  ".github/workflows/release.yml",
			WriteCapable:              true,
			ResolutionKey:             "rk-release",
			ResolutionMatchConfidence: "high",
			ResolutionMismatchReasons: []string{"selector:path_id_stale"},
			ReviewLifecycleState:      risk.ReviewLifecycleStateAcceptedRisk,
			ReviewSource:              "governance-ticket",
		}},
	})
	if bom == nil || len(bom.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", bom)
	}
	item := bom.Items[0]
	if item.ResolutionKey != "rk-release" {
		t.Fatalf("expected resolution_key on BOM item, got %+v", item)
	}
	if item.ResolutionMatchConfidence != "high" {
		t.Fatalf("expected selector match confidence on BOM item, got %+v", item)
	}
	if item.ReviewLifecycleState != risk.ReviewLifecycleStateAcceptedRisk {
		t.Fatalf("expected review lifecycle state on BOM item, got %+v", item)
	}
}
