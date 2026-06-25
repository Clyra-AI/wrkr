package controlbacklog

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestBuildControlBacklogCarriesResolutionKeySelectorMetadata(t *testing.T) {
	t.Parallel()

	backlog := Build(Input{
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
			RecommendedAction:         "control",
		}},
	})
	if len(backlog.Items) != 1 {
		t.Fatalf("expected one backlog item, got %+v", backlog.Items)
	}
	item := backlog.Items[0]
	if item.ResolutionKey != "rk-release" {
		t.Fatalf("expected resolution_key on backlog item, got %+v", item)
	}
	if item.ReviewLifecycleState != risk.ReviewLifecycleStateAcceptedRisk {
		t.Fatalf("expected review lifecycle state on backlog item, got %+v", item)
	}
}
