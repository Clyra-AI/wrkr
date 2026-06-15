package report

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestPrepareEvidenceBundleSummaryFocusesSinglePath(t *testing.T) {
	t.Parallel()

	summary := Summary{
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
		AgentActionBOM: &AgentActionBOM{
			Summary: AgentActionBOMSummary{
				PrimaryView: &AgentActionBOMPrimaryView{PathID: "apc-focus"},
			},
			Items: []AgentActionBOMItem{
				{PathID: "apc-focus", Location: ".github/workflows/release.yml", RecommendedActionContract: &risk.RecommendedActionContract{RequiredApproval: "Attach approval evidence"}},
				{PathID: "apc-other", Location: ".github/workflows/docs.yml"},
			},
		},
		ControlBacklog: &controlbacklog.Backlog{
			Items: []controlbacklog.Item{
				{ID: "cb-focus", LinkedActionPathID: "apc-focus"},
				{ID: "cb-other", LinkedActionPathID: "apc-other"},
			},
		},
		ControlPathGraph: &aggattack.ControlPathGraph{
			Nodes: []aggattack.ControlPathNode{{NodeID: "node-1", PathID: "apc-focus"}},
			Edges: []aggattack.ControlPathEdge{{EdgeID: "edge-1", PathID: "apc-focus"}},
		},
		WorkflowChains: &agentresolver.WorkflowChainArtifact{
			Chains: []agentresolver.WorkflowChain{{ChainID: "wc-1", PathIDs: []string{"apc-focus"}}},
		},
		ActionSurfaceRegistry: []ActionSurfaceRegistryEntry{
			{RegistryID: "registry-focus", PathIDs: []string{"apc-focus"}},
			{RegistryID: "registry-other", PathIDs: []string{"apc-other"}},
		},
	}

	focused := PrepareEvidenceBundleSummary(summary, "apc-focus", "")
	if focused.AgentActionBOM == nil || len(focused.AgentActionBOM.Items) != 1 {
		t.Fatalf("expected one focused BOM item, got %+v", focused.AgentActionBOM)
	}
	if focused.AgentActionBOM.Items[0].PathID != "apc-focus" {
		t.Fatalf("expected focused path to remain, got %+v", focused.AgentActionBOM.Items)
	}
	if focused.ControlBacklog == nil || len(focused.ControlBacklog.Items) != 1 || focused.ControlBacklog.Items[0].LinkedActionPathID != "apc-focus" {
		t.Fatalf("expected focused backlog item, got %+v", focused.ControlBacklog)
	}
	if focused.ControlPathGraph != nil {
		t.Fatalf("expected focused bundle to omit full graph export, got %+v", focused.ControlPathGraph)
	}
	if focused.WorkflowChains != nil {
		t.Fatalf("expected focused bundle to omit full workflow chains, got %+v", focused.WorkflowChains)
	}
	if len(focused.ActionSurfaceRegistry) != 1 || focused.ActionSurfaceRegistry[0].RegistryID != "registry-focus" {
		t.Fatalf("expected focused registry entry, got %+v", focused.ActionSurfaceRegistry)
	}
	if focused.SuppressedCounts == nil || focused.SuppressedCounts.AgentActionBOM != 1 || focused.SuppressedCounts.ControlBacklog != 1 {
		t.Fatalf("expected suppressed counts to reflect focused omissions, got %+v", focused.SuppressedCounts)
	}
}

func TestPrepareEvidenceBundleSummaryUsesFocusPresetTopPaths(t *testing.T) {
	t.Parallel()

	summary := Summary{
		FocusView: &FocusView{
			PathIDs: []string{"apc-1", "apc-2", "apc-3", "apc-4", "apc-5", "apc-6"},
		},
		AgentActionBOM: &AgentActionBOM{
			Items: []AgentActionBOMItem{
				{PathID: "apc-1"},
				{PathID: "apc-2"},
				{PathID: "apc-3"},
				{PathID: "apc-4"},
				{PathID: "apc-5"},
				{PathID: "apc-6"},
			},
		},
	}

	focused := PrepareEvidenceBundleSummary(summary, "", string(FocusPresetBOM))
	if focused.AgentActionBOM == nil || len(focused.AgentActionBOM.Items) != focusedEvidenceTopPathLimit {
		t.Fatalf("expected top %d focused items, got %+v", focusedEvidenceTopPathLimit, focused.AgentActionBOM)
	}
	if focused.AgentActionBOM.Items[focusedEvidenceTopPathLimit-1].PathID != "apc-5" {
		t.Fatalf("expected focus preset to cap at top path limit, got %+v", focused.AgentActionBOM.Items)
	}
}
