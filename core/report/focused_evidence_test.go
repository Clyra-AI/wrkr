package report

import (
	"fmt"
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
		ActionPaths: []risk.ActionPath{
			{PathID: "apc-focus", Org: "acme", Repo: "acme/release", ToolType: "compiled_action", Location: ".github/workflows/release.yml"},
			{PathID: "apc-other", Org: "acme", Repo: "acme/release", ToolType: "compiled_action", Location: ".github/workflows/docs.yml"},
		},
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
	if len(focused.ActionSurfaceRegistry) != 1 {
		t.Fatalf("expected focused registry entry, got %+v", focused.ActionSurfaceRegistry)
	}
	if focused.ActionSurfaceRegistry[0].ActionPathCount != 1 || len(focused.ActionSurfaceRegistry[0].PathIDs) != 1 || focused.ActionSurfaceRegistry[0].PathIDs[0] != "apc-focus" {
		t.Fatalf("expected focused registry to be rebuilt for the selected path only, got %+v", focused.ActionSurfaceRegistry[0])
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
		ActionPaths: []risk.ActionPath{
			{PathID: "apc-1", Org: "acme", Repo: "acme/release", ToolType: "compiled_action", Location: ".github/workflows/release.yml"},
			{PathID: "apc-2", Org: "acme", Repo: "acme/release", ToolType: "compiled_action", Location: ".github/workflows/release.yml"},
			{PathID: "apc-3", Org: "acme", Repo: "acme/release", ToolType: "compiled_action", Location: ".github/workflows/release.yml"},
			{PathID: "apc-4", Org: "acme", Repo: "acme/release", ToolType: "compiled_action", Location: ".github/workflows/release.yml"},
			{PathID: "apc-5", Org: "acme", Repo: "acme/release", ToolType: "compiled_action", Location: ".github/workflows/release.yml"},
			{PathID: "apc-6", Org: "acme", Repo: "acme/release", ToolType: "compiled_action", Location: ".github/workflows/release.yml"},
		},
		AgentActionBOM: &AgentActionBOM{
			Summary: AgentActionBOMSummary{
				PrimaryView: &AgentActionBOMPrimaryView{PathID: "apc-6"},
			},
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
	if focused.AgentActionBOM.Summary.PrimaryView == nil || focused.AgentActionBOM.Summary.PrimaryView.PathID != "apc-1" {
		t.Fatalf("expected primary view to be recomputed against focused items, got %+v", focused.AgentActionBOM.Summary.PrimaryView)
	}
	if len(focused.ActionSurfaceRegistry) != 1 || focused.ActionSurfaceRegistry[0].ActionPathCount != focusedEvidenceTopPathLimit {
		t.Fatalf("expected focused registry to be rebuilt from the selected paths, got %+v", focused.ActionSurfaceRegistry)
	}
	if len(focused.ActionSurfaceRegistry[0].PathIDs) != focusedEvidenceTopPathLimit || focused.ActionSurfaceRegistry[0].PathIDs[focusedEvidenceTopPathLimit-1] != "apc-5" {
		t.Fatalf("expected focused registry path IDs to stay capped to the selected set, got %+v", focused.ActionSurfaceRegistry[0])
	}
}

func TestPrepareEvidenceBundleSummaryKeepsFocusedModeWhenPresetIsEmpty(t *testing.T) {
	t.Parallel()

	summary := Summary{
		FocusView: &FocusView{
			PathIDs: nil,
		},
		AgentActionBOM: &AgentActionBOM{
			Summary: AgentActionBOMSummary{
				PrimaryView: &AgentActionBOMPrimaryView{PathID: "apc-focus"},
			},
			Items: []AgentActionBOMItem{{PathID: "apc-focus"}},
		},
		ControlBacklog: &controlbacklog.Backlog{
			Items: []controlbacklog.Item{{ID: "cb-focus", LinkedActionPathID: "apc-focus"}},
		},
		ControlPathGraph: &aggattack.ControlPathGraph{
			Nodes: []aggattack.ControlPathNode{{NodeID: "node-1", PathID: "apc-focus"}},
		},
		WorkflowChains: &agentresolver.WorkflowChainArtifact{
			Chains: []agentresolver.WorkflowChain{{ChainID: "wc-1", PathIDs: []string{"apc-focus"}}},
		},
	}

	focused := PrepareEvidenceBundleSummary(summary, "", string(FocusPresetContradictions))
	if focused.AgentActionBOM == nil || len(focused.AgentActionBOM.Items) != 0 {
		t.Fatalf("expected empty focused BOM when preset has no matches, got %+v", focused.AgentActionBOM)
	}
	if focused.ControlBacklog != nil {
		t.Fatalf("expected empty focused backlog when preset has no matches, got %+v", focused.ControlBacklog)
	}
	if focused.ControlPathGraph != nil || focused.WorkflowChains != nil {
		t.Fatalf("expected broad graph/workflow exports to be stripped for empty focus mode, graph=%+v workflow=%+v", focused.ControlPathGraph, focused.WorkflowChains)
	}
	if focused.SuppressedCounts == nil || focused.SuppressedCounts.AgentActionBOM != 1 || focused.SuppressedCounts.ControlBacklog != 1 {
		t.Fatalf("expected suppressions to record the stripped focused surfaces, got %+v", focused.SuppressedCounts)
	}
}

func TestPrepareEvidenceBundleSummaryDefaultsAgentActionBOMToLeadBundle(t *testing.T) {
	t.Parallel()

	paths := []risk.ActionPath{}
	items := []AgentActionBOMItem{}
	for idx := 1; idx <= 6; idx++ {
		pathID := fmt.Sprintf("apc-%d", idx)
		paths = append(paths, risk.ActionPath{PathID: pathID, Repo: "acme/release", Location: ".github/workflows/release.yml"})
		items = append(items, AgentActionBOMItem{
			PathID:                  pathID,
			Repo:                    "acme/release",
			Location:                ".github/workflows/release.yml",
			ActionPathEligible:      true,
			ActionBindingState:      risk.ActionBindingStateBound,
			ActionPathType:          risk.ActionPathTypeCICDWorkflow,
			ConfidenceLane:          risk.ConfidenceLaneConfirmedActionPath,
			RecommendedControl:      risk.RecommendedControlApprovalRequired,
			ApprovalEvidenceState:   risk.EvidenceStateUnknown,
			ProofEvidenceState:      risk.EvidenceStateUnknown,
			CredentialEvidenceState: risk.EvidenceStateVerified,
		})
	}
	summary := Summary{
		Template:    string(TemplateAgentActionBOM),
		ActionPaths: paths,
		WorkflowHighlights: &WorkflowHighlights{Highlights: []WorkflowHighlight{
			{PathID: "apc-1"},
			{PathID: "apc-2"},
			{PathID: "apc-3"},
			{PathID: "apc-4"},
			{PathID: "apc-5"},
			{PathID: "apc-6"},
		}},
		AgentActionBOM: &AgentActionBOM{
			Summary: AgentActionBOMSummary{
				PrimaryView: &AgentActionBOMPrimaryView{PathID: "apc-6"},
			},
			Items: items,
		},
		ControlBacklog: &controlbacklog.Backlog{
			Items: []controlbacklog.Item{
				{ID: "cb-1", LinkedActionPathID: "apc-1"},
				{ID: "cb-6", LinkedActionPathID: "apc-6"},
			},
		},
		ControlPathGraph: &aggattack.ControlPathGraph{
			Nodes: []aggattack.ControlPathNode{{NodeID: "node-1", PathID: "apc-1"}},
			Edges: []aggattack.ControlPathEdge{{EdgeID: "edge-1", PathID: "apc-1"}},
		},
		WorkflowChains: &agentresolver.WorkflowChainArtifact{
			Chains: []agentresolver.WorkflowChain{{ChainID: "wc-1", PathIDs: []string{"apc-1"}}},
		},
	}

	focused := PrepareEvidenceBundleSummary(summary, "", "")
	if !focused.FocusedBundleAvailable {
		t.Fatalf("expected default Agent Action BOM evidence to be marked as focused lead bundle")
	}
	if !focused.FullExportAvailable {
		t.Fatalf("expected full export to be advertised when graph-heavy surfaces are stripped")
	}
	if focused.ControlPathGraph != nil || focused.WorkflowChains != nil {
		t.Fatalf("expected default lead evidence to omit graph-heavy appendix, graph=%+v chains=%+v", focused.ControlPathGraph, focused.WorkflowChains)
	}
	if focused.AgentActionBOM == nil || len(focused.AgentActionBOM.Items) != focusedEvidenceTopPathLimit {
		t.Fatalf("expected default lead evidence to keep top %d BOM items, got %+v", focusedEvidenceTopPathLimit, focused.AgentActionBOM)
	}
	if !focusedEvidenceContainsPathID(itemPathIDs(focused.AgentActionBOM.Items), "apc-6") {
		t.Fatalf("expected default lead evidence to keep the primary path, got %+v", focused.AgentActionBOM.Items)
	}
	if focused.SuppressedCounts == nil || focused.SuppressedCounts.GraphNodes == 0 || focused.SuppressedCounts.WorkflowChains == 0 {
		t.Fatalf("expected lead evidence suppressions for graph-heavy appendix, got %+v", focused.SuppressedCounts)
	}
}

func TestPrepareEvidenceBundleSummaryKeepsNonBOMDefaultFullExport(t *testing.T) {
	t.Parallel()

	summary := Summary{
		Template: string(TemplateOperator),
		ControlPathGraph: &aggattack.ControlPathGraph{
			Nodes: []aggattack.ControlPathNode{{NodeID: "node-1", PathID: "apc-1"}},
		},
	}

	focused := PrepareEvidenceBundleSummary(summary, "", "")
	if focused.FocusedBundleAvailable {
		t.Fatalf("expected non-BOM evidence without explicit focus to remain full export")
	}
	if focused.ControlPathGraph == nil || len(focused.ControlPathGraph.Nodes) != 1 {
		t.Fatalf("expected non-BOM evidence to keep graph by default, got %+v", focused.ControlPathGraph)
	}
}

func itemPathIDs(items []AgentActionBOMItem) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.PathID)
	}
	return out
}
