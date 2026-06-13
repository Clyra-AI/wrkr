package cli

import (
	"fmt"
	"testing"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/source"
)

func TestBuildScanJSONSummaryBoundsLargeSections(t *testing.T) {
	t.Parallel()

	input := scanJSONSummaryInput{
		StatePath:      ".wrkr/last-scan.json",
		Findings:       makeScanSummaryFindings(scanSummaryInlineFindingsCap + 3),
		Inventory:      makeScanSummaryInventory(scanSummaryInlineInventoryToolsCap+2, scanSummaryInlinePrivilegeRowsCap+2),
		RiskReport:     makeScanSummaryRiskReport(scanSummaryInlineRankedFindingsCap+2, scanSummaryInlineActionPathsCap+2),
		ControlBacklog: makeScanSummaryBacklog(scanSummaryInlineBacklogItemsCap + 2),
	}

	payload := buildScanJSONSummary(input)

	if _, ok := payload["findings"]; ok {
		t.Fatalf("oversized findings must stay state-only in scan stdout")
	}
	ranked, ok := payload["ranked_findings"].([]risk.ScoredFinding)
	if !ok || len(ranked) != scanSummaryInlineRankedFindingsCap {
		t.Fatalf("expected bounded ranked_findings preview of %d, got %T len=%d", scanSummaryInlineRankedFindingsCap, payload["ranked_findings"], len(ranked))
	}
	actionPaths, ok := payload["action_paths"].([]risk.ActionPath)
	if !ok || len(actionPaths) != scanSummaryInlineActionPathsCap {
		t.Fatalf("expected bounded action_paths preview of %d, got %T len=%d", scanSummaryInlineActionPathsCap, payload["action_paths"], len(actionPaths))
	}
	backlog, ok := payload["control_backlog"].(controlbacklog.Backlog)
	if !ok || len(backlog.Items) != scanSummaryInlineBacklogItemsCap {
		t.Fatalf("expected bounded control_backlog preview of %d, got %T len=%d", scanSummaryInlineBacklogItemsCap, payload["control_backlog"], len(backlog.Items))
	}
	inventory, ok := payload["inventory"].(agginventory.Inventory)
	if !ok || len(inventory.Tools) != scanSummaryInlineInventoryToolsCap {
		t.Fatalf("expected bounded inventory.tools preview of %d, got %T len=%d", scanSummaryInlineInventoryToolsCap, payload["inventory"], len(inventory.Tools))
	}
	agentPrivilegeMap, ok := payload["agent_privilege_map"].([]agginventory.AgentPrivilegeMapEntry)
	if !ok || len(agentPrivilegeMap) != scanSummaryInlinePrivilegeRowsCap {
		t.Fatalf("expected bounded agent_privilege_map preview of %d, got %T len=%d", scanSummaryInlinePrivilegeRowsCap, payload["agent_privilege_map"], len(agentPrivilegeMap))
	}
	suppressed, ok := payload["suppressed_counts"].(*reportcore.SuppressedCounts)
	if !ok || suppressed == nil {
		t.Fatalf("expected suppressed_counts, got %T", payload["suppressed_counts"])
	}
	if suppressed.Findings != 3 ||
		suppressed.RankedFindings != 2 ||
		suppressed.ActionPaths != 2 ||
		suppressed.ControlBacklog != 2 ||
		suppressed.InventoryTools != 2 ||
		suppressed.PrivilegeRows != 2 {
		t.Fatalf("unexpected suppressed_counts: %#v", suppressed)
	}
}

func TestBuildScanJSONSummaryPreservesEmptyPreviewSlices(t *testing.T) {
	t.Parallel()

	input := scanJSONSummaryInput{
		StatePath: ".wrkr/last-scan.json",
		Inventory: agginventory.Inventory{
			InventoryVersion:  "1",
			Agents:            []agginventory.Agent{},
			Tools:             []agginventory.Tool{},
			AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{},
		},
		ControlBacklog: controlbacklog.Backlog{
			ControlBacklogVersion: controlbacklog.BacklogVersion,
			Items:                 []controlbacklog.Item{},
		},
	}

	payload := buildScanJSONSummary(input)

	backlog, ok := payload["control_backlog"].(controlbacklog.Backlog)
	if !ok {
		t.Fatalf("expected control_backlog payload, got %T", payload["control_backlog"])
	}
	if backlog.Items == nil {
		t.Fatalf("expected control_backlog.items to remain an empty slice, got nil")
	}
	inventory, ok := payload["inventory"].(agginventory.Inventory)
	if !ok {
		t.Fatalf("expected inventory payload, got %T", payload["inventory"])
	}
	if inventory.Agents == nil || inventory.Tools == nil || inventory.AgentPrivilegeMap == nil {
		t.Fatalf("expected inventory preview slices to remain empty slices, got agents=%v tools=%v privilege_map=%v", inventory.Agents, inventory.Tools, inventory.AgentPrivilegeMap)
	}
	agentPrivilegeMap, ok := payload["agent_privilege_map"].([]agginventory.AgentPrivilegeMapEntry)
	if !ok {
		t.Fatalf("expected agent_privilege_map payload, got %T", payload["agent_privilege_map"])
	}
	if agentPrivilegeMap == nil {
		t.Fatalf("expected agent_privilege_map to remain an empty slice, got nil")
	}
}

func TestBuildScanJSONSummaryUsesCanonicalOutputFinalizer(t *testing.T) {
	t.Parallel()

	authority := &agginventory.CredentialAuthority{
		CredentialPresent:      true,
		CredentialUsableByPath: true,
		StandingAccess:         true,
		CredentialKind:         agginventory.CredentialKindGitHubPAT,
		AccessType:             agginventory.CredentialAccessTypeStanding,
		ReasonCodes:            []string{"credential_authority:present"},
	}
	binding := &agginventory.AuthorityBinding{
		Kind:         agginventory.AuthorityBindingCloudRole,
		Provider:     "aws",
		Subject:      "release-role",
		TargetSystem: "deployment_platform",
		LikelyScope:  "deploy_write",
		AccessLevel:  agginventory.AuthorityAccessWrite,
		Environment:  "prod",
		Production:   true,
		Confidence:   "high",
	}
	semantics := []agginventory.MutableEndpointSemantic{{
		Semantic:     agginventory.EndpointSemanticDeploy,
		Confidence:   "high",
		Surface:      "workflow",
		Operation:    "deploy release",
		EvidenceRefs: []string{"deploy release"},
	}}

	input := scanJSONSummaryInput{
		StatePath: ".wrkr/last-scan.json",
		Manifest:  source.Manifest{Target: source.Target{Mode: "repo", Value: "acme/release"}},
		Inventory: agginventory.Inventory{
			AgentPrivilegeMap: []agginventory.AgentPrivilegeMapEntry{{
				AgentID:                     "wrkr:compiled_action:acme",
				ToolID:                      "tool-1",
				ToolType:                    "compiled_action",
				Org:                         "acme",
				Repos:                       []string{"acme/release"},
				Permissions:                 []string{"repo.contents.write"},
				WriteCapable:                true,
				MutableEndpointSemanticRefs: agginventory.CanonicalMutableEndpointRefs(semantics),
				MutableEndpointSemantics:    semantics,
				CredentialAuthorityRef:      agginventory.CanonicalCredentialAuthorityRef(authority),
				CredentialAuthority:         authority,
				AuthorityBindingRefs:        agginventory.CanonicalAuthorityBindingRefs([]*agginventory.AuthorityBinding{binding}),
				AuthorityBindings:           []*agginventory.AuthorityBinding{binding},
			}},
		},
		RiskReport: risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:                      "apc-canonical",
				Org:                         "acme",
				Repo:                        "acme/release",
				ToolType:                    "compiled_action",
				Location:                    ".github/workflows/release.yml",
				WriteCapable:                true,
				CredentialAccess:            true,
				ApprovalGap:                 true,
				RecommendedAction:           "control",
				MutableEndpointSemanticRefs: agginventory.CanonicalMutableEndpointRefs(semantics),
				MutableEndpointSemantics:    semantics,
				CredentialAuthorityRef:      agginventory.CanonicalCredentialAuthorityRef(authority),
				CredentialAuthority:         authority,
				AuthorityBindingRefs:        agginventory.CanonicalAuthorityBindingRefs([]*agginventory.AuthorityBinding{binding}),
				AuthorityBindings:           []*agginventory.AuthorityBinding{binding},
			}},
			ActionPathToControlFirst: &risk.ActionPathToControlFirst{
				Summary: risk.ActionPathSummary{TotalPaths: 1},
				Path: risk.ActionPath{
					PathID:                      "apc-canonical",
					Org:                         "acme",
					Repo:                        "acme/release",
					MutableEndpointSemanticRefs: agginventory.CanonicalMutableEndpointRefs(semantics),
					MutableEndpointSemantics:    semantics,
					CredentialAuthorityRef:      agginventory.CanonicalCredentialAuthorityRef(authority),
					CredentialAuthority:         authority,
					AuthorityBindingRefs:        agginventory.CanonicalAuthorityBindingRefs([]*agginventory.AuthorityBinding{binding}),
					AuthorityBindings:           []*agginventory.AuthorityBinding{binding},
				},
			},
			ControlPathGraph: &aggattack.ControlPathGraph{
				Version: "1",
				Nodes: []aggattack.ControlPathNode{{
					NodeID:                      "node-1",
					PathID:                      "apc-canonical",
					Kind:                        aggattack.ControlPathNodeWorkflow,
					MutableEndpointSemanticRefs: agginventory.CanonicalMutableEndpointRefs(semantics),
					MutableEndpointSemantics:    semantics,
					CredentialAuthorityRef:      agginventory.CanonicalCredentialAuthorityRef(authority),
					CredentialAuthority:         authority,
					AuthorityBindingRefs:        agginventory.CanonicalAuthorityBindingRefs([]*agginventory.AuthorityBinding{binding}),
					AuthorityBindings:           []*agginventory.AuthorityBinding{binding},
				}},
			},
		},
		ControlBacklog: controlbacklog.Backlog{
			ControlBacklogVersion: controlbacklog.BacklogVersion,
			Items: []controlbacklog.Item{{
				ID:                     "cb-canonical",
				Repo:                   "acme/release",
				Path:                   ".github/workflows/release.yml",
				ControlSurfaceType:     "workflow",
				CredentialAuthorityRef: agginventory.CanonicalCredentialAuthorityRef(authority),
				CredentialAuthority:    authority,
				AuthorityBindingRefs:   agginventory.CanonicalAuthorityBindingRefs([]*agginventory.AuthorityBinding{binding}),
				AuthorityBindings:      []*agginventory.AuthorityBinding{binding},
			}},
		},
	}

	payload := buildScanJSONSummary(input)

	actionPaths, ok := payload["action_paths"].([]risk.ActionPath)
	if !ok || len(actionPaths) != 1 {
		t.Fatalf("expected one action path preview, got %T %+v", payload["action_paths"], payload["action_paths"])
	}
	if actionPaths[0].CredentialAuthorityRef == "" || len(actionPaths[0].AuthorityBindingRefs) == 0 || len(actionPaths[0].MutableEndpointSemanticRefs) == 0 {
		t.Fatalf("expected canonical refs on scan action path, got %+v", actionPaths[0])
	}
	if actionPaths[0].CredentialAuthority != nil || len(actionPaths[0].AuthorityBindings) > 0 || len(actionPaths[0].MutableEndpointSemantics) > 0 {
		t.Fatalf("expected scan action path embedded clones stripped, got %+v", actionPaths[0])
	}

	inventory, ok := payload["inventory"].(agginventory.Inventory)
	if !ok || len(inventory.AgentPrivilegeMap) != 1 {
		t.Fatalf("expected inventory preview with one privilege row, got %T %+v", payload["inventory"], payload["inventory"])
	}
	entry := inventory.AgentPrivilegeMap[0]
	if entry.CredentialAuthorityRef == "" || len(entry.AuthorityBindingRefs) == 0 || len(entry.MutableEndpointSemanticRefs) == 0 {
		t.Fatalf("expected canonical refs on inventory preview, got %+v", entry)
	}
	if entry.CredentialAuthority != nil || len(entry.AuthorityBindings) > 0 || len(entry.MutableEndpointSemantics) > 0 {
		t.Fatalf("expected inventory preview embedded clones stripped, got %+v", entry)
	}

	backlog, ok := payload["control_backlog"].(controlbacklog.Backlog)
	if !ok || len(backlog.Items) != 1 {
		t.Fatalf("expected one backlog preview item, got %T %+v", payload["control_backlog"], payload["control_backlog"])
	}
	item := backlog.Items[0]
	if item.CredentialAuthorityRef == "" || len(item.AuthorityBindingRefs) == 0 {
		t.Fatalf("expected canonical refs on backlog preview, got %+v", item)
	}
	if item.CredentialAuthority != nil || len(item.AuthorityBindings) > 0 {
		t.Fatalf("expected backlog preview embedded clones stripped, got %+v", item)
	}

	graph, ok := payload["control_path_graph"].(*aggattack.ControlPathGraph)
	if !ok || graph == nil || len(graph.Nodes) != 1 {
		t.Fatalf("expected control path graph preview, got %T %+v", payload["control_path_graph"], payload["control_path_graph"])
	}
	node := graph.Nodes[0]
	if node.CredentialAuthorityRef == "" || len(node.AuthorityBindingRefs) == 0 || len(node.MutableEndpointSemanticRefs) == 0 {
		t.Fatalf("expected canonical refs on graph preview, got %+v", node)
	}
	if node.CredentialAuthority != nil || len(node.AuthorityBindings) > 0 || len(node.MutableEndpointSemantics) > 0 {
		t.Fatalf("expected graph preview embedded clones stripped, got %+v", node)
	}
}

func makeScanSummaryFindings(count int) []source.Finding {
	findings := make([]source.Finding, 0, count)
	for idx := 0; idx < count; idx++ {
		findings = append(findings, source.Finding{
			FindingType: "tool_detected",
			ToolType:    "codex",
			Location:    fmt.Sprintf(".codex/config-%02d.toml", idx),
			Repo:        "repo",
			Org:         "acme",
		})
	}
	return findings
}

func makeScanSummaryRiskReport(rankedCount, actionPathCount int) risk.Report {
	ranked := make([]risk.ScoredFinding, 0, rankedCount)
	for idx := 0; idx < rankedCount; idx++ {
		ranked = append(ranked, risk.ScoredFinding{
			CanonicalKey: fmt.Sprintf("finding-%02d", idx),
			Score:        float64(idx),
		})
	}
	actionPaths := make([]risk.ActionPath, 0, actionPathCount)
	for idx := 0; idx < actionPathCount; idx++ {
		actionPaths = append(actionPaths, risk.ActionPath{
			PathID:            fmt.Sprintf("apc-%02d", idx),
			Org:               "acme",
			Repo:              "repo",
			ToolType:          "codex",
			RecommendedAction: "review",
		})
	}
	return risk.Report{
		Ranked:      ranked,
		ActionPaths: actionPaths,
	}
}

func makeScanSummaryBacklog(count int) controlbacklog.Backlog {
	items := make([]controlbacklog.Item, 0, count)
	for idx := 0; idx < count; idx++ {
		items = append(items, controlbacklog.Item{
			ID:                 fmt.Sprintf("cb-%02d", idx),
			Repo:               "repo",
			Path:               fmt.Sprintf(".github/workflows/release-%02d.yml", idx),
			ControlSurfaceType: "workflow",
		})
	}
	return controlbacklog.Backlog{
		ControlBacklogVersion: controlbacklog.BacklogVersion,
		Summary: controlbacklog.Summary{
			TotalItems: count,
		},
		Items: items,
	}
}

func makeScanSummaryInventory(toolCount, privilegeRows int) agginventory.Inventory {
	tools := make([]agginventory.Tool, 0, toolCount)
	for idx := 0; idx < toolCount; idx++ {
		tools = append(tools, agginventory.Tool{
			ToolID:   fmt.Sprintf("tool-%02d", idx),
			AgentID:  fmt.Sprintf("wrkr:codex-%02d:acme", idx),
			ToolType: "codex",
			Org:      "acme",
			Repos:    []string{"repo"},
		})
	}
	rows := make([]agginventory.AgentPrivilegeMapEntry, 0, privilegeRows)
	for idx := 0; idx < privilegeRows; idx++ {
		rows = append(rows, agginventory.AgentPrivilegeMapEntry{
			AgentID:     fmt.Sprintf("wrkr:codex-%02d:acme", idx),
			ToolID:      fmt.Sprintf("tool-%02d", idx),
			ToolType:    "codex",
			Org:         "acme",
			Repos:       []string{"repo"},
			Permissions: []string{"write"},
		})
	}
	return agginventory.Inventory{
		InventoryVersion:  "1",
		Tools:             tools,
		AgentPrivilegeMap: rows,
	}
}
