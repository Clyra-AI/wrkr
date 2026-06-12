package cli

import (
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/compliance"
	"github.com/Clyra-AI/wrkr/core/outputsignal"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
	"github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
)

const (
	scanSummaryInlineFindingsCap        = 200
	scanSummaryInlineRankedFindingsCap  = 10
	scanSummaryInlineActionPathsCap     = 5
	scanSummaryInlineAttackPathsCap     = 5
	scanSummaryInlineBacklogItemsCap    = 5
	scanSummaryInlineInventoryAgentsCap = 10
	scanSummaryInlineInventoryToolsCap  = 10
	scanSummaryInlinePrivilegeRowsCap   = 10
	scanSummaryInlineGraphNodesCap      = 50
	scanSummaryInlineGraphEdgesCap      = 100
	scanSummaryInlineWorkflowChainsCap  = 5
)

type scanJSONSummaryInput struct {
	DeploymentMode          string
	Manifest                source.Manifest
	SourcePrivacy           sourceprivacy.Contract
	ScanMode                string
	ScanQuality             any
	StatePath               string
	Inventory               agginventory.Inventory
	RiskReport              risk.Report
	ControlBacklog          controlbacklog.Backlog
	Profile                 profileeval.Result
	PostureScore            score.Result
	ComplianceSummary       compliance.RollupSummary
	Findings                []source.Finding
	Warnings                []string
	ProductionTargetWarning []string
	DetectorErrors          any
	PartialResult           bool
	SourceErrors            []source.RepoFailure
}

func buildScanJSONSummary(input scanJSONSummaryInput) map[string]any {
	payload := map[string]any{
		"status":              "ok",
		"deployment_mode":     input.DeploymentMode,
		"target":              input.Manifest.Target,
		"source_manifest":     input.Manifest,
		"source_privacy":      input.SourcePrivacy,
		"scan_mode":           input.ScanMode,
		"scan_quality":        input.ScanQuality,
		"state_path":          input.StatePath,
		"inventory_summary":   input.Inventory.Summary,
		"privilege_budget":    input.Inventory.PrivilegeBudget,
		"posture_score":       input.PostureScore,
		"compliance_summary":  input.ComplianceSummary,
		"profile":             input.Profile,
		"policy_outcomes":     outputsignal.BuildPolicyOutcomes(input.Findings),
		"finding_counts":      buildFindingCounts(input.Findings),
		"tool_type_breakdown": buildToolTypeBreakdown(input.Inventory.Tools),
	}
	if len(input.Manifest.Targets) > 0 {
		payload["targets"] = input.Manifest.Targets
	}
	if input.PartialResult {
		payload["partial_result"] = true
		payload["source_errors"] = input.SourceErrors
		payload["source_degraded"] = hasDegradedFailures(input.SourceErrors)
	}
	if input.DetectorErrors != nil {
		payload["detector_errors"] = input.DetectorErrors
	}
	if len(input.Warnings) > 0 {
		payload["warnings"] = append([]string(nil), input.Warnings...)
	}
	if len(input.ProductionTargetWarning) > 0 {
		payload["policy_warnings"] = append([]string(nil), input.ProductionTargetWarning...)
	}
	if input.RiskReport.ActionPathToControlFirst != nil {
		payload["action_path_summary"] = input.RiskReport.ActionPathToControlFirst.Summary
		payload["top_path_to_control_first"] = input.RiskReport.ActionPathToControlFirst.Path.PathID
	}
	if activation := reportcore.BuildActivation(input.Manifest.Target.Mode, input.RiskReport.Ranked, &input.Inventory, input.RiskReport.ActionPaths, 5); activation != nil {
		payload["activation"] = activation
	}
	if suppressed := buildScanSuppressedCounts(input); suppressed != nil {
		payload["suppressed_counts"] = suppressed
	}
	if len(input.RiskReport.TopN) > 0 {
		payload["top_findings"] = input.RiskReport.TopN
	}
	if len(input.Findings) <= scanSummaryInlineFindingsCap {
		payload["findings"] = append([]source.Finding(nil), input.Findings...)
	}
	if ranked := scanPreview(input.RiskReport.Ranked, scanSummaryInlineRankedFindingsCap); len(ranked) > 0 {
		payload["ranked_findings"] = ranked
	}
	attackPaths := scanPreview(input.RiskReport.AttackPaths, scanSummaryInlineAttackPathsCap)
	if attackPaths == nil {
		attackPaths = []riskattack.ScoredPath{}
	}
	payload["attack_paths"] = attackPaths
	topAttackPaths := scanPreview(input.RiskReport.TopAttackPaths, scanSummaryInlineAttackPathsCap)
	if topAttackPaths == nil {
		topAttackPaths = []riskattack.ScoredPath{}
	}
	payload["top_attack_paths"] = topAttackPaths
	if actionPaths := scanPreview(input.RiskReport.ActionPaths, scanSummaryInlineActionPathsCap); len(actionPaths) > 0 {
		payload["action_paths"] = actionPaths
	}
	if input.RiskReport.ActionPathToControlFirst != nil {
		payload["action_path_to_control_first"] = input.RiskReport.ActionPathToControlFirst
	}
	if scanSummaryInlineBacklogItemsCap >= 0 {
		backlog := input.ControlBacklog
		backlog.Items = scanPreview(input.ControlBacklog.Items, scanSummaryInlineBacklogItemsCap)
		payload["control_backlog"] = backlog
	}
	if inventory := scanInventoryPreview(input.Inventory); inventory != nil {
		payload["inventory"] = *inventory
	}
	rows := scanPreview(input.Inventory.AgentPrivilegeMap, scanSummaryInlinePrivilegeRowsCap)
	if rows == nil {
		rows = []agginventory.AgentPrivilegeMapEntry{}
	}
	payload["agent_privilege_map"] = rows
	if len(input.Inventory.RepoExposureSummaries) > 0 {
		payload["repo_exposure_summaries"] = input.Inventory.RepoExposureSummaries
	}
	if input.RiskReport.ControlPathGraph != nil &&
		len(input.RiskReport.ControlPathGraph.Nodes) <= scanSummaryInlineGraphNodesCap &&
		len(input.RiskReport.ControlPathGraph.Edges) <= scanSummaryInlineGraphEdgesCap {
		payload["control_path_graph"] = input.RiskReport.ControlPathGraph
	}
	if input.RiskReport.WorkflowChains != nil && len(input.RiskReport.WorkflowChains.Chains) <= scanSummaryInlineWorkflowChainsCap {
		payload["workflow_chains"] = input.RiskReport.WorkflowChains
	}
	return payload
}

func buildScanSuppressedCounts(input scanJSONSummaryInput) *reportcore.SuppressedCounts {
	suppressed := &reportcore.SuppressedCounts{
		Findings:        positiveOverflow(len(input.Findings), scanSummaryInlineFindingsCap),
		RankedFindings:  positiveOverflow(len(input.RiskReport.Ranked), scanSummaryInlineRankedFindingsCap),
		AttackPaths:     positiveOverflow(len(input.RiskReport.AttackPaths), scanSummaryInlineAttackPathsCap),
		ActionPaths:     positiveOverflow(len(input.RiskReport.ActionPaths), scanSummaryInlineActionPathsCap),
		ControlBacklog:  positiveOverflow(len(input.ControlBacklog.Items), scanSummaryInlineBacklogItemsCap),
		InventoryAgents: positiveOverflow(len(input.Inventory.Agents), scanSummaryInlineInventoryAgentsCap),
		InventoryTools:  positiveOverflow(len(input.Inventory.Tools), scanSummaryInlineInventoryToolsCap),
		PrivilegeRows:   positiveOverflow(len(input.Inventory.AgentPrivilegeMap), scanSummaryInlinePrivilegeRowsCap),
		GraphNodes:      0,
		GraphEdges:      0,
		WorkflowChains:  0,
	}
	if input.RiskReport.ControlPathGraph != nil {
		suppressed.GraphNodes = positiveOverflow(len(input.RiskReport.ControlPathGraph.Nodes), scanSummaryInlineGraphNodesCap)
		suppressed.GraphEdges = positiveOverflow(len(input.RiskReport.ControlPathGraph.Edges), scanSummaryInlineGraphEdgesCap)
	}
	if input.RiskReport.WorkflowChains != nil {
		suppressed.WorkflowChains = positiveOverflow(len(input.RiskReport.WorkflowChains.Chains), scanSummaryInlineWorkflowChainsCap)
	}
	if suppressed.ActionPaths == 0 &&
		suppressed.AttackPaths == 0 &&
		suppressed.ControlBacklog == 0 &&
		suppressed.Findings == 0 &&
		suppressed.GraphNodes == 0 &&
		suppressed.GraphEdges == 0 &&
		suppressed.InventoryAgents == 0 &&
		suppressed.InventoryTools == 0 &&
		suppressed.PrivilegeRows == 0 &&
		suppressed.RankedFindings == 0 &&
		suppressed.WorkflowChains == 0 {
		return nil
	}
	return suppressed
}

func buildFindingCounts(findings []source.Finding) map[string]any {
	logicalTotal, logicalByType, rawTotal, rawByType := outputsignal.BuildLogicalFindingCounts(findings)
	out := map[string]any{
		"total":       logicalTotal,
		"by_type":     logicalByType,
		"raw_total":   rawTotal,
		"raw_by_type": rawByType,
	}
	return out
}

func buildToolTypeBreakdown(tools []agginventory.Tool) []map[string]any {
	byType := map[string]int{}
	for _, tool := range tools {
		toolType := strings.TrimSpace(tool.ToolType)
		if toolType == "" {
			continue
		}
		byType[toolType]++
	}
	keys := make([]string, 0, len(byType))
	for key := range byType {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		out = append(out, map[string]any{
			"tool_type": key,
			"count":     byType[key],
		})
	}
	return out
}

func positiveOverflow(size int, limit int) int {
	if size <= 0 {
		return 0
	}
	if limit <= 0 {
		return size
	}
	return outputsignal.PositiveOverflow(size, limit)
}

func scanPreview[T any](items []T, limit int) []T {
	if limit <= 0 {
		return nil
	}
	if len(items) == 0 {
		return []T{}
	}
	if len(items) <= limit {
		return append([]T(nil), items...)
	}
	return append([]T(nil), items[:limit]...)
}

func scanInventoryPreview(input agginventory.Inventory) *agginventory.Inventory {
	inventory := input
	inventory.Agents = scanPreview(input.Agents, scanSummaryInlineInventoryAgentsCap)
	inventory.Tools = scanPreview(input.Tools, scanSummaryInlineInventoryToolsCap)
	inventory.AgentPrivilegeMap = scanPreview(input.AgentPrivilegeMap, scanSummaryInlinePrivilegeRowsCap)
	if len(input.Agents) > scanSummaryInlineInventoryAgentsCap ||
		len(input.Tools) > scanSummaryInlineInventoryToolsCap ||
		len(input.AgentPrivilegeMap) > scanSummaryInlinePrivilegeRowsCap {
		inventory.CanonicalStores = nil
		inventory.NonHumanIdentities = nil
		inventory.LifecycleQueue = nil
	}
	return &inventory
}

func summarizeArtifactFindings(findings []source.Finding, scanMode string) []source.Finding {
	if len(findings) == 0 {
		return nil
	}
	if strings.TrimSpace(scanMode) == "deep" {
		return append([]source.Finding(nil), findings...)
	}
	out := make([]source.Finding, 0, len(findings))
	for _, finding := range findings {
		if !retainArtifactFinding(finding) {
			continue
		}
		out = append(out, finding)
	}
	return out
}

func retainArtifactFinding(finding source.Finding) bool {
	if finding.FindingType != "parse_error" && finding.ParseError == nil {
		return true
	}
	kind := ""
	detector := strings.TrimSpace(finding.Detector)
	toolType := strings.TrimSpace(finding.ToolType)
	if finding.ParseError != nil {
		kind = strings.TrimSpace(finding.ParseError.Kind)
		if detector == "" {
			detector = strings.TrimSpace(finding.ParseError.Detector)
		}
	}
	switch {
	case kind == "unsafe_path", kind == "schema_validation_error":
		return true
	case detector == "gaitpolicy", detector == "mcp", detector == "mcpgateway", detector == "webmcp", detector == "codex", detector == "cursor", detector == "claude", detector == "copilot", detector == "ciagent", detector == "a2a", detector == "secret":
		return true
	case toolType == "gait_policy", toolType == "mcp", toolType == "mcp_gateway", toolType == "webmcp", toolType == "codex", toolType == "cursor", toolType == "claude", toolType == "copilot", toolType == "ci_agent", toolType == "a2a", toolType == "secret":
		return true
	default:
		return false
	}
}
