package cli

import (
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/compliance"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
)

const (
	scanSummaryInlineFindingsCap       = 200
	scanSummaryInlineRankedFindingsCap = 1000
	scanSummaryInlineActionPathsCap    = 100
	scanSummaryInlineAttackPathsCap    = 100
	scanSummaryInlineBacklogItemsCap   = 100
	scanSummaryInlineInventoryToolsCap = 100
	scanSummaryInlinePrivilegeRowsCap  = 150
	scanSummaryInlineGraphNodesCap     = 500
	scanSummaryInlineGraphEdgesCap     = 1000
	scanSummaryInlineWorkflowChainsCap = 100
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
		"policy_outcomes":     reportcore.BuildPolicyOutcomes(input.Findings),
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
	if suppressed := reportcore.BuildSuppressedCountsForScan(input.RiskReport, &input.ControlBacklog); suppressed != nil {
		payload["suppressed_counts"] = suppressed
	}
	if len(input.RiskReport.TopN) > 0 {
		payload["top_findings"] = input.RiskReport.TopN
	}
	if len(input.Findings) <= scanSummaryInlineFindingsCap {
		payload["findings"] = input.Findings
	}
	if len(input.RiskReport.Ranked) <= scanSummaryInlineRankedFindingsCap {
		payload["ranked_findings"] = input.RiskReport.Ranked
	}
	if len(input.RiskReport.AttackPaths) <= scanSummaryInlineAttackPathsCap {
		payload["attack_paths"] = input.RiskReport.AttackPaths
	}
	if len(input.RiskReport.TopAttackPaths) <= scanSummaryInlineAttackPathsCap {
		payload["top_attack_paths"] = input.RiskReport.TopAttackPaths
	}
	if len(input.RiskReport.ActionPaths) <= scanSummaryInlineActionPathsCap {
		payload["action_paths"] = input.RiskReport.ActionPaths
	}
	if input.RiskReport.ActionPathToControlFirst != nil {
		payload["action_path_to_control_first"] = input.RiskReport.ActionPathToControlFirst
	}
	if len(input.ControlBacklog.Items) <= scanSummaryInlineBacklogItemsCap {
		payload["control_backlog"] = input.ControlBacklog
	}
	if len(input.Inventory.Tools) <= scanSummaryInlineInventoryToolsCap && len(input.Inventory.AgentPrivilegeMap) <= scanSummaryInlinePrivilegeRowsCap {
		payload["inventory"] = input.Inventory
		payload["agent_privilege_map"] = input.Inventory.AgentPrivilegeMap
	}
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

func buildFindingCounts(findings []source.Finding) map[string]any {
	counts := map[string]int{}
	for _, finding := range findings {
		counts[strings.TrimSpace(finding.FindingType)]++
	}
	out := map[string]any{
		"total":   len(findings),
		"by_type": counts,
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
