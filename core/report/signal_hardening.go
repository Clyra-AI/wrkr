package report

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/outputsignal"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const (
	defaultMaxActionPaths         = 150
	defaultMaxComposedActionPaths = 150
	defaultMaxBacklogItems        = 150
	defaultMaxGraphNodes          = 5000
	defaultMaxGraphEdges          = 7500
	defaultMaxWorkflowChains      = 150
	defaultMaxExposureGroups      = 150
	defaultMaxAgentActionBOM      = 100
	defaultMarkdownLineCap        = 1500
	defaultBOMLeadLineCap         = 45
	defaultBOMLeadSectionCap      = 4
	defaultBOMLeadTopPaths        = 5
	defaultBOMInspectCards        = 5
)

func BuildPolicyOutcomes(findings []model.Finding) []PolicyOutcome {
	return outputsignal.BuildPolicyOutcomes(findings)
}

func ApplySummaryCaps(summary *Summary) {
	if summary == nil {
		return
	}
	suppressed := &SuppressedCounts{}

	var count int
	summary.ActionPaths, count = outputsignal.CapSlice(summary.ActionPaths, defaultMaxActionPaths)
	suppressed.ActionPaths = count
	summary.ComposedActionPaths, count = outputsignal.CapSlice(summary.ComposedActionPaths, defaultMaxComposedActionPaths)
	suppressed.ComposedActionPaths = count
	allowedCompositionIDs := allowedCompositionIDs(summary.ComposedActionPaths)
	allowedComposedContractRefs := allowedComposedContractRefs(summary.ComposedActionPaths)
	if len(allowedCompositionIDs) > 0 || len(allowedComposedContractRefs) > 0 {
		summary.ActionPaths = filterActionPathCompositionRefs(summary.ActionPaths, allowedCompositionIDs, allowedComposedContractRefs)
		if summary.ActionPathToControlFirst != nil {
			filtered := filterActionPathCompositionRefs([]risk.ActionPath{summary.ActionPathToControlFirst.Path}, allowedCompositionIDs, allowedComposedContractRefs)
			if len(filtered) == 1 {
				summary.ActionPathToControlFirst.Path = filtered[0]
			}
		}
		if summary.AssessmentSummary != nil {
			if summary.AssessmentSummary.TopPathToControlFirst != nil {
				filtered := filterActionPathCompositionRefs([]risk.ActionPath{*summary.AssessmentSummary.TopPathToControlFirst}, allowedCompositionIDs, allowedComposedContractRefs)
				if len(filtered) == 1 {
					summary.AssessmentSummary.TopPathToControlFirst = &filtered[0]
				}
			}
			if summary.AssessmentSummary.TopExecutionIdentityBacked != nil {
				filtered := filterActionPathCompositionRefs([]risk.ActionPath{*summary.AssessmentSummary.TopExecutionIdentityBacked}, allowedCompositionIDs, allowedComposedContractRefs)
				if len(filtered) == 1 {
					summary.AssessmentSummary.TopExecutionIdentityBacked = &filtered[0]
				}
			}
		}
	}

	if summary.ControlBacklog != nil {
		summary.ControlBacklog.Items, count = outputsignal.CapSlice(summary.ControlBacklog.Items, defaultMaxBacklogItems)
		suppressed.ControlBacklog = count
	}
	if summary.ControlPathGraph != nil {
		summary.ControlPathGraph.Nodes, count = outputsignal.CapSlice(summary.ControlPathGraph.Nodes, defaultMaxGraphNodes)
		suppressed.GraphNodes = count
		summary.ControlPathGraph.Edges, count = outputsignal.CapSlice(summary.ControlPathGraph.Edges, defaultMaxGraphEdges)
		suppressed.GraphEdges = count
	}
	if summary.WorkflowChains != nil {
		summary.WorkflowChains.Chains, count = outputsignal.CapSlice(summary.WorkflowChains.Chains, defaultMaxWorkflowChains)
		suppressed.WorkflowChains = count
	}
	if summary.ExposureGroups != nil {
		summary.ExposureGroups, count = outputsignal.CapSlice(summary.ExposureGroups, defaultMaxExposureGroups)
		suppressed.ExposureGroups = count
	}
	if summary.AgentActionBOM != nil {
		summary.AgentActionBOM.ComposedActionPaths = append([]risk.ComposedActionPath(nil), summary.ComposedActionPaths...)
		if len(allowedCompositionIDs) > 0 || len(allowedComposedContractRefs) > 0 {
			if summary.AgentActionBOM.Summary.PrimaryView != nil {
				summary.AgentActionBOM.Summary.PrimaryView.CompositionIDs = filterStringSet(summary.AgentActionBOM.Summary.PrimaryView.CompositionIDs, allowedCompositionIDs)
				summary.AgentActionBOM.Summary.PrimaryView.ProposedActionContractRefs = filterStringSet(summary.AgentActionBOM.Summary.PrimaryView.ProposedActionContractRefs, allowedComposedContractRefs)
			}
			for idx := range summary.AgentActionBOM.Items {
				summary.AgentActionBOM.Items[idx].CompositionIDs = filterStringSet(summary.AgentActionBOM.Items[idx].CompositionIDs, allowedCompositionIDs)
				summary.AgentActionBOM.Items[idx].ProposedActionContractRefs = filterStringSet(summary.AgentActionBOM.Items[idx].ProposedActionContractRefs, allowedComposedContractRefs)
			}
		}
		summary.AgentActionBOM.Items, count = outputsignal.CapSlice(summary.AgentActionBOM.Items, defaultMaxAgentActionBOM)
		suppressed.AgentActionBOM = count
		if summary.AgentActionBOM.Summary.PrimaryView == nil {
			_ = selectAgentActionBOMPrimaryView(summary.AgentActionBOM, "")
		} else {
			for _, item := range summary.AgentActionBOM.focusSourceItems {
				if strings.TrimSpace(item.PathID) == strings.TrimSpace(summary.AgentActionBOM.Summary.PrimaryView.PathID) {
					ensureAgentActionBOMPrimaryItemVisible(summary.AgentActionBOM, item)
					break
				}
			}
		}
	}

	if !outputsignal.HasSuppressedCounts(suppressed) {
		summary.SuppressedCounts = nil
		return
	}
	summary.SuppressedCounts = suppressed
}

func allowedComposedContractRefs(paths []risk.ComposedActionPath) map[string]struct{} {
	out := map[string]struct{}{}
	for _, path := range paths {
		for _, ref := range path.ProposedActionContractRefs {
			if trimmed := strings.TrimSpace(ref); trimmed != "" {
				out[trimmed] = struct{}{}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func allowedCompositionIDs(paths []risk.ComposedActionPath) map[string]struct{} {
	out := map[string]struct{}{}
	for _, path := range paths {
		if trimmed := strings.TrimSpace(path.CompositionID); trimmed != "" {
			out[trimmed] = struct{}{}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func filterActionPathCompositionRefs(paths []risk.ActionPath, allowedCompositionIDs map[string]struct{}, allowedContractRefs map[string]struct{}) []risk.ActionPath {
	if len(paths) == 0 || (len(allowedCompositionIDs) == 0 && len(allowedContractRefs) == 0) {
		return paths
	}
	out := make([]risk.ActionPath, 0, len(paths))
	for _, path := range paths {
		copyPath := path
		copyPath.CompositionIDs = filterStringSet(copyPath.CompositionIDs, allowedCompositionIDs)
		copyPath.ProposedActionContractRefs = filterStringSet(copyPath.ProposedActionContractRefs, allowedContractRefs)
		out = append(out, copyPath)
	}
	return out
}

func filterStringSet(values []string, allowed map[string]struct{}) []string {
	if len(values) == 0 || len(allowed) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			if _, ok := allowed[trimmed]; ok {
				out = append(out, trimmed)
			}
		}
	}
	return out
}

func BuildSuppressedCountsForScan(r risk.Report, backlog *controlbacklog.Backlog) *SuppressedCounts {
	suppressed := &SuppressedCounts{}
	suppressed.ActionPaths = outputsignal.PositiveOverflow(len(r.ActionPaths), defaultMaxActionPaths)
	suppressed.ComposedActionPaths = outputsignal.PositiveOverflow(len(r.ComposedActionPaths), defaultMaxComposedActionPaths)
	if backlog != nil {
		suppressed.ControlBacklog = outputsignal.PositiveOverflow(len(backlog.Items), defaultMaxBacklogItems)
	}
	if r.ControlPathGraph != nil {
		suppressed.GraphNodes = outputsignal.PositiveOverflow(len(r.ControlPathGraph.Nodes), defaultMaxGraphNodes)
		suppressed.GraphEdges = outputsignal.PositiveOverflow(len(r.ControlPathGraph.Edges), defaultMaxGraphEdges)
	}
	if r.WorkflowChains != nil {
		suppressed.WorkflowChains = outputsignal.PositiveOverflow(len(r.WorkflowChains.Chains), defaultMaxWorkflowChains)
	}
	if !outputsignal.HasSuppressedCounts(suppressed) {
		return nil
	}
	return suppressed
}

func sanitizePolicyOutcomesWithConfig(in []PolicyOutcome, config RedactionConfig) []PolicyOutcome {
	if len(in) == 0 {
		return nil
	}
	out := make([]PolicyOutcome, 0, len(in))
	for _, item := range in {
		copyItem := item
		if config.Has(RedactionRepos) {
			for idx := range copyItem.TopRepoRefs {
				copyItem.TopRepoRefs[idx] = redactValue("repo", copyItem.TopRepoRefs[idx], 6)
			}
		}
		out = append(out, copyItem)
	}
	return out
}

func ApplyMarkdownBudget(markdown string) (string, int) {
	lines := strings.Split(strings.TrimRight(markdown, "\n"), "\n")
	if len(lines) <= defaultMarkdownLineCap {
		if strings.HasSuffix(markdown, "\n") {
			return markdown, 0
		}
		return markdown + "\n", 0
	}
	noteLines := []string{"", "... output truncated to stay within the markdown line budget ..."}
	keepLimit := defaultMarkdownLineCap - len(noteLines)
	if keepLimit < 0 {
		keepLimit = 0
	}
	suppressed := len(lines) - keepLimit
	kept := append([]string(nil), lines[:keepLimit]...)
	kept = append(kept, noteLines...)
	return strings.Join(kept, "\n") + "\n", suppressed
}
