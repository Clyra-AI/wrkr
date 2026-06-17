package report

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/outputsignal"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const (
	defaultMaxActionPaths     = 150
	defaultMaxBacklogItems    = 150
	defaultMaxGraphNodes      = 5000
	defaultMaxGraphEdges      = 7500
	defaultMaxWorkflowChains  = 150
	defaultMaxExposureGroups  = 150
	defaultMaxAgentActionBOM  = 5
	defaultMarkdownLineCap    = 1500
	defaultBOMMarkdownLineCap = 300
	defaultBOMLeadLineCap     = 45
	defaultBOMLeadSectionCap  = 4
	defaultBOMLeadTopPaths    = 5
	defaultBOMInspectCards    = 5
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
		summary.AgentActionBOM.Items, count = capAgentActionBOMItems(summary.AgentActionBOM.Items, defaultMaxAgentActionBOM)
		suppressed.AgentActionBOM = count
	}

	if !outputsignal.HasSuppressedCounts(suppressed) {
		summary.SuppressedCounts = nil
		return
	}
	summary.SuppressedCounts = suppressed
}

func capAgentActionBOMItems(items []AgentActionBOMItem, limit int) ([]AgentActionBOMItem, int) {
	if limit <= 0 || len(items) <= limit {
		return items, 0
	}
	capped := append([]AgentActionBOMItem(nil), items[:limit]...)
	for _, lane := range []string{risk.ConfidenceLaneConfirmedActionPath, risk.ConfidenceLaneSemanticReviewCandidate} {
		if bomItemsContainLane(capped, lane) {
			continue
		}
		candidate, ok := firstBOMItemByLane(items, lane, capped)
		if !ok {
			continue
		}
		capped[replacementIndexForBOMLaneDiversity(capped)] = candidate
	}
	return capped, len(items) - len(capped)
}

func bomItemsContainLane(items []AgentActionBOMItem, lane string) bool {
	for _, item := range items {
		if strings.TrimSpace(item.ConfidenceLane) == lane {
			return true
		}
	}
	return false
}

func firstBOMItemByLane(items []AgentActionBOMItem, lane string, excluded []AgentActionBOMItem) (AgentActionBOMItem, bool) {
	for _, item := range items {
		if strings.TrimSpace(item.ConfidenceLane) != lane {
			continue
		}
		if bomItemsContainItem(excluded, item) {
			continue
		}
		return item, true
	}
	return AgentActionBOMItem{}, false
}

func bomItemsContainItem(items []AgentActionBOMItem, candidate AgentActionBOMItem) bool {
	candidateKey := bomItemDiversityKey(candidate)
	for _, item := range items {
		if bomItemDiversityKey(item) == candidateKey {
			return true
		}
	}
	return false
}

func bomItemDiversityKey(item AgentActionBOMItem) string {
	parts := []string{
		strings.TrimSpace(item.PathID),
		strings.TrimSpace(item.Repo),
		strings.TrimSpace(item.Location),
		strings.TrimSpace(item.ConfidenceLane),
	}
	return strings.Join(parts, "\x00")
}

func replacementIndexForBOMLaneDiversity(items []AgentActionBOMItem) int {
	laneCounts := map[string]int{}
	for _, item := range items {
		laneCounts[strings.TrimSpace(item.ConfidenceLane)]++
	}
	for idx := len(items) - 1; idx >= 0; idx-- {
		lane := strings.TrimSpace(items[idx].ConfidenceLane)
		switch lane {
		case risk.ConfidenceLaneConfirmedActionPath, risk.ConfidenceLaneSemanticReviewCandidate:
			continue
		default:
			return idx
		}
	}
	for idx := len(items) - 1; idx >= 0; idx-- {
		lane := strings.TrimSpace(items[idx].ConfidenceLane)
		if laneCounts[lane] > 1 {
			return idx
		}
	}
	return len(items) - 1
}

func BuildSuppressedCountsForScan(r risk.Report, backlog *controlbacklog.Backlog) *SuppressedCounts {
	suppressed := &SuppressedCounts{}
	suppressed.ActionPaths = outputsignal.PositiveOverflow(len(r.ActionPaths), defaultMaxActionPaths)
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
	return applyMarkdownBudgetWithCap(markdown, defaultMarkdownLineCap)
}

func ApplyMarkdownBudgetForTemplate(markdown string, template string) (string, int) {
	lineCap := defaultMarkdownLineCap
	if strings.TrimSpace(template) == string(TemplateAgentActionBOM) {
		lineCap = defaultBOMMarkdownLineCap
	}
	return applyMarkdownBudgetWithCap(markdown, lineCap)
}

func applyMarkdownBudgetWithCap(markdown string, lineCap int) (string, int) {
	lines := strings.Split(strings.TrimRight(markdown, "\n"), "\n")
	if lineCap <= 0 || len(lines) <= lineCap {
		if strings.HasSuffix(markdown, "\n") {
			return markdown, 0
		}
		return markdown + "\n", 0
	}
	suppressed := len(lines) - lineCap
	kept := append([]string(nil), lines[:lineCap]...)
	kept = append(kept, "", "... output truncated to stay within the markdown line budget ...")
	return strings.Join(kept, "\n") + "\n", suppressed
}
