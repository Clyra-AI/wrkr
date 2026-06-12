package report

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/outputsignal"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const (
	defaultMaxActionPaths    = 150
	defaultMaxBacklogItems   = 150
	defaultMaxGraphNodes     = 5000
	defaultMaxGraphEdges     = 7500
	defaultMaxWorkflowChains = 150
	defaultMaxExposureGroups = 150
	defaultMaxAgentActionBOM = 100
	defaultMarkdownLineCap   = 1500
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
		summary.AgentActionBOM.Items, count = outputsignal.CapSlice(summary.AgentActionBOM.Items, defaultMaxAgentActionBOM)
		suppressed.AgentActionBOM = count
	}

	if !outputsignal.HasSuppressedCounts(suppressed) {
		summary.SuppressedCounts = nil
		return
	}
	summary.SuppressedCounts = suppressed
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
	lines := strings.Split(strings.TrimRight(markdown, "\n"), "\n")
	if len(lines) <= defaultMarkdownLineCap {
		if strings.HasSuffix(markdown, "\n") {
			return markdown, 0
		}
		return markdown + "\n", 0
	}
	suppressed := len(lines) - defaultMarkdownLineCap
	kept := append([]string(nil), lines[:defaultMarkdownLineCap]...)
	kept = append(kept, "", "... output truncated to stay within the markdown line budget ...")
	return strings.Join(kept, "\n") + "\n", suppressed
}
