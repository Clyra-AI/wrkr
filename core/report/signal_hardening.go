package report

import (
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	"github.com/Clyra-AI/wrkr/core/model"
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
	defaultPolicyRepoRefs    = 3
	defaultMarkdownLineCap   = 1500
)

func BuildPolicyOutcomes(findings []model.Finding) []PolicyOutcome {
	type outcomeKey struct {
		ruleID      string
		checkResult string
		severity    string
	}
	type outcomeAccumulator struct {
		ruleID      string
		checkResult string
		severity    string
		repoSet     map[string]struct{}
		repoRefs    []string
		count       int
	}

	accumulators := map[outcomeKey]*outcomeAccumulator{}
	for _, finding := range findings {
		if finding.FindingType != "policy_check" && finding.FindingType != "policy_violation" {
			continue
		}
		key := outcomeKey{
			ruleID:      strings.TrimSpace(finding.RuleID),
			checkResult: strings.TrimSpace(finding.CheckResult),
			severity:    strings.TrimSpace(finding.Severity),
		}
		acc, ok := accumulators[key]
		if !ok {
			acc = &outcomeAccumulator{
				ruleID:      key.ruleID,
				checkResult: key.checkResult,
				severity:    key.severity,
				repoSet:     map[string]struct{}{},
			}
			accumulators[key] = acc
		}
		acc.count++
		repoRef := policyOutcomeRepoRef(finding)
		if repoRef == "" {
			continue
		}
		if _, seen := acc.repoSet[repoRef]; seen {
			continue
		}
		acc.repoSet[repoRef] = struct{}{}
		acc.repoRefs = append(acc.repoRefs, repoRef)
	}

	out := make([]PolicyOutcome, 0, len(accumulators))
	for _, acc := range accumulators {
		sort.Strings(acc.repoRefs)
		topRefs := append([]string(nil), acc.repoRefs...)
		suppressedCount := 0
		if len(topRefs) > defaultPolicyRepoRefs {
			suppressedCount = len(topRefs) - defaultPolicyRepoRefs
			topRefs = topRefs[:defaultPolicyRepoRefs]
		}
		out = append(out, PolicyOutcome{
			OutcomeID:         stablePolicyOutcomeID(acc.ruleID, acc.checkResult, acc.severity),
			RuleID:            acc.ruleID,
			CheckResult:       acc.checkResult,
			Severity:          acc.severity,
			OccurrenceCount:   acc.count,
			AffectedRepoCount: len(acc.repoRefs),
			TopRepoRefs:       topRefs,
			SuppressedCount:   suppressedCount,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OccurrenceCount != out[j].OccurrenceCount {
			return out[i].OccurrenceCount > out[j].OccurrenceCount
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		if out[i].CheckResult != out[j].CheckResult {
			return out[i].CheckResult < out[j].CheckResult
		}
		return out[i].Severity < out[j].Severity
	})
	return out
}

func ApplySummaryCaps(summary *Summary) {
	if summary == nil {
		return
	}
	suppressed := &SuppressedCounts{}

	var count int
	summary.ActionPaths, count = capSlice(summary.ActionPaths, defaultMaxActionPaths)
	suppressed.ActionPaths = count

	if summary.ControlBacklog != nil {
		summary.ControlBacklog.Items, count = capSlice(summary.ControlBacklog.Items, defaultMaxBacklogItems)
		suppressed.ControlBacklog = count
	}
	if summary.ControlPathGraph != nil {
		summary.ControlPathGraph.Nodes, count = capSlice(summary.ControlPathGraph.Nodes, defaultMaxGraphNodes)
		suppressed.GraphNodes = count
		summary.ControlPathGraph.Edges, count = capSlice(summary.ControlPathGraph.Edges, defaultMaxGraphEdges)
		suppressed.GraphEdges = count
	}
	if summary.WorkflowChains != nil {
		summary.WorkflowChains.Chains, count = capSlice(summary.WorkflowChains.Chains, defaultMaxWorkflowChains)
		suppressed.WorkflowChains = count
	}
	if summary.ExposureGroups != nil {
		summary.ExposureGroups, count = capSlice(summary.ExposureGroups, defaultMaxExposureGroups)
		suppressed.ExposureGroups = count
	}
	if summary.AgentActionBOM != nil {
		summary.AgentActionBOM.Items, count = capSlice(summary.AgentActionBOM.Items, defaultMaxAgentActionBOM)
		suppressed.AgentActionBOM = count
	}

	if suppressed.ActionPaths == 0 &&
		suppressed.ControlBacklog == 0 &&
		suppressed.GraphNodes == 0 &&
		suppressed.GraphEdges == 0 &&
		suppressed.WorkflowChains == 0 &&
		suppressed.ExposureGroups == 0 &&
		suppressed.AgentActionBOM == 0 &&
		suppressed.MarkdownLines == 0 {
		summary.SuppressedCounts = nil
		return
	}
	summary.SuppressedCounts = suppressed
}

func BuildSuppressedCountsForScan(r risk.Report, backlog *controlbacklog.Backlog) *SuppressedCounts {
	suppressed := &SuppressedCounts{}
	suppressed.ActionPaths = positiveOverflow(len(r.ActionPaths), defaultMaxActionPaths)
	if backlog != nil {
		suppressed.ControlBacklog = positiveOverflow(len(backlog.Items), defaultMaxBacklogItems)
	}
	if r.ControlPathGraph != nil {
		suppressed.GraphNodes = positiveOverflow(len(r.ControlPathGraph.Nodes), defaultMaxGraphNodes)
		suppressed.GraphEdges = positiveOverflow(len(r.ControlPathGraph.Edges), defaultMaxGraphEdges)
	}
	if r.WorkflowChains != nil {
		suppressed.WorkflowChains = positiveOverflow(len(r.WorkflowChains.Chains), defaultMaxWorkflowChains)
	}
	if suppressed.ActionPaths == 0 &&
		suppressed.ControlBacklog == 0 &&
		suppressed.GraphNodes == 0 &&
		suppressed.GraphEdges == 0 &&
		suppressed.WorkflowChains == 0 {
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

func capSlice[T any](values []T, limit int) ([]T, int) {
	if len(values) <= limit || limit <= 0 {
		return values, 0
	}
	suppressed := len(values) - limit
	return append([]T(nil), values[:limit]...), suppressed
}

func positiveOverflow(size int, limit int) int {
	if limit <= 0 || size <= limit {
		return 0
	}
	return size - limit
}

func policyOutcomeRepoRef(finding model.Finding) string {
	repo := strings.TrimSpace(finding.Repo)
	org := strings.TrimSpace(finding.Org)
	switch {
	case org != "" && repo != "":
		return org + "/" + repo
	case repo != "":
		return repo
	default:
		return org
	}
}

func stablePolicyOutcomeID(ruleID, checkResult, severity string) string {
	parts := []string{
		strings.TrimSpace(ruleID),
		strings.TrimSpace(checkResult),
		strings.TrimSpace(severity),
	}
	return redactValue("policy", strings.Join(parts, "|"), 10)
}
