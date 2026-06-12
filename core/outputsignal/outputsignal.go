package outputsignal

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
)

const DefaultPolicyRepoRefs = 3

type PolicyOutcome struct {
	OutcomeID         string   `json:"outcome_id"`
	RuleID            string   `json:"rule_id"`
	CheckResult       string   `json:"check_result"`
	Severity          string   `json:"severity,omitempty"`
	OccurrenceCount   int      `json:"occurrence_count"`
	AffectedRepoCount int      `json:"affected_repo_count"`
	TopRepoRefs       []string `json:"top_repo_refs,omitempty"`
	SuppressedCount   int      `json:"suppressed_count,omitempty"`
}

type SuppressedCounts struct {
	Findings              int `json:"findings,omitempty"`
	RankedFindings        int `json:"ranked_findings,omitempty"`
	AttackPaths           int `json:"attack_paths,omitempty"`
	ActionPaths           int `json:"action_paths,omitempty"`
	ControlBacklog        int `json:"control_backlog,omitempty"`
	InventoryAgents       int `json:"inventory_agents,omitempty"`
	InventoryTools        int `json:"inventory_tools,omitempty"`
	PrivilegeRows         int `json:"privilege_rows,omitempty"`
	GraphNodes            int `json:"graph_nodes,omitempty"`
	GraphEdges            int `json:"graph_edges,omitempty"`
	WorkflowChains        int `json:"workflow_chains,omitempty"`
	RepoExposureSummaries int `json:"repo_exposure_summaries,omitempty"`
	ExposureGroups        int `json:"exposure_groups,omitempty"`
	AgentActionBOM        int `json:"agent_action_bom,omitempty"`
	MarkdownLines         int `json:"markdown_lines,omitempty"`
	ControlEvidence       int `json:"control_evidence,omitempty"`
	ReportArtifacts       int `json:"report_artifacts,omitempty"`
}

type policyOutcomeKey struct {
	ruleID      string
	checkResult string
	severity    string
}

type policyOutcomeAccumulator struct {
	ruleID      string
	checkResult string
	severity    string
	repoSet     map[string]struct{}
	repoRefs    []string
	count       int
}

func BuildPolicyOutcomes(findings []model.Finding) []PolicyOutcome {
	accumulators := map[policyOutcomeKey]*policyOutcomeAccumulator{}
	for _, finding := range findings {
		if finding.FindingType != "policy_check" && finding.FindingType != "policy_violation" {
			continue
		}
		key := policyOutcomeKey{
			ruleID:      strings.TrimSpace(finding.RuleID),
			checkResult: strings.TrimSpace(finding.CheckResult),
			severity:    strings.TrimSpace(finding.Severity),
		}
		acc := accumulators[key]
		if acc == nil {
			acc = &policyOutcomeAccumulator{
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
		if len(topRefs) > DefaultPolicyRepoRefs {
			suppressedCount = len(topRefs) - DefaultPolicyRepoRefs
			topRefs = topRefs[:DefaultPolicyRepoRefs]
		}
		out = append(out, PolicyOutcome{
			OutcomeID:         StablePolicyOutcomeID(acc.ruleID, acc.checkResult, acc.severity),
			RuleID:            acc.ruleID,
			CheckResult:       acc.checkResult,
			Severity:          acc.severity,
			OccurrenceCount:   acc.count,
			AffectedRepoCount: len(acc.repoRefs),
			TopRepoRefs:       topRefs,
			SuppressedCount:   suppressedCount,
		})
	}
	if len(out) == 0 {
		return nil
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

func StablePolicyOutcomeID(ruleID, checkResult, severity string) string {
	parts := []string{
		strings.TrimSpace(ruleID),
		strings.TrimSpace(checkResult),
		strings.TrimSpace(severity),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return fmt.Sprintf("policy-%s", hex.EncodeToString(sum[:])[:10])
}

func PolicyOutcomeIDForFinding(finding model.Finding) string {
	if trimmed := strings.TrimSpace(finding.PolicyOutcomeID); trimmed != "" {
		return trimmed
	}
	return StablePolicyOutcomeID(finding.RuleID, finding.CheckResult, finding.Severity)
}

func CompactFindingsForSeverity(findings []model.Finding) []model.Finding {
	if len(findings) == 0 {
		return nil
	}

	ordered := append([]model.Finding(nil), findings...)
	model.SortFindings(ordered)

	out := make([]model.Finding, 0, len(ordered))
	policyByOutcome := map[string]model.Finding{}
	for _, finding := range ordered {
		if finding.FindingType != "policy_check" && finding.FindingType != "policy_violation" {
			out = append(out, finding)
			continue
		}
		outcomeID := PolicyOutcomeIDForFinding(finding)
		current, ok := policyByOutcome[outcomeID]
		if !ok || shouldReplacePolicySeverityRepresentative(current, finding) {
			policyByOutcome[outcomeID] = finding
		}
	}
	keys := make([]string, 0, len(policyByOutcome))
	for key := range policyByOutcome {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		out = append(out, policyByOutcome[key])
	}
	model.SortFindings(out)
	return out
}

func BuildLogicalFindingCounts(findings []model.Finding) (int, map[string]int, int, map[string]int) {
	rawByType := map[string]int{}
	groupedByType := map[string]int{}
	groupedPolicyKeys := map[string]struct{}{}
	rawTotal := 0
	groupedTotal := 0

	for _, finding := range findings {
		findingType := strings.TrimSpace(finding.FindingType)
		if findingType == "" {
			continue
		}
		rawTotal++
		rawByType[findingType]++
		if findingType != "policy_check" && findingType != "policy_violation" {
			groupedTotal++
			groupedByType[findingType]++
			continue
		}
		logicalKey := findingType + "::" + PolicyOutcomeIDForFinding(finding)
		if _, seen := groupedPolicyKeys[logicalKey]; seen {
			continue
		}
		groupedPolicyKeys[logicalKey] = struct{}{}
		groupedTotal++
		groupedByType[findingType]++
	}
	return groupedTotal, groupedByType, rawTotal, rawByType
}

func CapSlice[T any](values []T, limit int) ([]T, int) {
	if len(values) <= limit || limit <= 0 {
		return values, 0
	}
	suppressed := len(values) - limit
	return append([]T(nil), values[:limit]...), suppressed
}

func PositiveOverflow(size int, limit int) int {
	if limit <= 0 || size <= limit {
		return 0
	}
	return size - limit
}

func MergeSuppressedCounts(items ...*SuppressedCounts) *SuppressedCounts {
	merged := &SuppressedCounts{}
	for _, item := range items {
		if item == nil {
			continue
		}
		merged.Findings += item.Findings
		merged.RankedFindings += item.RankedFindings
		merged.AttackPaths += item.AttackPaths
		merged.ActionPaths += item.ActionPaths
		merged.ControlBacklog += item.ControlBacklog
		merged.InventoryAgents += item.InventoryAgents
		merged.InventoryTools += item.InventoryTools
		merged.PrivilegeRows += item.PrivilegeRows
		merged.GraphNodes += item.GraphNodes
		merged.GraphEdges += item.GraphEdges
		merged.WorkflowChains += item.WorkflowChains
		merged.RepoExposureSummaries += item.RepoExposureSummaries
		merged.ExposureGroups += item.ExposureGroups
		merged.AgentActionBOM += item.AgentActionBOM
		merged.MarkdownLines += item.MarkdownLines
		merged.ControlEvidence += item.ControlEvidence
		merged.ReportArtifacts += item.ReportArtifacts
	}
	if !HasSuppressedCounts(merged) {
		return nil
	}
	return merged
}

func HasSuppressedCounts(counts *SuppressedCounts) bool {
	if counts == nil {
		return false
	}
	return counts.Findings > 0 ||
		counts.RankedFindings > 0 ||
		counts.AttackPaths > 0 ||
		counts.ActionPaths > 0 ||
		counts.ControlBacklog > 0 ||
		counts.InventoryAgents > 0 ||
		counts.InventoryTools > 0 ||
		counts.PrivilegeRows > 0 ||
		counts.GraphNodes > 0 ||
		counts.GraphEdges > 0 ||
		counts.WorkflowChains > 0 ||
		counts.RepoExposureSummaries > 0 ||
		counts.ExposureGroups > 0 ||
		counts.AgentActionBOM > 0 ||
		counts.MarkdownLines > 0 ||
		counts.ControlEvidence > 0 ||
		counts.ReportArtifacts > 0
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

func shouldReplacePolicySeverityRepresentative(current model.Finding, candidate model.Finding) bool {
	if current.FindingType != candidate.FindingType {
		return candidate.FindingType == "policy_violation"
	}
	return false
}
