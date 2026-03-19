package compliance

import (
	"fmt"
	"sort"
	"strings"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/proof/core/framework"
	"github.com/Clyra-AI/wrkr/core/model"
)

type RollupSummary struct {
	Frameworks []FrameworkRollup `json:"frameworks"`
}

type FrameworkRollup struct {
	FrameworkID        string          `json:"framework_id"`
	Title              string          `json:"title"`
	Version            string          `json:"version"`
	ControlCount       int             `json:"control_count"`
	CoveredCount       int             `json:"covered_count"`
	CoveragePercent    float64         `json:"coverage_percent"`
	MappedFindingCount int             `json:"mapped_finding_count"`
	Controls           []ControlRollup `json:"controls"`
}

type ControlRollup struct {
	ControlID     string   `json:"control_id"`
	Title         string   `json:"title"`
	ControlKind   string   `json:"control_kind"`
	Status        string   `json:"status"`
	MappedRuleIDs []string `json:"mapped_rule_ids,omitempty"`
	FindingCount  int      `json:"finding_count"`
}

func BuildRollupSummary(findings []model.Finding, chain *proof.Chain) (RollupSummary, error) {
	if chain == nil {
		return RollupSummary{}, fmt.Errorf("proof chain is required")
	}

	frameworkIDs := mappedFrameworkIDs()
	ruleFindingIndex := buildRuleFindingIndex(findings)
	frameworks := make([]FrameworkRollup, 0, len(frameworkIDs))

	for _, frameworkID := range frameworkIDs {
		frameworkDef, err := proof.LoadFramework(frameworkID)
		if err != nil {
			return RollupSummary{}, fmt.Errorf("load framework %s: %w", frameworkID, err)
		}
		result, err := Evaluate(Input{Framework: frameworkDef, Chain: chain})
		if err != nil {
			return RollupSummary{}, fmt.Errorf("evaluate framework %s: %w", frameworkID, err)
		}
		frameworks = append(frameworks, buildFrameworkRollup(frameworkDef, result, ruleFindingIndex))
	}

	return RollupSummary{Frameworks: frameworks}, nil
}

func ExplainRollupSummary(summary RollupSummary, limit int) []string {
	lines := make([]string, 0)
	for _, framework := range summary.Frameworks {
		for _, control := range framework.Controls {
			if control.FindingCount == 0 {
				continue
			}
			lines = append(lines, fmt.Sprintf("%d findings map to %s %s (%s)", control.FindingCount, framework.Title, strings.ToUpper(control.ControlID), control.Title))
		}
	}
	if len(lines) == 0 {
		lines = append(lines, "bundled framework mappings are available; current findings do not map to bundled compliance controls yet")
	}

	if guidance := explainEvidenceStateGuidance(summary); guidance != "" {
		if limit > 0 && len(lines) >= limit {
			out := append([]string(nil), lines[:limit-1]...)
			out = append(out, guidance)
			return out
		}
		lines = append(lines, guidance)
	}

	if limit > 0 && len(lines) > limit {
		return append([]string(nil), lines[:limit]...)
	}
	return lines
}

func explainEvidenceStateGuidance(summary RollupSummary) string {
	totalControls := 0
	coveredControls := 0
	totalMappedFindings := 0

	for _, framework := range summary.Frameworks {
		totalControls += framework.ControlCount
		coveredControls += framework.CoveredCount
		totalMappedFindings += framework.MappedFindingCount
	}

	if totalMappedFindings == 0 {
		return "coverage still reflects only controls evidenced in the current scan state; remediate gaps, rescan, and regenerate report/evidence artifacts"
	}
	if totalControls > 0 && coveredControls*2 < totalControls {
		return "coverage still reflects only controls evidenced in the current scan state; remediate gaps, rescan, and regenerate report/evidence artifacts"
	}
	return ""
}

func buildFrameworkRollup(frameworkDef *proof.Framework, result Result, ruleFindingIndex map[string]map[string]struct{}) FrameworkRollup {
	controlChecks := make(map[string]ControlCheck, len(result.Controls))
	for _, check := range result.Controls {
		controlChecks[strings.TrimSpace(check.ID)] = check
	}

	controls := flatten(frameworkDef.Controls)
	controlRollups := make([]ControlRollup, 0, len(controls))
	frameworkFindingKeys := map[string]struct{}{}

	for _, control := range controls {
		rollup := buildControlRollup(result.FrameworkID, control, controlChecks[strings.TrimSpace(control.ID)], ruleFindingIndex)
		for _, key := range mappedFindingKeys(result.FrameworkID, control.ID, ruleFindingIndex) {
			frameworkFindingKeys[key] = struct{}{}
		}
		controlRollups = append(controlRollups, rollup)
	}

	return FrameworkRollup{
		FrameworkID:        result.FrameworkID,
		Title:              result.Title,
		Version:            result.Version,
		ControlCount:       result.ControlCount,
		CoveredCount:       result.CoveredCount,
		CoveragePercent:    result.Coverage,
		MappedFindingCount: len(frameworkFindingKeys),
		Controls:           controlRollups,
	}
}

func buildControlRollup(frameworkID string, control framework.Control, check ControlCheck, ruleFindingIndex map[string]map[string]struct{}) ControlRollup {
	controlID := strings.TrimSpace(control.ID)
	title := strings.TrimSpace(control.Title)
	if title == "" {
		title = strings.TrimSpace(check.Title)
	}
	return ControlRollup{
		ControlID:     controlID,
		Title:         title,
		ControlKind:   classifyControlKind(controlID),
		Status:        strings.TrimSpace(check.Status),
		MappedRuleIDs: controlRuleIDs(frameworkID, controlID),
		FindingCount:  len(mappedFindingKeys(frameworkID, controlID, ruleFindingIndex)),
	}
}

func mappedFrameworkIDs() []string {
	out := make([]string, 0, len(frameworkControlRuleMap))
	for frameworkID := range frameworkControlRuleMap {
		out = append(out, frameworkID)
	}
	sort.Strings(out)
	return out
}

func buildRuleFindingIndex(findings []model.Finding) map[string]map[string]struct{} {
	ordered := append([]model.Finding(nil), findings...)
	model.SortFindings(ordered)

	out := map[string]map[string]struct{}{}
	for _, finding := range ordered {
		ruleID := strings.TrimSpace(finding.RuleID)
		if ruleID == "" {
			continue
		}
		if out[ruleID] == nil {
			out[ruleID] = map[string]struct{}{}
		}
		out[ruleID][findingRollupKey(finding)] = struct{}{}
	}
	return out
}

func controlRuleIDs(frameworkID, controlID string) []string {
	controls := frameworkControlRuleMap[strings.TrimSpace(frameworkID)]
	if len(controls) == 0 {
		return nil
	}
	return uniqueSortedStrings(controls[strings.TrimSpace(controlID)])
}

func mappedFindingKeys(frameworkID, controlID string, ruleFindingIndex map[string]map[string]struct{}) []string {
	keys := map[string]struct{}{}
	for _, ruleID := range controlRuleIDs(frameworkID, controlID) {
		for key := range ruleFindingIndex[ruleID] {
			keys[key] = struct{}{}
		}
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func classifyControlKind(controlID string) string {
	switch {
	case strings.HasPrefix(strings.TrimSpace(controlID), "article-"):
		return "article"
	case strings.HasPrefix(strings.TrimSpace(controlID), "req-"):
		return "requirement"
	default:
		return "control"
	}
}

func findingRollupKey(finding model.Finding) string {
	normalized := model.NormalizeFinding(finding)
	startLine := 0
	endLine := 0
	if normalized.LocationRange != nil {
		startLine = normalized.LocationRange.StartLine
		endLine = normalized.LocationRange.EndLine
	}
	return strings.Join([]string{
		normalized.RuleID,
		normalized.FindingType,
		normalized.ToolType,
		normalized.Location,
		fmt.Sprintf("%d", startLine),
		fmt.Sprintf("%d", endLine),
		normalized.Repo,
		normalized.Org,
	}, "|")
}
