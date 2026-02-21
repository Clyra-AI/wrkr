package fix

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/risk"
)

// BuildPlan returns deterministic remediation previews for top-ranked findings.
func BuildPlan(ranked []risk.ScoredFinding, top int) (Plan, error) {
	if top <= 0 {
		top = len(ranked)
	}

	templates, err := templatesByID()
	if err != nil {
		return Plan{}, err
	}

	candidates := append([]risk.ScoredFinding(nil), ranked...)
	sortCandidates(candidates)

	remediations := make([]Remediation, 0, top)
	skipped := make([]Skipped, 0)
	for _, candidate := range candidates {
		if len(remediations) >= top {
			break
		}

		selected, reasonCode, message := chooseTemplateID(candidate)
		if reasonCode != "" {
			skipped = append(skipped, skippedFinding(candidate, reasonCode, message))
			continue
		}
		template, ok := templates[selected]
		if !ok {
			skipped = append(skipped, skippedFinding(candidate, ReasonMissingRuleTemplate, "no remediation template for selected rule/template"))
			continue
		}

		remediations = append(remediations, Remediation{
			ID:            remediationID(candidate, template.ID),
			TemplateID:    template.ID,
			Category:      template.Category,
			RuleID:        strings.TrimSpace(candidate.Finding.RuleID),
			Title:         template.Title,
			Rationale:     rationale(candidate),
			CommitMessage: commitMessage(template, candidate),
			PatchPreview:  patchPreview(template, candidate),
			Finding:       candidate.Finding,
		})
	}

	plan := Plan{
		RequestedTop: top,
		Remediations: remediations,
		Skipped:      skipped,
	}
	plan.Fingerprint = planFingerprint(remediations, skipped)
	return plan, nil
}

func sortCandidates(in []risk.ScoredFinding) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Score != in[j].Score {
			return in[i].Score > in[j].Score
		}
		return canonicalFindingKey(in[i].Finding) < canonicalFindingKey(in[j].Finding)
	})
}

func chooseTemplateID(candidate risk.ScoredFinding) (templateID, reasonCode, message string) {
	finding := candidate.Finding
	location := strings.TrimSpace(finding.Location)
	if location == "" {
		return "", ReasonMissingLocation, "finding location is required to generate a deterministic patch preview"
	}
	if isAmbiguousLocation(location) {
		return "", ReasonAmbiguousPatchTarget, "finding location is ambiguous for deterministic patching"
	}

	ruleID := strings.ToUpper(strings.TrimSpace(finding.RuleID))
	if (finding.FindingType == "policy_violation" || finding.FindingType == "policy_check") && ruleID != "" {
		return ruleID, "", ""
	}

	switch strings.TrimSpace(finding.FindingType) {
	case "skill_policy_conflict":
		return "WRKR-014", "", ""
	case "skill_metrics":
		return "WRKR-015", "", ""
	case "ai_dependency":
		return "DEPENDENCY-PIN", "", ""
	case "mcp_server":
		return "MCP-PIN-LOCK", "", ""
	case "ci_autonomy", "compiled_action":
		return "CI-GATE-ADD", "", ""
	case "tool_config":
		return "MANIFEST-GENERATE", "", ""
	default:
		return "", ReasonUnsupportedFindingType, "finding type is not currently auto-fixable"
	}
}

func isAmbiguousLocation(location string) bool {
	trimmed := strings.TrimSpace(location)
	if trimmed == "" {
		return true
	}
	if strings.Contains(trimmed, "*") || strings.Contains(trimmed, ",") || strings.Contains(trimmed, "\n") {
		return true
	}
	return false
}

func skippedFinding(candidate risk.ScoredFinding, reasonCode, message string) Skipped {
	finding := candidate.Finding
	return Skipped{
		CanonicalKey: canonicalFindingKey(finding),
		FindingType:  finding.FindingType,
		RuleID:       strings.TrimSpace(finding.RuleID),
		Location:     strings.TrimSpace(finding.Location),
		ReasonCode:   reasonCode,
		Message:      message,
	}
}

func rationale(candidate risk.ScoredFinding) string {
	reasons := append([]string(nil), candidate.Reasons...)
	sort.Strings(reasons)
	if len(reasons) == 0 {
		return fmt.Sprintf("risk_score=%.2f", candidate.Score)
	}
	return fmt.Sprintf("risk_score=%.2f; reasons=%s", candidate.Score, strings.Join(reasons, ", "))
}

func commitMessage(template Template, candidate risk.ScoredFinding) string {
	location := strings.TrimSpace(candidate.Finding.Location)
	ruleID := strings.ToUpper(strings.TrimSpace(candidate.Finding.RuleID))
	tail := location
	if idx := strings.LastIndex(location, "/"); idx >= 0 && idx+1 < len(location) {
		tail = location[idx+1:]
	}
	if ruleID != "" {
		return fmt.Sprintf("%s %s (%s)", template.CommitPrefix, tail, ruleID)
	}
	return fmt.Sprintf("%s %s", template.CommitPrefix, tail)
}

func patchPreview(template Template, candidate risk.ScoredFinding) string {
	location := strings.TrimPrefix(strings.TrimSpace(candidate.Finding.Location), "./")
	lines := []string{
		"--- a/" + location,
		"+++ b/" + location,
		"@@ wrkr-fix @@",
		"+# wrkr template: " + template.ID,
		"+# category: " + template.Category,
	}
	for _, hint := range template.Hints {
		lines = append(lines, "+# hint: "+hint)
	}
	if ruleID := strings.TrimSpace(candidate.Finding.RuleID); ruleID != "" {
		lines = append(lines, "+# rule: "+strings.ToUpper(ruleID))
	}
	return strings.Join(lines, "\n") + "\n"
}
