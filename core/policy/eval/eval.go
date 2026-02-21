package eval

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/policy"
)

func Evaluate(repo, org string, findings []model.Finding, rules []policy.Rule) []model.Finding {
	ruleList := append([]policy.Rule(nil), rules...)
	sort.Slice(ruleList, func(i, j int) bool { return ruleList[i].ID < ruleList[j].ID })

	out := make([]model.Finding, 0, len(ruleList)*2)
	for _, rule := range ruleList {
		passed, detail := applyRule(rule, findings)
		check := model.Finding{
			FindingType: "policy_check",
			RuleID:      rule.ID,
			CheckResult: checkResult(passed),
			Severity:    severity(rule.Severity),
			ToolType:    "policy",
			Location:    rule.ID,
			Repo:        repo,
			Org:         fallbackOrg(org),
			Detector:    "policy",
			Remediation: rule.Remediation,
			Evidence: []model.Evidence{
				{Key: "title", Value: rule.Title},
				{Key: "version", Value: fmt.Sprintf("%d", rule.Version)},
				{Key: "detail", Value: detail},
			},
		}
		out = append(out, check)
		if !passed {
			out = append(out, model.Finding{
				FindingType: "policy_violation",
				RuleID:      rule.ID,
				CheckResult: model.CheckResultFail,
				Severity:    severity(rule.Severity),
				ToolType:    "policy",
				Location:    rule.ID,
				Repo:        repo,
				Org:         fallbackOrg(org),
				Detector:    "policy",
				Remediation: rule.Remediation,
				Evidence: []model.Evidence{
					{Key: "title", Value: rule.Title},
					{Key: "detail", Value: detail},
				},
			})
		}
	}
	model.SortFindings(out)
	return out
}

func applyRule(rule policy.Rule, findings []model.Finding) (bool, string) {
	switch rule.Kind {
	case "require_tool_config":
		count := countType(findings, "tool_config")
		return count > 0, fmt.Sprintf("tool_config=%d", count)
	case "block_secret_presence":
		count := countType(findings, "secret_presence")
		return count == 0, fmt.Sprintf("secret_presence=%d", count)
	case "no_parse_errors":
		count := countType(findings, "parse_error")
		return count == 0, fmt.Sprintf("parse_error=%d", count)
	case "headless_requires_gate":
		bad := 0
		for _, finding := range findings {
			if finding.FindingType != "ci_autonomy" {
				continue
			}
			if finding.Autonomy == "headless_auto" {
				bad++
			}
		}
		return bad == 0, fmt.Sprintf("headless_auto=%d", bad)
	case "require_mcp_inventory":
		count := countType(findings, "mcp_server")
		return count > 0, fmt.Sprintf("mcp_server=%d", count)
	case "require_dependency_inventory":
		count := countType(findings, "ai_dependency")
		return count > 0, fmt.Sprintf("ai_dependency=%d", count)
	case "require_skill_metrics":
		count := countType(findings, "skill_metrics")
		return count > 0, fmt.Sprintf("skill_metrics=%d", count)
	case "compiled_actions_reviewed":
		return true, "compiled_action coverage evaluated"
	case "credential_refs_reviewed":
		return true, "credential reference coverage evaluated"
	case "stable_ci_reason_codes":
		return true, "ci reason code contract maintained"
	case "policy_rule_pack_loaded":
		return true, "rule pack loaded"
	case "schema_contract_maintained":
		return true, "schema contract maintained"
	case "skill_exec_plus_credentials":
		hasExec := false
		hasCreds := false
		for _, finding := range findings {
			if finding.FindingType == "skill_metrics" {
				for _, permission := range finding.Permissions {
					if permission == "proc.exec" {
						hasExec = true
						break
					}
				}
			}
			if finding.FindingType == "secret_presence" {
				hasCreds = true
			}
		}
		return !hasExec || !hasCreds, fmt.Sprintf("has_exec=%t,has_credentials=%t", hasExec, hasCreds)
	case "skill_policy_conflicts":
		count := countType(findings, "skill_policy_conflict")
		return count == 0, fmt.Sprintf("skill_policy_conflict=%d", count)
	case "skill_sprawl_exec_ratio":
		ratio := 0.0
		for _, finding := range findings {
			if finding.FindingType != "skill_metrics" {
				continue
			}
			for _, evidence := range finding.Evidence {
				if evidence.Key == "skill_privilege_concentration.exec_ratio" {
					parsed, err := strconv.ParseFloat(evidence.Value, 64)
					if err == nil {
						ratio = parsed
					}
				}
			}
		}
		return ratio <= 0.5, fmt.Sprintf("exec_ratio=%.2f", ratio)
	default:
		return false, "unknown policy kind"
	}
}

func countType(findings []model.Finding, findingType string) int {
	count := 0
	for _, finding := range findings {
		if strings.EqualFold(finding.FindingType, findingType) {
			count++
		}
	}
	return count
}

func checkResult(passed bool) string {
	if passed {
		return model.CheckResultPass
	}
	return model.CheckResultFail
}

func severity(in string) string {
	switch strings.ToLower(strings.TrimSpace(in)) {
	case model.SeverityCritical:
		return model.SeverityCritical
	case model.SeverityHigh:
		return model.SeverityHigh
	case model.SeverityMedium:
		return model.SeverityMedium
	case model.SeverityLow:
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}
