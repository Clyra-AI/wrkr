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
	case "agent_approval_required":
		agents := agentFindings(findings)
		if len(agents) == 0 {
			return legacyRuleResult("require_tool_config", findings)
		}
		approvalStatusMissing := 0
		approvalSourceMissing := 0
		approvalSourceAmbiguous := 0
		for _, finding := range agents {
			status := strings.ToLower(strings.TrimSpace(evidenceValue(finding, "approval_status")))
			if status == "" {
				status = "missing"
			}
			if status != "approved" && status != "valid" {
				approvalStatusMissing++
			}
			switch normalizeEvidenceState(evidenceValue(finding, "approval_source"), "missing") {
			case "missing":
				approvalSourceMissing++
			case "ambiguous":
				approvalSourceAmbiguous++
			}
		}
		return approvalStatusMissing == 0 && approvalSourceMissing == 0 && approvalSourceAmbiguous == 0,
			fmt.Sprintf(
				"agent_count=%d,approval_status_missing=%d,approval_source_missing=%d,approval_source_ambiguous=%d",
				len(agents),
				approvalStatusMissing,
				approvalSourceMissing,
				approvalSourceAmbiguous,
			)
	case "agent_prod_write_human_gate":
		agents := agentFindings(findings)
		if len(agents) == 0 {
			return legacyRuleResult("block_secret_presence", findings)
		}
		violations := 0
		proofRequirementMissing := 0
		for _, finding := range agents {
			deployment := strings.ToLower(strings.TrimSpace(evidenceValue(finding, "deployment_status")))
			autoDeploy := boolEvidence(finding, "auto_deploy")
			humanGate := boolEvidenceWithDefault(finding, "human_gate", false)
			if hasWriteLikePermission(finding.Permissions) && (deployment == "deployed" || autoDeploy) && !humanGate {
				violations++
			}
			if hasWriteLikePermission(finding.Permissions) && (deployment == "deployed" || autoDeploy) {
				switch normalizeEvidenceState(evidenceValue(finding, "proof_requirement"), "missing") {
				case "missing", "ambiguous":
					proofRequirementMissing++
				}
			}
		}
		secretCount := countType(findings, "secret_presence")
		return violations == 0 && secretCount == 0 && proofRequirementMissing == 0,
			fmt.Sprintf(
				"prod_write_without_human_gate=%d,proof_requirement_missing=%d,secret_presence=%d",
				violations,
				proofRequirementMissing,
				secretCount,
			)
	case "agent_secret_controls":
		agents := agentFindings(findings)
		if len(agents) == 0 {
			return legacyRuleResult("no_parse_errors", findings)
		}
		violations := 0
		for _, finding := range agents {
			secretControl := strings.ToLower(strings.TrimSpace(evidenceValue(finding, "secret_control")))
			if hasSecretSignal(finding) && secretControl != "managed" && secretControl != "enforced" {
				violations++
			}
		}
		return violations == 0, fmt.Sprintf("secret_control_gaps=%d", violations)
	case "agent_exfil_controls":
		agents := agentFindings(findings)
		if len(agents) == 0 {
			return legacyRuleResult("headless_requires_gate", findings)
		}
		violations := 0
		for _, finding := range agents {
			external := boolEvidence(finding, "external_network")
			egress := strings.ToLower(strings.TrimSpace(evidenceValue(finding, "egress_policy")))
			if external && egress != "enforced" {
				violations++
			}
		}
		return violations == 0, fmt.Sprintf("exfil_control_gaps=%d", violations)
	case "agent_delegation_controls":
		agents := agentFindings(findings)
		if len(agents) == 0 {
			return legacyRuleResult("require_mcp_inventory", findings)
		}
		violations := 0
		for _, finding := range agents {
			delegationEnabled := boolEvidence(finding, "delegation") || strings.TrimSpace(evidenceValue(finding, "delegate_to")) != ""
			delegationPolicy := strings.ToLower(strings.TrimSpace(evidenceValue(finding, "delegation_policy")))
			if delegationEnabled && delegationPolicy != "approved" && delegationPolicy != "enforced" {
				violations++
			}
		}
		return violations == 0, fmt.Sprintf("delegation_control_gaps=%d", violations)
	case "agent_dynamic_discovery_controls":
		agents := agentFindings(findings)
		if len(agents) == 0 {
			return legacyRuleResult("require_dependency_inventory", findings)
		}
		violations := 0
		for _, finding := range agents {
			if boolEvidence(finding, "dynamic_discovery") {
				violations++
			}
		}
		return violations == 0, fmt.Sprintf("dynamic_discovery_enabled=%d", violations)
	case "agent_kill_switch_required":
		agents := agentFindings(findings)
		if len(agents) == 0 {
			return legacyRuleResult("require_skill_metrics", findings)
		}
		violations := 0
		for _, finding := range agents {
			deployment := strings.ToLower(strings.TrimSpace(evidenceValue(finding, "deployment_status")))
			if deployment != "deployed" {
				continue
			}
			if !boolEvidence(finding, "kill_switch") {
				violations++
			}
		}
		return violations == 0, fmt.Sprintf("missing_kill_switch=%d", violations)
	case "agent_data_classification_required":
		agents := agentFindings(findings)
		if len(agents) == 0 {
			return legacyRuleResult("compiled_actions_reviewed", findings)
		}
		violations := 0
		for _, finding := range agents {
			dataClass := strings.ToLower(strings.TrimSpace(evidenceValue(finding, "data_class")))
			if dataClass == "" || dataClass == "unknown" || dataClass == "unclassified" {
				violations++
			}
		}
		return violations == 0, fmt.Sprintf("unclassified_agents=%d", violations)
	case "agent_auto_deploy_gate":
		agents := agentFindings(findings)
		if len(agents) == 0 {
			return legacyRuleResult("credential_refs_reviewed", findings)
		}
		violations := 0
		ambiguous := 0
		for _, finding := range agents {
			if !boolEvidence(finding, "auto_deploy") {
				continue
			}
			gate := normalizeEvidenceState(evidenceValue(finding, "deployment_gate"), "missing")
			if gate != "approved" && gate != "enforced" {
				violations++
			}
			if gate == "ambiguous" {
				ambiguous++
			}
		}
		return violations == 0, fmt.Sprintf("auto_deploy_gate_gaps=%d,auto_deploy_gate_ambiguous=%d", violations, ambiguous)
	case "agent_autodeploy_without_human_gate":
		agents := agentFindings(findings)
		if len(agents) == 0 {
			return legacyRuleResult("stable_ci_reason_codes", findings)
		}
		violations := 0
		for _, finding := range agents {
			if !boolEvidence(finding, "auto_deploy") {
				continue
			}
			if !boolEvidenceWithDefault(finding, "human_gate", true) {
				violations++
			}
		}
		return violations == 0, fmt.Sprintf("auto_deploy_without_human_gate=%d", violations)
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
	case "prompt_channel_governance":
		total := 0
		highOrCritical := 0
		for _, finding := range findings {
			if !isPromptChannelFinding(finding) {
				continue
			}
			total++
			switch severity(finding.Severity) {
			case model.SeverityHigh, model.SeverityCritical:
				highOrCritical++
			}
		}
		return highOrCritical == 0, fmt.Sprintf("prompt_channel_high=%d,total=%d", highOrCritical, total)
	default:
		return false, "unknown policy kind"
	}
}

func legacyRuleResult(kind string, findings []model.Finding) (bool, string) {
	return applyRule(policy.Rule{Kind: kind}, findings)
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

func isPromptChannelFinding(finding model.Finding) bool {
	if strings.TrimSpace(finding.ToolType) == "prompt_channel" {
		return true
	}
	switch strings.TrimSpace(finding.FindingType) {
	case "prompt_channel_hidden_text", "prompt_channel_override", "prompt_channel_untrusted_context":
		return true
	default:
		return false
	}
}

func agentFindings(findings []model.Finding) []model.Finding {
	agentToolTypes := map[string]struct{}{
		"langchain":     {},
		"crewai":        {},
		"openai_agents": {},
		"autogen":       {},
		"llamaindex":    {},
	}
	out := make([]model.Finding, 0)
	for _, finding := range findings {
		if strings.TrimSpace(finding.FindingType) == "agent_framework" {
			out = append(out, finding)
			continue
		}
		if _, ok := agentToolTypes[strings.ToLower(strings.TrimSpace(finding.ToolType))]; ok {
			out = append(out, finding)
		}
	}
	return out
}

func evidenceValue(finding model.Finding, key string) string {
	target := strings.ToLower(strings.TrimSpace(key))
	for _, evidence := range finding.Evidence {
		if strings.ToLower(strings.TrimSpace(evidence.Key)) == target {
			return strings.TrimSpace(evidence.Value)
		}
	}
	return ""
}

func boolEvidence(finding model.Finding, key string) bool {
	value := strings.ToLower(strings.TrimSpace(evidenceValue(finding, key)))
	return value == "true" || value == "1" || value == "yes" || value == "enabled"
}

func boolEvidenceWithDefault(finding model.Finding, key string, defaultValue bool) bool {
	value := strings.ToLower(strings.TrimSpace(evidenceValue(finding, key)))
	if value == "" {
		return defaultValue
	}
	switch value {
	case "true", "1", "yes", "enabled":
		return true
	default:
		return false
	}
}

func hasWriteLikePermission(permissions []string) bool {
	for _, permission := range permissions {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		if strings.Contains(normalized, "write") || strings.Contains(normalized, "deploy") || strings.Contains(normalized, "proc.exec") {
			return true
		}
	}
	return false
}

func hasSecretSignal(finding model.Finding) bool {
	for _, permission := range finding.Permissions {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		if strings.Contains(normalized, "secret") || strings.Contains(normalized, "token") || strings.Contains(normalized, "credential") {
			return true
		}
	}
	authSurfaces := strings.ToLower(strings.TrimSpace(evidenceValue(finding, "auth_surfaces")))
	return strings.Contains(authSurfaces, "secret") || strings.Contains(authSurfaces, "token") || strings.Contains(authSurfaces, "credential")
}

func normalizeEvidenceState(value string, missing string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return missing
	}
	switch normalized {
	case "approved", "enforced", "open", "missing", "ambiguous", "manual_approval_step", "environment", "workflow_dispatch", "evidence", "attestation", "not_applicable":
		return normalized
	default:
		return normalized
	}
}
