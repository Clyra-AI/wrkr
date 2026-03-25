package eval

import (
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/policy"
)

func TestEvaluateEmitsChecksAndViolations(t *testing.T) {
	t.Parallel()

	rules := []policy.Rule{
		{ID: "WRKR-001", Title: "tool config", Severity: "high", Kind: "require_tool_config", Version: 1},
		{ID: "WRKR-002", Title: "no secret", Severity: "high", Kind: "block_secret_presence", Version: 1},
	}
	findings := []model.Finding{{FindingType: "tool_config", Severity: model.SeverityLow, ToolType: "claude", Location: ".claude", Org: "local"}}
	out := Evaluate("repo", "org", findings, rules)

	checks := 0
	violations := 0
	for _, finding := range out {
		switch finding.FindingType {
		case "policy_check":
			checks++
		case "policy_violation":
			violations++
		}
	}
	if checks != 2 {
		t.Fatalf("expected 2 policy checks, got %d", checks)
	}
	if violations != 0 {
		t.Fatalf("expected no policy violations, got %d", violations)
	}
}

func TestRuleWRKR015FailsWhenExecRatioAboveThreshold(t *testing.T) {
	t.Parallel()

	rules := []policy.Rule{{ID: "WRKR-015", Title: "sprawl", Severity: "medium", Kind: "skill_sprawl_exec_ratio", Version: 1}}
	findings := []model.Finding{{
		FindingType: "skill_metrics",
		Severity:    model.SeverityMedium,
		ToolType:    "skill",
		Location:    ".agents/skills",
		Org:         "local",
		Evidence: []model.Evidence{{
			Key:   "skill_privilege_concentration.exec_ratio",
			Value: "0.80",
		}},
	}}
	out := Evaluate("repo", "org", findings, rules)

	foundViolation := false
	for _, finding := range out {
		if finding.FindingType == "policy_violation" && finding.RuleID == "WRKR-015" {
			foundViolation = true
		}
	}
	if !foundViolation {
		t.Fatal("expected WRKR-015 policy violation")
	}
}

func TestRuleWRKR016FailsWhenPromptChannelHighFindingsExist(t *testing.T) {
	t.Parallel()

	rules := []policy.Rule{{ID: "WRKR-016", Title: "prompt channel governance", Severity: "high", Kind: "prompt_channel_governance", Version: 1}}
	findings := []model.Finding{{
		FindingType: "prompt_channel_override",
		Severity:    model.SeverityHigh,
		ToolType:    "prompt_channel",
		Location:    "AGENTS.md",
		Org:         "local",
	}}

	out := Evaluate("repo", "org", findings, rules)
	foundViolation := false
	for _, finding := range out {
		if finding.FindingType == "policy_violation" && finding.RuleID == "WRKR-016" {
			foundViolation = true
		}
	}
	if !foundViolation {
		t.Fatal("expected WRKR-016 policy violation")
	}
}

func TestPolicyEval_WRKRA001_NoApprovalFails(t *testing.T) {
	t.Parallel()

	rules := []policy.Rule{{
		ID:          "WRKR-A001",
		Title:       "approval required",
		Severity:    "high",
		Kind:        "agent_approval_required",
		Remediation: "set approval_status",
		Version:     1,
	}}
	findings := []model.Finding{{
		FindingType: "agent_framework",
		ToolType:    "langchain",
		Location:    "agents/release.py",
		Evidence: []model.Evidence{
			{Key: "symbol", Value: "release_agent"},
			{Key: "approval_status", Value: "missing"},
			{Key: "approval_source", Value: "missing"},
		},
	}}
	out := Evaluate("repo", "org", findings, rules)
	if !hasViolation(out, "WRKR-A001") {
		t.Fatalf("expected WRKR-A001 violation, got %+v", out)
	}
}

func TestPolicyEval_WRKRA001_MissingApprovalSourceFailsClosed(t *testing.T) {
	t.Parallel()

	rules := []policy.Rule{{
		ID:          "WRKR-A001",
		Title:       "approval required",
		Severity:    "high",
		Kind:        "agent_approval_required",
		Remediation: "set approval_source",
		Version:     1,
	}}
	findings := []model.Finding{{
		FindingType: "agent_framework",
		ToolType:    "langchain",
		Location:    "agents/release.py",
		Evidence: []model.Evidence{
			{Key: "symbol", Value: "release_agent"},
			{Key: "approval_status", Value: "approved"},
			{Key: "approval_source", Value: "missing"},
		},
	}}

	out := Evaluate("repo", "org", findings, rules)
	if !hasViolation(out, "WRKR-A001") {
		t.Fatalf("expected WRKR-A001 violation when approval_source is missing, got %+v", out)
	}
}

func TestPolicyEval_WRKRA010_AutoDeployWithoutHumanGateFails(t *testing.T) {
	t.Parallel()

	rules := []policy.Rule{{
		ID:          "WRKR-A010",
		Title:       "auto deploy gate",
		Severity:    "high",
		Kind:        "agent_autodeploy_without_human_gate",
		Remediation: "set human_gate=true",
		Version:     1,
	}}
	findings := []model.Finding{{
		FindingType: "agent_framework",
		ToolType:    "openai_agents",
		Location:    "agents/release.py",
		Evidence: []model.Evidence{
			{Key: "symbol", Value: "release_agent"},
			{Key: "auto_deploy", Value: "true"},
			{Key: "human_gate", Value: "false"},
		},
	}}
	out := Evaluate("repo", "org", findings, rules)
	if !hasViolation(out, "WRKR-A010") {
		t.Fatalf("expected WRKR-A010 violation, got %+v", out)
	}
}

func TestPolicyEval_WRKR002_AgentProdWriteAlsoChecksSecretPresence(t *testing.T) {
	t.Parallel()

	rules := []policy.Rule{{
		ID:          "WRKR-002",
		Title:       "production write agents require human gate",
		Severity:    "high",
		Kind:        "agent_prod_write_human_gate",
		Remediation: "set human gate and remove inline secrets",
		Version:     1,
	}}
	findings := []model.Finding{
		{
			FindingType: "agent_framework",
			ToolType:    "langchain",
			Location:    "agents/release.py",
			Permissions: []string{"deploy.write"},
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "release_agent"},
				{Key: "deployment_status", Value: "deployed"},
				{Key: "human_gate", Value: "true"},
				{Key: "proof_requirement", Value: "attestation"},
			},
		},
		{
			FindingType: "secret_presence",
			ToolType:    "codex",
			Location:    ".codex/config.toml",
		},
	}
	out := Evaluate("repo", "org", findings, rules)
	if !hasViolation(out, "WRKR-002") {
		t.Fatalf("expected WRKR-002 violation when secret_presence exists, got %+v", out)
	}
}

func TestPolicyEval_WRKRA002_MissingProofRequirementFailsClosed(t *testing.T) {
	t.Parallel()

	rules := []policy.Rule{{
		ID:          "WRKR-A002",
		Title:       "production write agents require human gate and proof requirements",
		Severity:    "high",
		Kind:        "agent_prod_write_human_gate",
		Remediation: "declare proof requirement",
		Version:     1,
	}}
	findings := []model.Finding{{
		FindingType: "agent_framework",
		ToolType:    "langchain",
		Location:    "agents/release.py",
		Permissions: []string{"deploy.write"},
		Evidence: []model.Evidence{
			{Key: "symbol", Value: "release_agent"},
			{Key: "deployment_status", Value: "deployed"},
			{Key: "human_gate", Value: "true"},
			{Key: "proof_requirement", Value: "missing"},
		},
	}}

	out := Evaluate("repo", "org", findings, rules)
	if !hasViolation(out, "WRKR-A002") {
		t.Fatalf("expected WRKR-A002 violation when proof_requirement is missing, got %+v", out)
	}
}

func TestPolicyEval_WRKRA009_RequiresExplicitGateSource(t *testing.T) {
	t.Parallel()

	rules := []policy.Rule{{
		ID:          "WRKR-A009",
		Title:       "auto deploy requires deployment gate",
		Severity:    "high",
		Kind:        "agent_auto_deploy_gate",
		Remediation: "declare deployment gate",
		Version:     1,
	}}
	findings := []model.Finding{{
		FindingType: "agent_framework",
		ToolType:    "openai_agents",
		Location:    "agents/release.py",
		Evidence: []model.Evidence{
			{Key: "symbol", Value: "release_agent"},
			{Key: "auto_deploy", Value: "true"},
			{Key: "human_gate", Value: "true"},
			{Key: "approval_source", Value: "manual_approval_step"},
			{Key: "deployment_gate", Value: "enforced"},
		},
	}}

	out := Evaluate("repo", "org", findings, rules)
	if hasViolation(out, "WRKR-A009") {
		t.Fatalf("expected WRKR-A009 to pass with human_gate fallback, got %+v", out)
	}
}

func TestPolicyEval_AgentRuleKindsDeterministicPassFail(t *testing.T) {
	t.Parallel()

	rules := []policy.Rule{
		{ID: "WRKR-A001", Title: "A001", Severity: "high", Kind: "agent_approval_required", Remediation: "r1", Version: 1},
		{ID: "WRKR-A002", Title: "A002", Severity: "high", Kind: "agent_prod_write_human_gate", Remediation: "r2", Version: 1},
		{ID: "WRKR-A003", Title: "A003", Severity: "high", Kind: "agent_secret_controls", Remediation: "r3", Version: 1},
		{ID: "WRKR-A004", Title: "A004", Severity: "high", Kind: "agent_exfil_controls", Remediation: "r4", Version: 1},
		{ID: "WRKR-A005", Title: "A005", Severity: "high", Kind: "agent_delegation_controls", Remediation: "r5", Version: 1},
		{ID: "WRKR-A006", Title: "A006", Severity: "high", Kind: "agent_dynamic_discovery_controls", Remediation: "r6", Version: 1},
		{ID: "WRKR-A007", Title: "A007", Severity: "high", Kind: "agent_kill_switch_required", Remediation: "r7", Version: 1},
		{ID: "WRKR-A008", Title: "A008", Severity: "high", Kind: "agent_data_classification_required", Remediation: "r8", Version: 1},
		{ID: "WRKR-A009", Title: "A009", Severity: "high", Kind: "agent_auto_deploy_gate", Remediation: "r9", Version: 1},
		{ID: "WRKR-A010", Title: "A010", Severity: "high", Kind: "agent_autodeploy_without_human_gate", Remediation: "r10", Version: 1},
	}
	findings := []model.Finding{{
		FindingType: "agent_framework",
		ToolType:    "langchain",
		Location:    "agents/main.py",
		Permissions: []string{"deploy.write", "secret.read"},
		Evidence: []model.Evidence{
			{Key: "symbol", Value: "ops_agent"},
			{Key: "approval_status", Value: "approved"},
			{Key: "approval_source", Value: "manual_approval_step"},
			{Key: "deployment_status", Value: "deployed"},
			{Key: "human_gate", Value: "true"},
			{Key: "proof_requirement", Value: "attestation"},
			{Key: "secret_control", Value: "managed"},
			{Key: "external_network", Value: "true"},
			{Key: "egress_policy", Value: "enforced"},
			{Key: "delegation", Value: "true"},
			{Key: "delegation_policy", Value: "approved"},
			{Key: "dynamic_discovery", Value: "false"},
			{Key: "kill_switch", Value: "true"},
			{Key: "data_class", Value: "internal"},
			{Key: "auto_deploy", Value: "true"},
			{Key: "deployment_gate", Value: "enforced"},
		},
	}}
	first := Evaluate("repo", "org", findings, rules)
	second := Evaluate("repo", "org", findings, rules)
	if len(first) != 10 || len(second) != 10 {
		t.Fatalf("expected 10 policy checks for deterministic baseline, got %d and %d", len(first), len(second))
	}
	for _, finding := range first {
		if finding.FindingType == "policy_violation" {
			t.Fatalf("expected no violations for all-pass fixture, got %+v", first)
		}
	}
	for i := range first {
		if first[i].RuleID != second[i].RuleID || first[i].CheckResult != second[i].CheckResult {
			t.Fatalf("non-deterministic rule ordering or outcomes\nfirst=%+v\nsecond=%+v", first, second)
		}
	}
}

func hasViolation(findings []model.Finding, ruleID string) bool {
	for _, finding := range findings {
		if finding.FindingType == "policy_violation" && finding.RuleID == ruleID {
			return true
		}
	}
	return false
}
