package outputsignal

import (
	"reflect"
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
)

func TestBuildPolicyOutcomesGroupsRepoFanout(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{FindingType: "policy_check", RuleID: "WRKR-001", CheckResult: model.CheckResultFail, Severity: model.SeverityHigh, Org: "acme", Repo: "repo-a"},
		{FindingType: "policy_violation", RuleID: "WRKR-001", CheckResult: model.CheckResultFail, Severity: model.SeverityHigh, Org: "acme", Repo: "repo-a"},
		{FindingType: "policy_check", RuleID: "WRKR-001", CheckResult: model.CheckResultFail, Severity: model.SeverityHigh, Org: "acme", Repo: "repo-b"},
		{FindingType: "policy_violation", RuleID: "WRKR-001", CheckResult: model.CheckResultFail, Severity: model.SeverityHigh, Org: "acme", Repo: "repo-b"},
		{FindingType: "policy_check", RuleID: "WRKR-001", CheckResult: model.CheckResultFail, Severity: model.SeverityHigh, Org: "acme", Repo: "repo-c"},
		{FindingType: "policy_violation", RuleID: "WRKR-001", CheckResult: model.CheckResultFail, Severity: model.SeverityHigh, Org: "acme", Repo: "repo-c"},
		{FindingType: "policy_check", RuleID: "WRKR-001", CheckResult: model.CheckResultFail, Severity: model.SeverityHigh, Org: "acme", Repo: "repo-d"},
		{FindingType: "policy_violation", RuleID: "WRKR-001", CheckResult: model.CheckResultFail, Severity: model.SeverityHigh, Org: "acme", Repo: "repo-d"},
	}

	outcomes := BuildPolicyOutcomes(findings)
	if len(outcomes) != 1 {
		t.Fatalf("expected one grouped outcome, got %+v", outcomes)
	}
	if outcomes[0].OccurrenceCount != len(findings) {
		t.Fatalf("expected occurrence count %d, got %+v", len(findings), outcomes[0])
	}
	if outcomes[0].AffectedRepoCount != 4 {
		t.Fatalf("expected four affected repos, got %+v", outcomes[0])
	}
	if !reflect.DeepEqual(outcomes[0].TopRepoRefs, []string{"acme/repo-a", "acme/repo-b", "acme/repo-c"}) {
		t.Fatalf("unexpected bounded repo refs: %+v", outcomes[0].TopRepoRefs)
	}
	if outcomes[0].SuppressedCount != 1 {
		t.Fatalf("expected one suppressed repo ref, got %+v", outcomes[0])
	}
}

func TestCompactFindingsForSeverityCollapsesPolicyFanout(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{FindingType: "tool_detected", Severity: model.SeverityLow, ToolType: "codex", Location: ".codex/config.toml", Org: "acme"},
		{FindingType: "policy_check", RuleID: "WRKR-009", CheckResult: model.CheckResultFail, PolicyOutcomeID: "policy-a", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-009", Org: "acme", Repo: "repo-a"},
		{FindingType: "policy_violation", RuleID: "WRKR-009", CheckResult: model.CheckResultFail, PolicyOutcomeID: "policy-a", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-009", Org: "acme", Repo: "repo-a"},
		{FindingType: "policy_check", RuleID: "WRKR-009", CheckResult: model.CheckResultFail, PolicyOutcomeID: "policy-a", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-009", Org: "acme", Repo: "repo-b"},
		{FindingType: "policy_violation", RuleID: "WRKR-009", CheckResult: model.CheckResultFail, PolicyOutcomeID: "policy-a", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-009", Org: "acme", Repo: "repo-b"},
	}

	compact := CompactFindingsForSeverity(findings)
	if len(compact) != 2 {
		t.Fatalf("expected one logical policy outcome plus one non-policy finding, got %+v", compact)
	}
	policyCount := 0
	for _, item := range compact {
		if item.FindingType == "policy_violation" {
			policyCount++
		}
	}
	if policyCount != 1 {
		t.Fatalf("expected a single policy violation representative, got %+v", compact)
	}
}

func TestBuildLogicalFindingCountsCollapsesPolicyFanoutPerType(t *testing.T) {
	t.Parallel()

	findings := []model.Finding{
		{FindingType: "tool_detected", ToolType: "codex", Location: ".codex/config.toml", Org: "acme"},
		{FindingType: "policy_check", RuleID: "WRKR-010", CheckResult: model.CheckResultFail, PolicyOutcomeID: "policy-a", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-010", Org: "acme", Repo: "repo-a"},
		{FindingType: "policy_violation", RuleID: "WRKR-010", CheckResult: model.CheckResultFail, PolicyOutcomeID: "policy-a", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-010", Org: "acme", Repo: "repo-a"},
		{FindingType: "policy_check", RuleID: "WRKR-010", CheckResult: model.CheckResultFail, PolicyOutcomeID: "policy-a", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-010", Org: "acme", Repo: "repo-b"},
		{FindingType: "policy_violation", RuleID: "WRKR-010", CheckResult: model.CheckResultFail, PolicyOutcomeID: "policy-a", Severity: model.SeverityHigh, ToolType: "policy", Location: "WRKR-010", Org: "acme", Repo: "repo-b"},
	}

	total, byType, rawTotal, rawByType := BuildLogicalFindingCounts(findings)
	if total != 3 {
		t.Fatalf("expected logical total 3, got total=%d by_type=%v", total, byType)
	}
	if rawTotal != len(findings) {
		t.Fatalf("expected raw total %d, got %d", len(findings), rawTotal)
	}
	if byType["policy_check"] != 1 || byType["policy_violation"] != 1 {
		t.Fatalf("expected grouped policy counts, got %v", byType)
	}
	if rawByType["policy_check"] != 2 || rawByType["policy_violation"] != 2 {
		t.Fatalf("expected raw policy counts to preserve fanout, got %v", rawByType)
	}
}
