//go:build scenario

package scenarios

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestScenario_AgentRelationshipCorrelation(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "agent-relationship-correlation", "repos")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})

	findings, ok := payload["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}

	hasMCPClient := false
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["finding_type"] == "agent_framework" && finding["detector"] == "agentmcpclient" {
			hasMCPClient = true
			break
		}
	}
	if !hasMCPClient {
		t.Fatalf("expected agentmcpclient agent_framework finding, got %v", findings)
	}

	inventory, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory payload, got %T", payload["inventory"])
	}
	agents, ok := inventory["agents"].([]any)
	if !ok || len(agents) == 0 {
		t.Fatalf("expected inventory.agents entries, got %v", inventory["agents"])
	}
	firstAgent, ok := agents[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected inventory agent shape: %T", agents[0])
	}
	if firstAgent["deployment_status"] != "deployed" {
		t.Fatalf("expected deployment_status=deployed, got %v", firstAgent["deployment_status"])
	}
	boundTools := toStringSlice(firstAgent["bound_tools"])
	for _, required := range []string{"mcp.server.deploy", "shell.exec"} {
		if !slices.Contains(boundTools, required) {
			t.Fatalf("expected bound tool %q in %v", required, boundTools)
		}
	}
}

func TestScenario_AgentPolicyOutcomes(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "agent-policy-outcomes", "repos")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})

	findings, ok := payload["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}

	hasCustomFinding := false
	violations := map[string]bool{}
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["finding_type"] == "agent_custom_scaffold" {
			hasCustomFinding = true
		}
		if finding["finding_type"] == "policy_violation" {
			ruleID, _ := finding["rule_id"].(string)
			if ruleID != "" {
				violations[ruleID] = true
			}
		}
	}
	if !hasCustomFinding {
		t.Fatalf("expected agent_custom_scaffold finding in scenario output, got %v", findings)
	}
	requiredRuleAliases := [][]string{
		{"WRKR-A001", "WRKR-001"},
		{"WRKR-A010", "WRKR-010"},
	}
	for _, aliases := range requiredRuleAliases {
		found := false
		for _, alias := range aliases {
			if violations[alias] {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected policy_violation for one of %v, got %v", aliases, violations)
		}
	}
}

func toStringSlice(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			continue
		}
		out = append(out, text)
	}
	return out
}
