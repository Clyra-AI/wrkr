package workflowcap

import (
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
)

func appendDeliveryControlEvidence(path string, workflowText string, result Result, evidence []model.Evidence) []model.Evidence {
	out := append([]model.Evidence(nil), evidence...)
	add := func(key string, values ...string) {
		for _, value := range values {
			trimmed := strings.TrimSpace(value)
			if trimmed == "" {
				continue
			}
			out = append(out, model.Evidence{Key: key, Value: trimmed})
		}
	}

	add("delivery_harness", deliveryHarnessValues(result)...)
	if hasResolverStatusEvidence(out) {
		add("resolver_ref", path)
	}
	if isEvalWorkflowPayload(workflowText) {
		add("eval_config_ref", path)
		add("validation_requirement", "review_eval_config")
	}
	if requiresDryRun(result, workflowText) {
		add("dry_run_required", "true")
		add("validation_requirement", "dry_run_before_delivery")
	}
	for _, gate := range sandboxGateValues(result.EnvironmentNames) {
		add("sandbox_gate", gate)
	}
	if len(sandboxGateValues(result.EnvironmentNames)) > 0 {
		add("validation_requirement", "respect_sandbox_gate")
	}
	for _, gate := range testGateValues(workflowText) {
		add("test_gate", gate)
	}
	if len(testGateValues(workflowText)) > 0 {
		add("validation_requirement", "run_test_gate")
	}
	return dedupeEvidence(out)
}

func deliveryHarnessValues(result Result) []string {
	values := []string{"ci_workflow"}
	switch strings.TrimSpace(result.Tool) {
	case "codex":
		values = append(values, "codex_cli")
	case "claude":
		values = append(values, "claude_code")
	case "cursor":
		values = append(values, "cursor_rules")
	case "gait":
		values = append(values, "gait_eval")
	}
	return uniqueWorkflowcapStrings(values)
}

func hasResolverStatusEvidence(evidence []model.Evidence) bool {
	for _, item := range evidence {
		switch strings.TrimSpace(item.Key) {
		case "include_resolution_status", "template_resolution_status":
			return true
		}
	}
	return false
}

func isEvalWorkflowPayload(workflowText string) bool {
	lower := strings.ToLower(workflowText)
	return strings.Contains(lower, "gait eval --script")
}

func requiresDryRun(result Result, workflowText string) bool {
	lower := strings.ToLower(workflowText)
	if strings.Contains(lower, "--dry-run") {
		return true
	}
	for _, job := range result.JobNames {
		if strings.Contains(strings.ToLower(strings.TrimSpace(job)), "dry-run") {
			return true
		}
	}
	return false
}

func sandboxGateValues(environmentNames []string) []string {
	values := []string{}
	for _, name := range environmentNames {
		lower := strings.ToLower(strings.TrimSpace(name))
		switch {
		case strings.Contains(lower, "sandbox"),
			strings.Contains(lower, "staging"),
			strings.Contains(lower, "preview"),
			strings.Contains(lower, "nonprod"):
			values = append(values, "environment:"+lower)
		}
	}
	return uniqueWorkflowcapStrings(values)
}

func testGateValues(workflowText string) []string {
	lower := strings.ToLower(workflowText)
	values := []string{}
	switch {
	case strings.Contains(lower, "go test ./"):
		values = append(values, "step.run:go_test")
	case strings.Contains(lower, "pytest"):
		values = append(values, "step.run:pytest")
	case strings.Contains(lower, "npm test"):
		values = append(values, "step.run:npm_test")
	case strings.Contains(lower, "pnpm test"):
		values = append(values, "step.run:pnpm_test")
	case strings.Contains(lower, "yarn test"):
		values = append(values, "step.run:yarn_test")
	}
	return uniqueWorkflowcapStrings(values)
}

func dedupeEvidence(values []model.Evidence) []model.Evidence {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]model.Evidence, 0, len(values))
	for _, item := range values {
		key := strings.TrimSpace(item.Key)
		value := strings.TrimSpace(item.Value)
		if key == "" || value == "" {
			continue
		}
		joined := key + "\x00" + value
		if _, ok := seen[joined]; ok {
			continue
		}
		seen[joined] = struct{}{}
		out = append(out, model.Evidence{Key: key, Value: value})
	}
	return out
}

func uniqueWorkflowcapStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
