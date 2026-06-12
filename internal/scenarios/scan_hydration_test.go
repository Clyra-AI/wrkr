package scenarios

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/state"
)

func hydrateScenarioScanSummaryPayload(t *testing.T, args []string, payload map[string]any) {
	t.Helper()
	if len(args) == 0 || args[0] != "scan" {
		return
	}
	statePath := scanStatePathFromArgs(args)
	if statePath == "" {
		return
	}
	snapshot, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load scan state %s: %v", statePath, err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal hydrated scan state %s: %v", statePath, err)
	}
	statePayload := map[string]any{}
	if err := json.Unmarshal(raw, &statePayload); err != nil {
		t.Fatalf("parse hydrated scan state %s: %v", statePath, err)
	}
	for _, key := range []string{"findings", "inventory", "control_backlog", "scan_quality", "scan_mode", "profile", "posture_score", "source_privacy"} {
		if shouldHydrateScenarioScanPayloadKey(payload, key) {
			if value, exists := statePayload[key]; exists {
				payload[key] = value
			}
		}
	}
	if shouldHydrateScenarioScanPayloadKey(payload, "agent_privilege_map") {
		if inventory, ok := statePayload["inventory"].(map[string]any); ok {
			if value, exists := inventory["agent_privilege_map"]; exists {
				payload["agent_privilege_map"] = value
			}
		}
	}
	if riskReport, ok := statePayload["risk_report"].(map[string]any); ok {
		for _, key := range []string{"ranked_findings", "top_findings", "attack_paths", "top_attack_paths", "action_paths", "action_path_to_control_first", "control_path_graph", "workflow_chains"} {
			if value, ok := riskReport[key]; ok && shouldHydrateScenarioScanPayloadKey(payload, key) {
				payload[key] = value
			}
		}
	}
}

func shouldHydrateScenarioScanPayloadKey(payload map[string]any, key string) bool {
	if _, ok := payload[key]; !ok {
		return true
	}
	switch key {
	case "findings":
		return scenarioSuppressedCountPositive(payload, "findings")
	case "ranked_findings":
		return scenarioSuppressedCountPositive(payload, "ranked_findings")
	case "attack_paths", "top_attack_paths":
		return scenarioSuppressedCountPositive(payload, "attack_paths")
	case "action_paths":
		return scenarioSuppressedCountPositive(payload, "action_paths")
	case "control_backlog":
		return scenarioSuppressedCountPositive(payload, "control_backlog")
	case "inventory":
		return scenarioSuppressedCountPositive(payload, "inventory_agents") ||
			scenarioSuppressedCountPositive(payload, "inventory_tools") ||
			scenarioSuppressedCountPositive(payload, "privilege_rows")
	case "agent_privilege_map":
		return scenarioSuppressedCountPositive(payload, "privilege_rows")
	case "control_path_graph":
		return scenarioSuppressedCountPositive(payload, "graph_nodes") || scenarioSuppressedCountPositive(payload, "graph_edges")
	case "workflow_chains":
		return scenarioSuppressedCountPositive(payload, "workflow_chains")
	default:
		return false
	}
}

func scenarioSuppressedCountPositive(payload map[string]any, key string) bool {
	counts, ok := payload["suppressed_counts"].(map[string]any)
	if !ok {
		return false
	}
	value, ok := counts[key]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case float64:
		return typed > 0
	case int:
		return typed > 0
	default:
		return false
	}
}

func scanStatePathFromArgs(args []string) string {
	for idx := 0; idx < len(args); idx++ {
		if args[idx] == "--state" && idx+1 < len(args) {
			return args[idx+1]
		}
		if strings.HasPrefix(args[idx], "--state=") {
			return strings.TrimSpace(strings.TrimPrefix(args[idx], "--state="))
		}
	}
	return ""
}
