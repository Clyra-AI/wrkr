package contracts

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestWave32SchemasDeclareAgenticDeliveryAndDecisionTraceFields(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	cases := []struct {
		name       string
		path       string
		definition string
	}{
		{
			name:       "agent action bom item",
			path:       filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"),
			definition: "item",
		},
		{
			name:       "risk report action path",
			path:       filepath.Join(repoRoot, "schemas", "v1", "risk", "risk-report.schema.json"),
			definition: "actionPath",
		},
		{
			name:       "report summary action path",
			path:       filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"),
			definition: "actionPath",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			schema := mustReadJSON(t, tc.path)
			props := schemaDefinitionProperties(t, schema, tc.definition)
			if _, ok := props["agentic_delivery_system_change"].(map[string]any); !ok {
				t.Fatalf("%s schema missing agentic_delivery_system_change: %v", tc.name, props)
			}
			if _, ok := props["decision_trace_refs"].(map[string]any); !ok {
				t.Fatalf("%s schema missing decision_trace_refs: %v", tc.name, props)
			}
		})
	}

	bomSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"))
	primaryProps := schemaDefinitionProperties(t, bomSchema, "primaryView")
	if _, ok := primaryProps["agentic_delivery_system_change"].(map[string]any); !ok {
		t.Fatalf("primaryView schema missing agentic_delivery_system_change: %v", primaryProps)
	}
	if _, ok := primaryProps["decision_trace_refs"].(map[string]any); !ok {
		t.Fatalf("primaryView schema missing decision_trace_refs: %v", primaryProps)
	}
}

func TestWave32ReportProjectsAgenticDeliveryChangesAndDecisionTraceRefs(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "agent-action-bom-demo", "after", "repos", "demo-app")
	statePath := filepath.Join(t.TempDir(), "state.json")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := cli.Run([]string{"report", "--state", statePath, "--template", "agent-action-bom", "--json"}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report failed: %d (%s)", code, reportErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(reportOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	bom, ok := payload["agent_action_bom"].(map[string]any)
	if !ok {
		t.Fatalf("expected agent_action_bom payload, got %T", payload["agent_action_bom"])
	}
	items, ok := bom["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected bom items, got %v", bom["items"])
	}

	foundChange := false
	foundTraceRefs := false
	for _, raw := range items {
		item, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if change, ok := item["agentic_delivery_system_change"].(map[string]any); ok {
			if change["surface_type"] != nil && change["authority_impact"] != nil && change["review_state"] != nil {
				foundChange = true
			}
		}
		if refs, ok := item["decision_trace_refs"].([]any); ok && len(refs) > 0 {
			foundTraceRefs = true
		}
	}
	if !foundChange {
		t.Fatalf("expected report bom item with agentic delivery-system change, got %v", bom["items"])
	}
	if !foundTraceRefs {
		t.Fatalf("expected report bom item with decision_trace_refs, got %v", bom["items"])
	}
}
