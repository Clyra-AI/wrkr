package scenarios

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestControlBacklogGovernance(t *testing.T) {
	repoRoot := mustFindRepoRootWithoutTag(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "control-backlog-governance", "repos")
	first := runControlBacklogScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state-a.json"), "--json"})
	second := runControlBacklogScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state-b.json"), "--json"})

	backlog := requireScenarioObject(t, first, "control_backlog")
	if backlog["control_backlog_version"] != "1" {
		t.Fatalf("unexpected control backlog version: %v", backlog["control_backlog_version"])
	}
	items := requireScenarioArrayFromObject(t, backlog, "items")
	if len(items) == 0 {
		t.Fatal("expected control backlog items")
	}
	if !scenarioPayloadsEqual(backlog["items"], requireScenarioObject(t, second, "control_backlog")["items"]) {
		t.Fatalf("expected deterministic backlog ordering\nfirst=%v\nsecond=%v", backlog["items"], requireScenarioObject(t, second, "control_backlog")["items"])
	}
	seenUnique := false
	seenSupporting := false
	for _, raw := range items {
		item := requireScenarioMap(t, raw)
		if item["signal_class"] == "unique_wrkr_signal" {
			seenUnique = true
		}
		if item["signal_class"] == "supporting_security_signal" {
			seenSupporting = true
		}
		if links, ok := item["linked_finding_ids"].([]any); !ok || len(links) == 0 {
			t.Fatalf("expected linked finding ids on item: %v", item)
		}
	}
	if !seenUnique || !seenSupporting {
		t.Fatalf("expected unique and supporting signal classes in %v", items)
	}
	if _, ok := first["findings"].([]any); !ok {
		t.Fatalf("legacy findings missing: %v", first)
	}
	if _, ok := first["top_findings"].([]any); !ok {
		t.Fatalf("legacy top_findings missing: %v", first)
	}
	if _, ok := first["inventory"].(map[string]any); !ok {
		t.Fatalf("legacy inventory missing: %v", first)
	}
}

func TestSecretReferenceSemantics(t *testing.T) {
	repoRoot := mustFindRepoRootWithoutTag(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "secret-reference-semantics", "repos")
	payload := runControlBacklogScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})
	backlog := requireScenarioObject(t, payload, "control_backlog")
	items := requireScenarioArrayFromObject(t, backlog, "items")

	foundSecretReference := false
	for _, raw := range items {
		item := requireScenarioMap(t, raw)
		signals, _ := item["secret_signal_types"].([]any)
		if len(signals) == 0 {
			continue
		}
		if scenarioArrayContains(signals, "secret_reference_detected") {
			foundSecretReference = true
		}
		if scenarioArrayContains(signals, "secret_value_detected") {
			t.Fatalf("workflow secret reference was misclassified as secret value: %v", item)
		}
		if !scenarioArrayContains(signals, "secret_used_by_write_capable_workflow") {
			t.Fatalf("expected write-capable secret workflow signal: %v", item)
		}
		if action := item["recommended_action"]; action != "attach_evidence" && action != "approve" {
			t.Fatalf("expected attach_evidence or approve, got %v in %v", action, item)
		}
	}
	if !foundSecretReference {
		t.Fatalf("expected a secret reference backlog item in %v", items)
	}
	if bytes, ok := payload["findings"]; ok && scenarioPayloadContains(bytes, "super-secret-value") {
		t.Fatal("raw secret value leaked in findings payload")
	}
}

func requireScenarioObject(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := payload[key].(map[string]any)
	if !ok {
		t.Fatalf("expected %s object, got %T (%v)", key, payload[key], payload[key])
	}
	return value
}

func runControlBacklogScenarioCommandJSON(t *testing.T, args []string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run(args, &out, &errOut); code != 0 {
		t.Fatalf("command failed: %v code=%d stderr=%s", args, code, errOut.String())
	}
	payload := map[string]any{}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse command json output for %v: %v", args, err)
	}
	return payload
}

func requireScenarioArrayFromObject(t *testing.T, payload map[string]any, key string) []any {
	t.Helper()
	value, ok := payload[key].([]any)
	if !ok {
		t.Fatalf("expected %s array, got %T (%v)", key, payload[key], payload[key])
	}
	return value
}

func requireScenarioMap(t *testing.T, value any) map[string]any {
	t.Helper()
	item, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected object, got %T (%v)", value, value)
	}
	return item
}

func scenarioArrayContains(values []any, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func scenarioPayloadContains(value any, needle string) bool {
	encoded, _ := json.Marshal(value)
	return strings.Contains(string(encoded), needle)
}

func scenarioPayloadsEqual(a, b any) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return string(left) == string(right)
}
