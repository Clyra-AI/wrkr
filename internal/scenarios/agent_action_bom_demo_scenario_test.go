//go:build scenario

package scenarios

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestScenarioAgentActionBOMDemoContract(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	expectedRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "agent-action-bom-demo", "expected")

	beforeOutput := filepath.Join(t.TempDir(), "before")
	runDemoScript(t, repoRoot, "before", beforeOutput)
	beforeScan := extractDemoTopActionPath(t, filepath.Join(beforeOutput, "scan.json"))
	beforeReport := extractDemoTopBOM(t, filepath.Join(beforeOutput, "report.json"))

	afterOutput := filepath.Join(t.TempDir(), "after")
	runDemoScript(t, repoRoot, "after", afterOutput)
	afterScan := extractDemoTopActionPath(t, filepath.Join(afterOutput, "scan.json"))
	afterReport := extractDemoTopBOM(t, filepath.Join(afterOutput, "report.json"))
	afterIngest := extractDemoJSONFile(t, filepath.Join(afterOutput, "ingest.json"), "runtime_evidence", "correlations")
	afterEvidenceReport := extractDemoEvidenceReport(t, filepath.Join(afterOutput, "evidence-bundle", "reports", "agent-action-bom.json"))

	assertDemoScenarioEqual(t, beforeScan, mustLoadDemoScenarioValue(t, filepath.Join(expectedRoot, "before-scan.json")))
	assertDemoScenarioEqual(t, beforeReport, mustLoadDemoScenarioValue(t, filepath.Join(expectedRoot, "before-report.json")))
	assertDemoScenarioEqual(t, afterScan, mustLoadDemoScenarioValue(t, filepath.Join(expectedRoot, "after-scan.json")))
	assertDemoScenarioEqual(t, afterReport, mustLoadDemoScenarioValue(t, filepath.Join(expectedRoot, "after-report.json")))
	assertDemoScenarioEqual(t, afterIngest, mustLoadDemoScenarioValue(t, filepath.Join(expectedRoot, "after-ingest.json")))
	assertDemoScenarioEqual(t, afterEvidenceReport, mustLoadDemoScenarioValue(t, filepath.Join(expectedRoot, "after-evidence-report.json")))
}

func runDemoScript(t *testing.T, repoRoot, mode, outputRoot string) {
	t.Helper()

	cmd := exec.Command("bash", filepath.Join(repoRoot, "scripts", "run_agent_action_bom_demo.sh"), mode, outputRoot) // #nosec G204 -- deterministic local demo fixture runner.
	cmd.Dir = repoRoot
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		t.Fatalf("demo script failed mode=%s err=%v stderr=%s", mode, err, errOut.String())
	}
}

func extractDemoTopActionPath(t *testing.T, path string) map[string]any {
	t.Helper()
	payload := mustLoadDemoScenarioJSON(t, path)
	paths := requireDemoScenarioArray(t, payload, "action_paths")
	first := requireDemoScenarioObjectItem(t, paths[0])
	return map[string]any{
		"top_action_path": map[string]any{
			"path_id":                    first["path_id"],
			"tool_type":                  first["tool_type"],
			"repo":                       first["repo"],
			"location":                   first["location"],
			"action_classes":             first["action_classes"],
			"credential_kind":            requireDemoScenarioObject(t, first, "credential_provenance")["credential_kind"],
			"matched_production_targets": first["matched_production_targets"],
			"policy_coverage_status":     first["policy_coverage_status"],
		},
	}
}

func extractDemoTopBOM(t *testing.T, path string) map[string]any {
	t.Helper()
	payload := mustLoadDemoScenarioJSON(t, path)
	bom := requireDemoScenarioObject(t, payload, "agent_action_bom")
	items := requireDemoScenarioArray(t, bom, "items")
	first := requireDemoScenarioObjectItem(t, items[0])
	topItem := map[string]any{
		"path_id":                 first["path_id"],
		"tool_type":               first["tool_type"],
		"policy_status":           first["policy_status"],
		"runtime_evidence_status": demoScenarioString(first["runtime_evidence_status"]),
	}
	if classes, ok := first["runtime_evidence_classes"]; ok && classes != nil {
		topItem["runtime_evidence_classes"] = classes
	}
	return map[string]any{
		"summary":  requireDemoScenarioObject(t, bom, "summary"),
		"top_item": topItem,
	}
}

func extractDemoEvidenceReport(t *testing.T, path string) map[string]any {
	t.Helper()
	payload := mustLoadDemoScenarioJSON(t, path)
	items := requireDemoScenarioArray(t, payload, "items")
	first := requireDemoScenarioObjectItem(t, items[0])
	topItem := map[string]any{
		"path_id":                 first["path_id"],
		"tool_type":               first["tool_type"],
		"policy_status":           first["policy_status"],
		"runtime_evidence_status": demoScenarioString(first["runtime_evidence_status"]),
	}
	if classes, ok := first["runtime_evidence_classes"]; ok && classes != nil {
		topItem["runtime_evidence_classes"] = classes
	}
	return map[string]any{
		"top_item": topItem,
		"summary":  requireDemoScenarioObject(t, payload, "summary"),
	}
}

func extractDemoJSONFile(t *testing.T, path string, keys ...string) any {
	t.Helper()
	payload := mustLoadDemoScenarioJSON(t, path)
	value := any(payload)
	for _, key := range keys {
		obj, ok := value.(map[string]any)
		if !ok {
			t.Fatalf("expected object while walking %s at key %s", path, key)
		}
		value = obj[key]
	}
	return value
}

func mustLoadDemoScenarioJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return decoded
}

func mustLoadDemoScenarioValue(t *testing.T, path string) any {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var decoded any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return decoded
}

func assertDemoScenarioEqual(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scenario mismatch\nwant=%#v\ngot=%#v", want, got)
	}
}

func requireDemoScenarioObject(t *testing.T, payload map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := payload[key].(map[string]any)
	if !ok {
		t.Fatalf("expected object %s, got %T (%v)", key, payload[key], payload[key])
	}
	return value
}

func requireDemoScenarioArray(t *testing.T, payload map[string]any, key string) []any {
	t.Helper()
	value, ok := payload[key].([]any)
	if !ok {
		t.Fatalf("expected array %s, got %T (%v)", key, payload[key], payload[key])
	}
	return value
}

func requireDemoScenarioObjectItem(t *testing.T, value any) map[string]any {
	t.Helper()
	record, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected object item, got %T (%v)", value, value)
	}
	return record
}

func demoScenarioString(value any) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}
