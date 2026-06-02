//go:build scenario

package scenarios

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestScenarioWave41PrecisionCalibration(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "precision-calibration", "repos")
	expectedPath := filepath.Join(repoRoot, "scenarios", "wrkr", "precision-calibration", "expected", "calibration-summary.json")
	statePath := filepath.Join(t.TempDir(), "precision-calibration-state.json")

	scanPayload := runScenarioCommandJSON(t, []string{"scan", "--path", scanRoot, "--state", statePath, "--json"})
	runtimeEvidencePath := filepath.Join(t.TempDir(), "precision-runtime-evidence.json")
	writePrecisionRuntimeEvidence(t, runtimeEvidencePath, firstRepoPathID(t, cloneArray(scanPayload["action_paths"]), "deploy-agent"))
	runScenarioCommandJSON(t, []string{"ingest", "--state", statePath, "--input", runtimeEvidencePath, "--json"})
	reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--template", "agent-action-bom", "--json"})

	projected := projectPrecisionCalibration(scanPayload, reportPayload)
	if os.Getenv("WRKR_UPDATE_GOLDENS") == "1" {
		writeScenarioGolden(t, expectedPath, projected)
		return
	}

	expected := mustLoadScenarioGolden(t, expectedPath)
	if !scenarioPayloadsEqual(projected, expected) {
		t.Fatalf("precision calibration drifted\nprojected=%v\nexpected=%v", projected, expected)
	}
}

func writePrecisionRuntimeEvidence(t *testing.T, path string, pathID string) {
	t.Helper()

	payload := `{
  "schema_version": "v1",
  "generated_at": "2026-05-31T17:00:00Z",
  "records": [
    {
      "record_kind": "runtime",
      "record_id": "deploy-agent-approval",
      "path_id": "` + pathID + `",
      "repo": "deploy-agent",
      "location": ".github/workflows/release.yml",
      "tool": "ci_agent",
      "source": "demo_runtime_export",
      "observed_at": "2026-05-31T16:55:00Z",
      "evidence_class": "approval",
      "status": "matched",
      "evidence_refs": [
        "evidence://public/runtime.json#deploy-agent-approval"
      ]
    },
    {
      "record_kind": "runtime",
      "record_id": "deploy-agent-proof",
      "path_id": "` + pathID + `",
      "repo": "deploy-agent",
      "location": ".github/workflows/release.yml",
      "tool": "ci_agent",
      "source": "demo_runtime_export",
      "observed_at": "2026-05-31T16:56:00Z",
      "evidence_class": "proof_verification",
      "status": "matched",
      "proof_ref": "proof_head:deploy-agent"
    }
  ]
}`
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("write runtime evidence: %v", err)
	}
}

func projectPrecisionCalibration(scanPayload, reportPayload map[string]any) map[string]any {
	repos := []string{
		"owner-evidence",
		"approval-sidecar",
		"non-prod-contradiction",
		"dependency-only",
		"ci-without-agent",
		"deploy-agent",
		"branch-protected",
		"branch-unprotected",
		"source-only-old",
	}

	findings := cloneArray(scanPayload["findings"])
	actionPaths := cloneArray(reportPayload["action_paths"])
	bomItems := cloneArray(nestedObject(reportPayload, "agent_action_bom")["items"])
	backlogItems := cloneArray(nestedObject(reportPayload, "control_backlog")["items"])

	projected := map[string]any{}
	for _, repo := range repos {
		projected[repo] = map[string]any{
			"finding_types":        collectFindingTypes(findings, repo),
			"framework_candidates": collectFrameworkCandidates(findings, repo),
			"action_paths":         collectRepoActionPaths(actionPaths, repo),
			"bom_items":            collectRepoBOMItems(bomItems, repo),
			"control_backlog":      collectRepoBacklog(backlogItems, repo),
		}
	}
	return projected
}

func firstRepoPathID(t *testing.T, actionPaths []any, repo string) string {
	t.Helper()
	for _, raw := range actionPaths {
		row := requireScenarioMapForRepo(raw)
		if stringValue(row["repo"]) == repo {
			return stringValue(row["path_id"])
		}
	}
	t.Fatalf("expected action path for repo %s", repo)
	return ""
}

func collectFindingTypes(findings []any, repo string) []any {
	out := []string{}
	for _, raw := range findings {
		row := requireScenarioMapForRepo(raw)
		if stringValue(row["repo"]) != repo {
			continue
		}
		out = append(out, stringValue(row["finding_type"]))
	}
	sort.Strings(out)
	values := dedupeStrings(out)
	outAny := make([]any, len(values))
	for idx, value := range values {
		outAny[idx] = value
	}
	return outAny
}

func collectFrameworkCandidates(findings []any, repo string) []any {
	out := []string{}
	for _, raw := range findings {
		row := requireScenarioMapForRepo(raw)
		if stringValue(row["repo"]) != repo || stringValue(row["finding_type"]) != "framework_candidate" {
			continue
		}
		out = append(out, stringValue(row["tool_type"]))
	}
	sort.Strings(out)
	values := dedupeStrings(out)
	outAny := make([]any, len(values))
	for idx, value := range values {
		outAny[idx] = value
	}
	return outAny
}

func collectRepoActionPaths(actionPaths []any, repo string) []any {
	out := []map[string]any{}
	for _, raw := range actionPaths {
		row := requireScenarioMapForRepo(raw)
		if stringValue(row["repo"]) != repo {
			continue
		}
		out = append(out, map[string]any{
			"path_id":                  row["path_id"],
			"action_path_type":         row["action_path_type"],
			"control_resolution_state": row["control_resolution_state"],
			"recommended_action":       row["recommended_action"],
			"approval_evidence_state":  row["approval_evidence_state"],
			"owner_evidence_state":     row["owner_evidence_state"],
			"target_evidence_state":    row["target_evidence_state"],
			"runtime_evidence_state":   row["runtime_evidence_state"],
			"constraint_evidence":      row["constraint_evidence_classes"],
			"contradiction_count":      row["contradiction_count"],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return stringValue(out[i]["path_id"]) < stringValue(out[j]["path_id"])
	})
	outAny := make([]any, len(out))
	for idx, value := range out {
		outAny[idx] = value
	}
	return outAny
}

func collectRepoBOMItems(items []any, repo string) []any {
	out := []map[string]any{}
	for _, raw := range items {
		row := requireScenarioMapForRepo(raw)
		if stringValue(row["repo"]) != repo {
			continue
		}
		out = append(out, map[string]any{
			"path_id":                  row["path_id"],
			"action_path_type":         row["action_path_type"],
			"control_state":            row["control_state"],
			"queue":                    row["queue"],
			"approval_evidence_state":  row["approval_evidence_state"],
			"owner_evidence_state":     row["owner_evidence_state"],
			"runtime_evidence_status":  row["runtime_evidence_status"],
			"runtime_evidence_classes": row["runtime_evidence_classes"],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return stringValue(out[i]["path_id"]) < stringValue(out[j]["path_id"])
	})
	outAny := make([]any, len(out))
	for idx, value := range out {
		outAny[idx] = value
	}
	return outAny
}

func collectRepoBacklog(items []any, repo string) []any {
	out := []map[string]any{}
	for _, raw := range items {
		row := requireScenarioMapForRepo(raw)
		if stringValue(row["repo"]) != repo {
			continue
		}
		out = append(out, map[string]any{
			"id":                 row["id"],
			"queue":              row["queue"],
			"recommended_action": row["recommended_action"],
			"signal_class":       row["signal_class"],
			"finding_visibility": row["finding_visibility"],
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return stringValue(out[i]["id"]) < stringValue(out[j]["id"])
	})
	outAny := make([]any, len(out))
	for idx, value := range out {
		outAny[idx] = value
	}
	return outAny
}

func mustLoadScenarioGolden(t *testing.T, path string) map[string]any {
	t.Helper()

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scenario golden %s: %v", path, err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("parse scenario golden %s: %v", path, err)
	}
	return out
}

func writeScenarioGolden(t *testing.T, path string, payload map[string]any) {
	t.Helper()

	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal scenario golden: %v", err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o600); err != nil {
		t.Fatalf("write scenario golden %s: %v", path, err)
	}
}

func requireScenarioMapForRepo(value any) map[string]any {
	item, ok := value.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return item
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := []string{values[0]}
	for _, value := range values[1:] {
		if value == out[len(out)-1] {
			continue
		}
		out = append(out, value)
	}
	return out
}

func nestedObject(value map[string]any, key string) map[string]any {
	item, ok := value[key].(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return item
}

func cloneArray(value any) []any {
	items, ok := value.([]any)
	if !ok {
		return []any{}
	}
	out := make([]any, len(items))
	copy(out, items)
	return out
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}
