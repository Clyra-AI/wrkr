package siteassets

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestGeneratedSiteAssetsMatchCheckedInCopies(t *testing.T) {
	t.Parallel()

	repoRoot := mustRepoRoot(t)
	assetSet, err := Build(repoRoot)
	if err != nil {
		t.Fatalf("build site assets: %v", err)
	}

	expectedDir := filepath.Join(repoRoot, "docs", "examples", "site-assets")
	for _, name := range PublishedFilenames() {
		expectedPath := filepath.Join(expectedDir, name)
		expected, err := os.ReadFile(expectedPath)
		if err != nil {
			t.Fatalf("read checked-in asset %s: %v", name, err)
		}
		generated, ok := assetSet.Files[name]
		if !ok {
			t.Fatalf("generated asset missing %s", name)
		}
		if string(generated) != string(expected) {
			t.Fatalf("site asset drifted for %s; %s; run `go run ./scripts/generate_site_assets --repo-root . --output-dir ./docs/examples/site-assets`", name, firstDiffSnippet(expected, generated))
		}
	}
}

func firstDiffSnippet(expected, generated []byte) string {
	expectedLines := strings.Split(string(expected), "\n")
	generatedLines := strings.Split(string(generated), "\n")
	limit := len(expectedLines)
	if len(generatedLines) < limit {
		limit = len(generatedLines)
	}
	for idx := 0; idx < limit; idx++ {
		if expectedLines[idx] == generatedLines[idx] {
			continue
		}
		return "first diff at line " + itoa(idx+1) + ": expected=" + expectedLines[idx] + " generated=" + generatedLines[idx]
	}
	if len(expectedLines) != len(generatedLines) {
		return "line count differs: expected=" + itoa(len(expectedLines)) + " generated=" + itoa(len(generatedLines))
	}
	return "content differs"
}

func itoa(value int) string {
	return strconv.Itoa(value)
}

func TestPublishedSiteAssetsPassHygieneChecks(t *testing.T) {
	t.Parallel()

	repoRoot := mustRepoRoot(t)
	dir := filepath.Join(repoRoot, "docs", "examples", "site-assets")
	files := map[string][]byte{}
	for _, name := range PublishedFilenames() {
		payload, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read published asset %s: %v", name, err)
		}
		files[name] = payload
	}
	if err := ValidateFiles(files); err != nil {
		t.Fatalf("published site assets failed hygiene validation: %v", err)
	}
}

func TestPublishedSiteAssetDirectoryHasExpectedFilesOnly(t *testing.T) {
	t.Parallel()

	repoRoot := mustRepoRoot(t)
	dir := filepath.Join(repoRoot, "docs", "examples", "site-assets")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read site-assets dir: %v", err)
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			t.Fatalf("unexpected nested directory in site-assets: %s", entry.Name())
		}
		actual = append(actual, entry.Name())
	}
	sort.Strings(actual)
	expected := PublishedFilenames()
	sort.Strings(expected)
	if len(actual) != len(expected) {
		t.Fatalf("unexpected site-assets file count: got=%v want=%v", actual, expected)
	}
	for idx := range actual {
		if actual[idx] != expected[idx] {
			t.Fatalf("unexpected site-assets files: got=%v want=%v", actual, expected)
		}
	}
}

func TestProjectControlPathGraphCanonicalizesRawIDs(t *testing.T) {
	t.Parallel()

	first := sampleControlPathGraph("raw-node-a", "raw-node-b", "raw-edge-a")
	second := sampleControlPathGraph("raw-node-x", "raw-node-y", "raw-edge-x")
	firstPayload, err := marshalJSON(normalizePublishedValue(projectControlPathGraph(first)))
	if err != nil {
		t.Fatalf("marshal first graph: %v", err)
	}
	secondPayload, err := marshalJSON(normalizePublishedValue(projectControlPathGraph(second)))
	if err != nil {
		t.Fatalf("marshal second graph: %v", err)
	}
	if string(firstPayload) != string(secondPayload) {
		t.Fatalf("projected graph should ignore volatile raw IDs\nfirst:\n%s\nsecond:\n%s", firstPayload, secondPayload)
	}
}

func TestProjectExecutiveRollupCanonicalizesExampleSelectionAfterOpaqueProjection(t *testing.T) {
	t.Parallel()

	rollup := map[string]any{
		"total_groups": 1,
		"total_paths":  4,
		"groups": []any{
			map[string]any{
				"group_id":               "xrg-demo",
				"count":                  4,
				"highest_severity":       "high",
				"highest_priority":       "review_queue",
				"closure_recommendation": "attach evidence",
				"top_example_refs":       []any{"raw-a", "raw-b", "raw-d"},
				"rationale":              []any{"demo rationale"},
				"evidence_state_summary": map[string]any{"verified": 0, "declared": 0, "inferred": 0, "unknown": 4, "contradictory": 0},
				"dimensions":             map[string]any{"action_class": "read", "target_class": "developer_productivity"},
			},
		},
	}
	ids := publishedIDMaps{
		Path: map[string]string{
			"raw-a": "path-c",
			"raw-b": "path-a",
			"raw-c": "path-b",
			"raw-d": "path-d",
		},
	}
	selectionKey := executiveRollupExampleSelectionKey(map[string]any{
		"action_classes": []any{"read"},
	})
	selectionKeyByRawPathID := map[string]string{
		"raw-a": selectionKey,
		"raw-b": selectionKey,
		"raw-c": selectionKey,
		"raw-d": selectionKey,
	}
	projectedPathIDsBySelectionKey := map[string][]string{
		selectionKey: {"path-c", "path-a", "path-b", "path-d"},
	}

	projected, err := marshalJSON(normalizePublishedValue(projectExecutiveRollup(rollup, ids, selectionKeyByRawPathID, projectedPathIDsBySelectionKey)))
	if err != nil {
		t.Fatalf("marshal rollup: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(projected, &decoded); err != nil {
		t.Fatalf("unmarshal projected rollup: %v", err)
	}
	groups := cloneArray(decoded["groups"])
	if len(groups) != 1 {
		t.Fatalf("expected one projected group, got %d", len(groups))
	}
	gotRefs := stringArray(requireObjectFromAny(groups[0])["top_example_refs"])
	wantRefs := []string{"path-a", "path-b", "path-c"}
	if !reflect.DeepEqual(gotRefs, wantRefs) {
		t.Fatalf("expected projected executive rollup refs %v, got %v", wantRefs, gotRefs)
	}
}

func TestProjectGovernedUsageMetricsUsesDisplayedRowsAndPreservesSourceCounters(t *testing.T) {
	t.Parallel()

	items := []map[string]any{
		{
			"path_id":                  "path-dependency",
			"action_path_type":         "dependency_only_signal",
			"standing_privilege":       true,
			"risk_zone":                "production_data",
			"control_resolution_state": "declared_control",
		},
		{
			"path_id":                  "path-release",
			"action_path_type":         "ci_cd_workflow",
			"standing_privilege":       true,
			"risk_zone":                "release",
			"queue":                    "control_first",
			"control_resolution_state": "external_control_reference",
		},
		{
			"path_id":                  "path-agent",
			"action_path_type":         "ai_assisted_workflow",
			"risk_zone":                "credential_bearing",
			"control_resolution_state": "detected_control",
		},
	}
	sourceMetrics := map[string]any{
		"approval_decisions": 7,
		"connected_runtimes": 3,
		"evidence_packs":     2,
		"audit_exports":      9,
	}

	metrics := projectGovernedUsageMetrics(sourceMetrics, items)
	if got := objectCount(metrics["active_monitored_action_paths"]); got != 2 {
		t.Fatalf("expected dependency-only rows excluded from active paths, got %d metrics=%v", got, metrics)
	}
	if got := objectCount(metrics["verified_control_paths"]); got != 3 {
		t.Fatalf("expected detected, declared, and external controls counted as verified, got %d metrics=%v", got, metrics)
	}
	for key, want := range map[string]int{
		"approval_decisions": 7,
		"connected_runtimes": 3,
		"evidence_packs":     2,
		"audit_exports":      9,
	} {
		if got := objectCount(metrics[key]); got != want {
			t.Fatalf("expected preserved source metric %s=%d, got %d metrics=%v", key, want, got, metrics)
		}
	}

	summary := projectAgentActionBOMSummary(map[string]any{
		"governed_usage_metrics": sourceMetrics,
		"primary_view":           map[string]any{},
	}, items, publishedIDMaps{})
	if got := objectCount(summary["standing_privilege_items"]); got != 2 {
		t.Fatalf("expected standing privilege count from explicit flag, got %d summary=%v", got, summary)
	}
}

func TestProjectSampleExecutiveRollupUsesPublishedPathRefsAndEvidenceStates(t *testing.T) {
	t.Parallel()

	rollup := projectSampleExecutiveRollup([]map[string]any{
		{
			"path_id":                    "path-declared",
			"risk_zone":                  "release",
			"target_class":               "release_adjacent",
			"confidence_lane":            "confirmed_action_path",
			"control_resolution_state":   "declared_control",
			"approval_evidence_state":    "declared",
			"owner_evidence_state":       "verified",
			"proof_evidence_state":       "verified",
			"runtime_evidence_state":     "verified",
			"target_evidence_state":      "verified",
			"credential_evidence_state":  "verified",
			"delegation_readiness_state": "ready_for_control",
		},
		{
			"path_id":                    "path-unknown",
			"risk_zone":                  "release",
			"target_class":               "release_adjacent",
			"confidence_lane":            "confirmed_action_path",
			"control_resolution_state":   "detected_control",
			"approval_evidence_state":    "verified",
			"owner_evidence_state":       "verified",
			"proof_evidence_state":       "unknown",
			"runtime_evidence_state":     "verified",
			"target_evidence_state":      "verified",
			"credential_evidence_state":  "verified",
			"delegation_readiness_state": "proof_required",
		},
		{
			"path_id":                    "path-contradictory",
			"risk_zone":                  "production_data",
			"target_class":               "customer_data_adjacent",
			"confidence_lane":            "semantic_review_candidate",
			"control_resolution_state":   "contradictory_control",
			"approval_evidence_state":    "verified",
			"owner_evidence_state":       "verified",
			"proof_evidence_state":       "verified",
			"runtime_evidence_state":     "verified",
			"target_evidence_state":      "verified",
			"credential_evidence_state":  "verified",
			"delegation_readiness_state": "blocked_by_contradiction",
		},
	})
	groups := cloneArray(rollup["groups"])
	if len(groups) != 3 {
		t.Fatalf("expected one group per evidence/action shape, got %d rollup=%v", len(groups), rollup)
	}
	seenStates := map[string]bool{}
	for _, raw := range groups {
		group := requireObjectFromAny(raw)
		dimensions := requireObjectFromAny(group["dimensions"])
		for _, forbidden := range []string{"control_resolution_state", "delegation_readiness_state", "queue"} {
			if _, ok := dimensions[forbidden]; ok {
				t.Fatalf("published rollup dimension %s is not in the schema contract: %v", forbidden, dimensions)
			}
		}
		for _, ref := range stringArray(group["top_example_refs"]) {
			if strings.HasPrefix(ref, "path-example-") {
				t.Fatalf("expected real published path refs, got %v", group["top_example_refs"])
			}
		}
		seenStates[stringValue(dimensions["evidence_state"])] = true
	}
	for _, state := range []string{"declared", "unknown", "contradictory"} {
		if !seenStates[state] {
			t.Fatalf("expected evidence state %s in rollup dimensions, got %v", state, seenStates)
		}
	}
}

func TestPrepareScenarioSnapshotCopiesOnlyTrackedFixtureFiles(t *testing.T) {
	t.Parallel()

	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git unavailable: %v", err)
	}
	repoRoot := t.TempDir()
	runGit(t, repoRoot, "init")

	trackedRel := filepath.ToSlash(filepath.Join(ScenarioRelPath, "tracked.txt"))
	trackedPath := filepath.Join(repoRoot, filepath.FromSlash(trackedRel))
	if err := os.MkdirAll(filepath.Dir(trackedPath), 0o750); err != nil {
		t.Fatalf("create tracked fixture dir: %v", err)
	}
	if err := os.WriteFile(trackedPath, []byte("tracked\n"), 0o600); err != nil {
		t.Fatalf("write tracked fixture: %v", err)
	}

	untrackedRel := filepath.ToSlash(filepath.Join(ScenarioRelPath, "local-only", "settings.json"))
	untrackedPath := filepath.Join(repoRoot, filepath.FromSlash(untrackedRel))
	if err := os.MkdirAll(filepath.Dir(untrackedPath), 0o750); err != nil {
		t.Fatalf("create untracked fixture dir: %v", err)
	}
	if err := os.WriteFile(untrackedPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write untracked fixture: %v", err)
	}

	runGit(t, repoRoot, "add", trackedRel)

	snapshotRoot, err := prepareScenarioSnapshot(repoRoot, t.TempDir())
	if err != nil {
		t.Fatalf("prepare scenario snapshot: %v", err)
	}
	if payload, err := os.ReadFile(filepath.Join(snapshotRoot, "tracked.txt")); err != nil || string(payload) != "tracked\n" {
		t.Fatalf("tracked file not copied correctly: payload=%q err=%v", string(payload), err)
	}
	if _, err := os.Stat(filepath.Join(snapshotRoot, "local-only", "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("untracked file should not be copied, err=%v", err)
	}
}

func sampleControlPathGraph(fromNodeID, toNodeID, edgeID string) map[string]any {
	return map[string]any{
		"version": "1",
		"summary": map[string]any{
			"total_nodes": 2,
			"total_edges": 1,
		},
		"nodes": []any{
			map[string]any{
				"node_id":         fromNodeID,
				"path_id":         "path-demo",
				"kind":            "human_identity",
				"lineage_segment": "human",
				"label":           "label-human",
				"boundary_label":  "report_only",
				"status":          "present",
			},
			map[string]any{
				"node_id":         toNodeID,
				"path_id":         "path-demo",
				"kind":            "task",
				"lineage_segment": "task",
				"label":           "label-task",
				"boundary_label":  "report_only",
				"status":          "present",
			},
		},
		"edges": []any{
			map[string]any{
				"edge_id":        edgeID,
				"path_id":        "path-demo",
				"kind":           "human_delegates_task",
				"boundary_label": "report_only",
				"from_node_id":   fromNodeID,
				"to_node_id":     toNodeID,
			},
		},
	}
}

func runGit(t *testing.T, repoRoot string, args ...string) {
	t.Helper()

	cmdArgs := append([]string{"-C", repoRoot}, args...)
	cmd := exec.Command("git", cmdArgs...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
}

func mustRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(wd, "go.mod")); statErr == nil {
			return wd
		}
		next := filepath.Dir(wd)
		if next == wd {
			t.Fatal("could not locate repo root")
		}
		wd = next
	}
}
