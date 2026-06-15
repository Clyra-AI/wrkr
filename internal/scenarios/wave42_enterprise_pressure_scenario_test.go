//go:build scenario

package scenarios

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/cli"
	"github.com/Clyra-AI/wrkr/internal/enterprisepressure"
)

type enterprisePressureContract struct {
	RepoCount               int      `json:"repo_count"`
	MinimumInventoryRows    int      `json:"minimum_inventory_rows"`
	MinimumRollupGroups     int      `json:"minimum_rollup_groups"`
	MaximumMarkdownLines    int      `json:"maximum_markdown_lines"`
	MaximumGraphNodes       int      `json:"maximum_graph_nodes"`
	MinimumProofRecords     int      `json:"minimum_proof_records"`
	RequiredDriftCategories []string `json:"required_drift_categories"`
	RequiredShareProfiles   []string `json:"required_share_profiles"`
	Performance             struct {
		ScanMaxMS   int `json:"scan_max_ms"`
		ReportMaxMS int `json:"report_max_ms"`
	} `json:"performance"`
}

func TestScenarioWave42EnterprisePressureContract(t *testing.T) {
	repoRoot := mustFindRepoRoot(t)
	contract := loadEnterprisePressureContract(t, repoRoot)
	tmp := t.TempDir()
	baselineRoot := filepath.Join(tmp, "baseline")
	currentRoot := filepath.Join(tmp, "current")
	if err := enterprisepressure.Materialize(baselineRoot, enterprisepressure.VariantBaseline); err != nil {
		t.Fatalf("materialize baseline enterprise fixture: %v", err)
	}
	if err := enterprisepressure.Materialize(currentRoot, enterprisepressure.VariantCurrent); err != nil {
		t.Fatalf("materialize current enterprise fixture: %v", err)
	}

	baselineState := filepath.Join(tmp, "baseline-state.json")
	scanStarted := time.Now()
	baselineScan := runScenarioCommandJSON(t, []string{"scan", "--path", baselineRoot, "--state", baselineState, "--quiet", "--json"})
	scanDuration := time.Since(scanStarted)

	mdPath := filepath.Join(tmp, "enterprise-pressure.md")
	evidencePath := filepath.Join(tmp, "enterprise-pressure-evidence.json")
	reportStarted := time.Now()
	reportPayload := runScenarioCommandJSON(t, []string{
		"report",
		"--state", baselineState,
		"--template", "ciso",
		"--md",
		"--md-path", mdPath,
		"--evidence-json",
		"--evidence-json-path", evidencePath,
		"--json",
	})
	reportDuration := time.Since(reportStarted)

	evidencePayload := readScenarioJSONFile(t, evidencePath)
	contractSummary := requireScenarioObject(t, reportPayload, "summary")
	rollup := requireScenarioObject(t, contractSummary, "executive_rollup")
	proof := requireScenarioObject(t, contractSummary, "proof")
	graph := requireScenarioObject(t, evidencePayload, "control_path_graph")

	markdownBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read enterprise markdown: %v", err)
	}
	markdown := string(markdownBytes)
	markdownLines := len(strings.Split(strings.TrimRight(markdown, "\n"), "\n"))
	if !strings.Contains(markdown, "## Executive Rollup") || !strings.Contains(markdown, "## Control Backlog") {
		t.Fatalf("expected enterprise markdown to keep executive rollup and backlog sections, got %q", markdown)
	}
	if strings.Index(markdown, "## Executive Rollup") > strings.Index(markdown, "## Control Backlog") {
		t.Fatalf("expected executive rollup before backlog detail")
	}

	baselinePath := filepath.Join(tmp, "enterprise-pressure-baseline.json")
	runScenarioCommandJSON(t, []string{"regress", "init", "--baseline", baselineState, "--output", baselinePath, "--json"})
	currentState := filepath.Join(tmp, "current-state.json")
	_ = runScenarioCommandJSON(t, []string{"scan", "--path", currentRoot, "--state", currentState, "--quiet", "--json"})
	driftPayload := runScenarioCommandJSONAllowExit5(t, []string{"regress", "run", "--baseline", baselinePath, "--state", currentState, "--json"})
	driftCategories := collectDriftCategories(driftPayload)

	scorecard := map[string]any{
		"repo_count":              contract.RepoCount,
		"inventory_rows":          arrayLength(requireScenarioObject(t, baselineScan, "inventory")["agent_privilege_map"]),
		"action_path_count":       objectInt(rollup["total_paths"]),
		"executive_rollup_groups": objectInt(rollup["total_groups"]),
		"markdown_lines":          markdownLines,
		"graph_nodes":             arrayLength(graph["nodes"]),
		"graph_edges":             arrayLength(graph["edges"]),
		"proof_record_count":      objectInt(proof["record_count"]),
		"drift_categories":        driftCategories,
		"scan_duration_ms":        scanDuration.Milliseconds(),
		"report_duration_ms":      reportDuration.Milliseconds(),
	}

	if scorecard["inventory_rows"].(int) < contract.MinimumInventoryRows {
		t.Fatalf("expected at least %d inventory rows, got %v", contract.MinimumInventoryRows, scorecard["inventory_rows"])
	}
	if scorecard["executive_rollup_groups"].(int) < contract.MinimumRollupGroups {
		t.Fatalf("expected at least %d executive groups, got %v", contract.MinimumRollupGroups, scorecard["executive_rollup_groups"])
	}
	if markdownLines > contract.MaximumMarkdownLines {
		t.Fatalf("expected markdown readability under %d lines, got %d", contract.MaximumMarkdownLines, markdownLines)
	}
	if scorecard["graph_nodes"].(int) > contract.MaximumGraphNodes {
		t.Fatalf("expected graph nodes <= %d, got %v", contract.MaximumGraphNodes, scorecard["graph_nodes"])
	}
	if scorecard["proof_record_count"].(int) < contract.MinimumProofRecords {
		t.Fatalf("expected at least %d proof records, got %v", contract.MinimumProofRecords, scorecard["proof_record_count"])
	}
	for _, category := range contract.RequiredDriftCategories {
		if !containsStringValue(driftCategories, category) {
			t.Fatalf("expected drift category %s in %v", category, driftCategories)
		}
	}
	if os.Getenv("WRKR_ENTERPRISE_PRESSURE_ENFORCE_TIMINGS") == "1" {
		if scanDuration.Milliseconds() > int64(contract.Performance.ScanMaxMS) {
			t.Fatalf("enterprise scan exceeded budget: %dms > %dms", scanDuration.Milliseconds(), contract.Performance.ScanMaxMS)
		}
		if reportDuration.Milliseconds() > int64(contract.Performance.ReportMaxMS) {
			t.Fatalf("enterprise report exceeded budget: %dms > %dms", reportDuration.Milliseconds(), contract.Performance.ReportMaxMS)
		}
	}
	writeEnterprisePressureScorecardIfRequested(t, scorecard)
}

func TestScenarioWave42EnterprisePressureHardening(t *testing.T) {
	repoRoot := mustFindRepoRoot(t)
	contract := loadEnterprisePressureContract(t, repoRoot)
	tmp := t.TempDir()
	root := filepath.Join(tmp, "hardening")
	if err := enterprisepressure.MaterializeCount(root, enterprisepressure.VariantBaseline, 64); err != nil {
		t.Fatalf("materialize enterprise fixture: %v", err)
	}
	statePath := filepath.Join(tmp, "hardening-state.json")
	_ = runScenarioCommandJSON(t, []string{"scan", "--path", root, "--state", statePath, "--quiet", "--json"})

	for _, profile := range contract.RequiredShareProfiles {
		mdPath := filepath.Join(tmp, profile+".md")
		reportPayload := runScenarioCommandJSON(t, []string{
			"report",
			"--state", statePath,
			"--template", "ciso",
			"--share-profile", profile,
			"--md",
			"--md-path", mdPath,
			"--json",
		})
		reportJSON, err := json.Marshal(reportPayload)
		if err != nil {
			t.Fatalf("marshal report payload for %s: %v", profile, err)
		}
		markdown, err := os.ReadFile(mdPath)
		if err != nil {
			t.Fatalf("read markdown for %s: %v", profile, err)
		}
		combined := string(reportJSON) + "\n" + string(markdown)
		forbidden := []string{"/Users/", "proof://", "graph://", enterprisepressure.RepoName(1)}
		for _, token := range forbidden {
			if strings.Contains(combined, token) {
				t.Fatalf("share profile %s leaked forbidden token %q", profile, token)
			}
		}
	}
}

func TestScenarioWave42EnterprisePressureChaos(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "chaos")
	if err := enterprisepressure.MaterializeCount(root, enterprisepressure.VariantBaseline, 64); err != nil {
		t.Fatalf("materialize enterprise fixture: %v", err)
	}
	statePath := filepath.Join(tmp, "chaos-state.json")
	reportPayload := runScenarioCommandJSON(t, []string{"scan", "--path", root, "--state", statePath, "--quiet", "--json"})
	if scanQuality, ok := reportPayload["scan_quality"].(map[string]any); ok {
		if detectors, ok := scanQuality["detectors"].([]any); ok && len(detectors) == 0 {
			t.Fatalf("expected scan quality detector rows under enterprise pressure chaos fixture")
		}
	}

	badBaselinePath := filepath.Join(tmp, "bad-baseline.json")
	if err := os.WriteFile(badBaselinePath, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write bad baseline: %v", err)
	}
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"regress", "run", "--baseline", badBaselinePath, "--state", statePath, "--json"}, &out, &errOut)
	if code == 0 {
		t.Fatalf("expected corrupt baseline to fail closed")
	}
}

func TestScenarioWave42EndpointDenseProjectionBoundaries(t *testing.T) {
	tmp := t.TempDir()
	root := filepath.Join(tmp, "endpoint-dense")
	if err := enterprisepressure.MaterializeEndpointDense(root, 4, enterprisepressure.DefaultDenseOpenAPIOperations); err != nil {
		t.Fatalf("materialize endpoint-dense fixture: %v", err)
	}

	statePath := filepath.Join(tmp, "endpoint-dense-state.json")
	scanPayload := runScenarioCommandJSON(t, []string{"scan", "--path", root, "--state", statePath, "--quiet", "--json"})
	reportPath := filepath.Join(tmp, "endpoint-dense-evidence.json")
	reportPayload := runScenarioCommandJSON(t, []string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--share-profile", "customer-redacted",
		"--evidence-json",
		"--evidence-json-path", reportPath,
		"--json",
	})
	evidencePayload := readScenarioJSONFile(t, reportPath)

	actionPaths := requireScenarioArrayFromObject(t, scanPayload, "action_paths")
	groupedActionPathFound := false
	for _, raw := range actionPaths {
		path := requireScenarioMapForRepo(raw)
		count := objectInt(path["endpoint_ref_count"])
		refs := arrayLength(path["mutable_endpoint_semantic_refs"])
		if count > refs && count >= 1000 {
			groupedActionPathFound = true
			if strings.TrimSpace(stringValue(path["endpoint_ref_group_id"])) == "" {
				t.Fatalf("expected grouped action path to expose endpoint_ref_group_id, got %v", path)
			}
			if arrayLength(path["endpoint_ref_samples"]) == 0 {
				t.Fatalf("expected grouped action path to expose endpoint_ref_samples, got %v", path)
			}
		}
	}
	if !groupedActionPathFound {
		t.Fatalf("expected at least one grouped endpoint-dense action path, got %v", actionPaths)
	}

	bom := requireScenarioObject(t, reportPayload, "agent_action_bom")
	items := requireScenarioArrayFromObject(t, bom, "items")
	groupedBOMFound := false
	for _, raw := range items {
		item := requireScenarioMapForRepo(raw)
		count := objectInt(item["endpoint_ref_count"])
		refs := arrayLength(item["mutable_endpoint_semantic_refs"])
		if count > refs && count >= 1000 {
			groupedBOMFound = true
			if refs > 8 {
				t.Fatalf("expected BOM endpoint refs to stay bounded, got %d in %v", refs, item)
			}
			if arrayLength(item["endpoint_route_groups"]) == 0 {
				t.Fatalf("expected BOM endpoint_route_groups, got %v", item)
			}
			if arrayLength(item["endpoint_operation_counts"]) == 0 {
				t.Fatalf("expected BOM endpoint_operation_counts, got %v", item)
			}
		}
	}
	if !groupedBOMFound {
		t.Fatalf("expected grouped endpoint-dense BOM item, got %v", items)
	}

	graph := requireScenarioObject(t, evidencePayload, "control_path_graph")
	nodes := requireScenarioArrayFromObject(t, graph, "nodes")
	groupedNodeFound := false
	for _, raw := range nodes {
		node := requireScenarioMapForRepo(raw)
		count := objectInt(node["endpoint_ref_count"])
		refs := arrayLength(node["mutable_endpoint_semantic_refs"])
		if count > refs && count >= 1000 {
			groupedNodeFound = true
			if refs > 8 {
				t.Fatalf("expected graph node endpoint refs to stay bounded, got %d in %v", refs, node)
			}
		}
	}
	if !groupedNodeFound {
		t.Fatalf("expected grouped endpoint-dense graph node, got %v", nodes)
	}

	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatalf("read endpoint-dense state: %v", err)
	}
	if len(stateBytes) > 24<<20 {
		t.Fatalf("expected endpoint-dense saved state under 24MiB, got %d", len(stateBytes))
	}
}

func loadEnterprisePressureContract(t *testing.T, repoRoot string) enterprisePressureContract {
	t.Helper()

	path := filepath.Join(repoRoot, "scenarios", "wrkr", "enterprise-pressure", "expected", "contract.json")
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read enterprise contract: %v", err)
	}
	var contract enterprisePressureContract
	if err := json.Unmarshal(payload, &contract); err != nil {
		t.Fatalf("parse enterprise contract: %v", err)
	}
	return contract
}

func readScenarioJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read json file %s: %v", path, err)
	}
	out := map[string]any{}
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("parse json file %s: %v", path, err)
	}
	return out
}

func collectDriftCategories(payload map[string]any) []any {
	items := cloneArray(payload["drift_categories"])
	out := make([]string, 0, len(items))
	for _, raw := range items {
		row := requireScenarioMapForRepo(raw)
		out = append(out, stringValue(row["category"]))
	}
	sort.Strings(out)
	deduped := dedupeStrings(out)
	result := make([]any, len(deduped))
	for idx, item := range deduped {
		result[idx] = item
	}
	return result
}

func containsStringValue(items []any, want string) bool {
	for _, raw := range items {
		if text, ok := raw.(string); ok && text == want {
			return true
		}
	}
	return false
}

func writeEnterprisePressureScorecardIfRequested(t *testing.T, scorecard map[string]any) {
	t.Helper()

	dir := strings.TrimSpace(os.Getenv("WRKR_ENTERPRISE_PRESSURE_SCORECARD_DIR"))
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir scorecard dir: %v", err)
	}
	payload, err := json.MarshalIndent(scorecard, "", "  ")
	if err != nil {
		t.Fatalf("marshal enterprise scorecard: %v", err)
	}
	jsonPath := filepath.Join(dir, "enterprise-pressure-scorecard.json")
	if err := os.WriteFile(jsonPath, append(payload, '\n'), 0o600); err != nil {
		t.Fatalf("write enterprise scorecard json: %v", err)
	}
	lines := []string{
		"# Enterprise Pressure Scorecard",
		"",
		fmt.Sprintf("- Repo count: `%v`", scorecard["repo_count"]),
		fmt.Sprintf("- Inventory rows: `%v`", scorecard["inventory_rows"]),
		fmt.Sprintf("- Executive-rollup paths: `%v`", scorecard["action_path_count"]),
		fmt.Sprintf("- Executive rollup groups: `%v`", scorecard["executive_rollup_groups"]),
		fmt.Sprintf("- Markdown lines: `%v`", scorecard["markdown_lines"]),
		fmt.Sprintf("- Graph nodes: `%v`", scorecard["graph_nodes"]),
		fmt.Sprintf("- Proof records: `%v`", scorecard["proof_record_count"]),
		fmt.Sprintf("- Drift categories: `%v`", scorecard["drift_categories"]),
		fmt.Sprintf("- Scan duration ms: `%v`", scorecard["scan_duration_ms"]),
		fmt.Sprintf("- Report duration ms: `%v`", scorecard["report_duration_ms"]),
		"",
	}
	mdPath := filepath.Join(dir, "enterprise-pressure-scorecard.md")
	if err := os.WriteFile(mdPath, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		t.Fatalf("write enterprise scorecard md: %v", err)
	}
}

func arrayLength(value any) int {
	items, ok := value.([]any)
	if !ok {
		return 0
	}
	return len(items)
}

func objectInt(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	default:
		return 0
	}
}
