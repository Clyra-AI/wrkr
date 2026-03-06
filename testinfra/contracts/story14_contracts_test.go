package contracts

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type benchmarkThresholds struct {
	MinimumPrecision    float64 `json:"minimum_precision"`
	MinimumRecall       float64 `json:"minimum_recall"`
	BaselineRecall      float64 `json:"baseline_recall"`
	MaxRecallRegression float64 `json:"max_recall_regression"`
}

type benchmarkMetrics struct {
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
}

func TestStory14AgentBenchmarkContractsPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	requiredPaths := []string{
		"scripts/run_agent_benchmarks.sh",
		"testinfra/benchmarks/agents/corpus.json",
		"testinfra/benchmarks/agents/thresholds.json",
		"schemas/v1/benchmarks/agent-benchmark.schema.json",
	}
	for _, rel := range requiredPaths {
		if _, err := os.Stat(filepath.Join(repoRoot, rel)); err != nil {
			t.Fatalf("missing benchmark contract path %s: %v", rel, err)
		}
	}
}

func TestAgentBenchmarkHarness_FailsPrecisionBelowThreshold(t *testing.T) {
	t.Parallel()

	thresholds := benchmarkThresholds{
		MinimumPrecision:    0.95,
		MinimumRecall:       0.70,
		BaselineRecall:      0.95,
		MaxRecallRegression: 0.03,
	}
	metrics := benchmarkMetrics{Precision: 0.90, Recall: 0.95}
	violations := evaluateBenchmarkThresholds(metrics, thresholds)
	if len(violations) == 0 {
		t.Fatal("expected precision violation")
	}
	if !containsSubstring(violations, "precision") {
		t.Fatalf("expected precision violation detail, got %v", violations)
	}
}

func TestAgentBenchmarkHarness_FailsRecallRegressionBudget(t *testing.T) {
	t.Parallel()

	thresholds := benchmarkThresholds{
		MinimumPrecision:    0.95,
		MinimumRecall:       0.70,
		BaselineRecall:      0.95,
		MaxRecallRegression: 0.03,
	}
	metrics := benchmarkMetrics{Precision: 0.99, Recall: 0.90}
	violations := evaluateBenchmarkThresholds(metrics, thresholds)
	if len(violations) == 0 {
		t.Fatal("expected recall regression violation")
	}
	if !containsSubstring(violations, "regression floor") {
		t.Fatalf("expected recall regression floor violation detail, got %v", violations)
	}
}

func TestAgentBenchmarkRunner_JsonSchemaAndDeterminism(t *testing.T) {
	repoRoot := mustFindRepoRoot(t)
	firstPath := filepath.Join(t.TempDir(), "agent-bench-first.json")
	secondPath := filepath.Join(t.TempDir(), "agent-bench-second.json")

	first := runAgentBenchmarkJSON(t, repoRoot, firstPath)
	second := runAgentBenchmarkJSON(t, repoRoot, secondPath)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("benchmark output must be deterministic across runs\nfirst=%v\nsecond=%v", first, second)
	}

	if first["version"] != "v1" {
		t.Fatalf("expected version=v1, got %v", first["version"])
	}
	status, _ := first["status"].(string)
	if status != "pass" {
		t.Fatalf("expected benchmark status pass, got %q (%v)", status, first["violations"])
	}

	metrics, ok := first["metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected metrics object, got %T", first["metrics"])
	}
	if _, ok := metrics["precision"]; !ok {
		t.Fatalf("metrics missing precision: %v", metrics)
	}
	if _, ok := metrics["recall"]; !ok {
		t.Fatalf("metrics missing recall: %v", metrics)
	}

	cases, ok := first["cases"].([]any)
	if !ok || len(cases) == 0 {
		t.Fatalf("expected non-empty cases list, got %T", first["cases"])
	}
	for _, item := range cases {
		entry, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("unexpected case payload type %T", item)
		}
		for _, key := range []string{"id", "kind", "path", "expected_detectors", "matched_detectors", "outcome"} {
			if _, present := entry[key]; !present {
				t.Fatalf("case payload missing key %q: %v", key, entry)
			}
		}
	}
}

func evaluateBenchmarkThresholds(metrics benchmarkMetrics, thresholds benchmarkThresholds) []string {
	violations := make([]string, 0)
	if metrics.Precision < thresholds.MinimumPrecision {
		violations = append(violations, "precision below minimum threshold")
	}
	if metrics.Recall < thresholds.MinimumRecall {
		violations = append(violations, "recall below minimum threshold")
	}
	recallFloor := thresholds.BaselineRecall - thresholds.MaxRecallRegression
	if metrics.Recall < recallFloor {
		violations = append(violations, "recall below regression floor")
	}
	return violations
}

func runAgentBenchmarkJSON(t *testing.T, repoRoot string, outputPath string) map[string]any {
	t.Helper()

	cmd := exec.Command("bash", "scripts/run_agent_benchmarks.sh", "--json", "--output", outputPath)
	cmd.Dir = repoRoot
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run agent benchmark: %v\noutput=%s", err, string(output))
	}

	payload, readErr := os.ReadFile(outputPath)
	if readErr != nil {
		t.Fatalf("read benchmark output %s: %v", outputPath, readErr)
	}
	parsed := map[string]any{}
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("parse benchmark output json: %v", err)
	}
	return parsed
}

func containsSubstring(values []string, token string) bool {
	for _, item := range values {
		if strings.Contains(item, token) {
			return true
		}
	}
	return false
}
