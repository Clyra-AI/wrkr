//go:build scenario

package scenarios

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/internal/enterprisepressure"
)

const scanAnalysisReliabilityRepoCount = 384
const scanAnalysisReliabilityMaxDuration = 45 * time.Second

func TestScenarioScanAnalysisReliabilityAtEnterpriseScale(t *testing.T) {
	tmp := t.TempDir()
	reposRoot := filepath.Join(tmp, "repos")
	if err := enterprisepressure.MaterializeEndpointDense(
		reposRoot,
		scanAnalysisReliabilityRepoCount,
		enterprisepressure.DefaultDenseOpenAPIOperations,
	); err != nil {
		t.Fatalf("materialize enterprise reliability fixture: %v", err)
	}

	firstStarted := time.Now()
	first := runScenarioCommandJSONRaw(t, []string{
		"scan", "--path", reposRoot, "--state", filepath.Join(tmp, "first-state.json"), "--quiet", "--json",
	})
	if elapsed := time.Since(firstStarted); elapsed > scanAnalysisReliabilityMaxDuration {
		t.Fatalf("first enterprise-scale scan took %s, want <= %s", elapsed.Round(time.Millisecond), scanAnalysisReliabilityMaxDuration)
	}

	secondStarted := time.Now()
	second := runScenarioCommandJSONRaw(t, []string{
		"scan", "--path", reposRoot, "--state", filepath.Join(tmp, "second-state.json"), "--quiet", "--json",
	})
	if elapsed := time.Since(secondStarted); elapsed > scanAnalysisReliabilityMaxDuration {
		t.Fatalf("second enterprise-scale scan took %s, want <= %s", elapsed.Round(time.Millisecond), scanAnalysisReliabilityMaxDuration)
	}

	assertEnterpriseReliabilityShape(t, first)
	if !bytes.Equal(scanAnalysisReliabilityFingerprint(t, first), scanAnalysisReliabilityFingerprint(t, second)) {
		t.Fatal("enterprise-scale scan output changed between identical fixture runs")
	}
}

func assertEnterpriseReliabilityShape(t *testing.T, payload map[string]any) {
	t.Helper()
	manifest := requireScenarioObject(t, payload, "source_manifest")
	repos := requireScenarioArrayFromObject(t, manifest, "repos")
	if got := len(repos); got != scanAnalysisReliabilityRepoCount {
		t.Fatalf("fixture repositories = %d, want %d", got, scanAnalysisReliabilityRepoCount)
	}
	if paths := requireScenarioArrayFromObject(t, payload, "action_paths"); len(paths) == 0 {
		t.Fatal("expected workflow and endpoint fixture to produce action paths")
	}
	if compositions := requireScenarioArrayFromObject(t, payload, "composed_action_paths"); len(compositions) == 0 {
		t.Fatal("expected workflow and endpoint fixture to produce composed action paths")
	}
}

func scanAnalysisReliabilityFingerprint(t *testing.T, payload map[string]any) []byte {
	t.Helper()
	stable := map[string]any{
		"action_path_summary":                   payload["action_path_summary"],
		"action_path_to_control_first":          payload["action_path_to_control_first"],
		"action_paths":                          payload["action_paths"],
		"composed_action_path_to_control_first": payload["composed_action_path_to_control_first"],
		"composed_action_paths":                 payload["composed_action_paths"],
		"finding_counts":                        payload["finding_counts"],
		"source_manifest":                       payload["source_manifest"],
	}
	encoded, err := json.Marshal(stable)
	if err != nil {
		t.Fatalf("marshal stable enterprise scan output: %v", err)
	}
	return encoded
}
