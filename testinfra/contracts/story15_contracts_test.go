package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestStory15ScenarioPacksPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	requiredPaths := []string{
		"scenarios/wrkr/agent-relationship-correlation/repos",
		"scenarios/wrkr/agent-policy-outcomes/repos",
		"internal/scenarios/epic12_scenario_test.go",
		"internal/scenarios/coverage_map.json",
	}
	for _, rel := range requiredPaths {
		if _, err := os.Stat(filepath.Join(repoRoot, rel)); err != nil {
			t.Fatalf("missing Story 15 scenario path %s: %v", rel, err)
		}
	}
}

func TestStory15CoverageMapIncludesAgentWave3Mappings(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	coveragePath := filepath.Join(repoRoot, "internal", "scenarios", "coverage_map.json")
	payload, err := os.ReadFile(coveragePath)
	if err != nil {
		t.Fatalf("read coverage map: %v", err)
	}
	coverage := map[string][]string{}
	if err := json.Unmarshal(payload, &coverage); err != nil {
		t.Fatalf("parse coverage map: %v", err)
	}

	required := map[string][]string{
		"FR14": {"TestScenario_AgentRelationshipCorrelation"},
		"FR15": {"TestScenario_AgentPolicyOutcomes"},
		"AC26": {"TestScenario_AgentRelationshipCorrelation"},
		"AC27": {"TestScenario_AgentPolicyOutcomes"},
	}
	for key, expectedTests := range required {
		mapped := coverage[key]
		if len(mapped) == 0 {
			t.Fatalf("coverage map missing %s", key)
		}
		for _, testName := range expectedTests {
			if !slicesContains(mapped, testName) {
				t.Fatalf("coverage map for %s missing %q: %v", key, testName, mapped)
			}
		}
	}
}

func TestStory15AgentScenariosDeterministicOutput(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scenarios := []string{
		filepath.Join(repoRoot, "scenarios", "wrkr", "agent-relationship-correlation", "repos"),
		filepath.Join(repoRoot, "scenarios", "wrkr", "agent-policy-outcomes", "repos"),
	}

	for _, scanPath := range scenarios {
		first := runStory15ScanJSON(t, scanPath, filepath.Join(t.TempDir(), "state-first.json"))
		second := runStory15ScanJSON(t, scanPath, filepath.Join(t.TempDir(), "state-second.json"))

		firstNormalized := normalizeStory15Volatile(first)
		secondNormalized := normalizeStory15Volatile(second)
		if !reflect.DeepEqual(firstNormalized, secondNormalized) {
			t.Fatalf("non-deterministic scenario output for %s\nfirst=%v\nsecond=%v", scanPath, firstNormalized, secondNormalized)
		}

		for _, key := range []string{"findings", "ranked_findings", "inventory", "agent_privilege_map"} {
			if _, present := firstNormalized[key]; !present {
				t.Fatalf("scenario payload missing required key %q: %v", key, firstNormalized)
			}
		}
	}
}

func runStory15ScanJSON(t *testing.T, scanPath, statePath string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
	payload := map[string]any{}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output json: %v", err)
	}
	return payload
}

func normalizeStory15Volatile(in map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range in {
		switch key {
		case "generated_at":
			continue
		default:
			out[key] = normalizeStory15Any(value)
		}
	}
	return out
}

func normalizeStory15Any(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for key, val := range typed {
			lower := strings.ToLower(strings.TrimSpace(key))
			switch lower {
			case "generated_at", "scan_started_at", "scan_completed_at", "scan_duration_seconds":
				continue
			default:
				out[key] = normalizeStory15Any(val)
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, normalizeStory15Any(item))
		}
		return out
	default:
		return value
	}
}

func slicesContains(values []string, target string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}
