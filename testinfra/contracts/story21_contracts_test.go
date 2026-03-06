package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestRequiredChecks_EnforceWaveSequence1To2To3To4(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	payload, err := os.ReadFile(filepath.Join(repoRoot, ".github", "wave-gates.json"))
	if err != nil {
		t.Fatalf("read wave gates: %v", err)
	}

	var contract struct {
		MergeGates struct {
			RequiredPRChecks []string `json:"required_pr_checks"`
		} `json:"merge_gates"`
		Waves []struct {
			ID                  string   `json:"id"`
			Order               int      `json:"order"`
			Requires            string   `json:"requires"`
			Successor           string   `json:"successor"`
			RequiredLanes       []string `json:"required_lanes"`
			RequiredStoryChecks []string `json:"required_story_checks"`
		} `json:"waves"`
	}
	if err := json.Unmarshal(payload, &contract); err != nil {
		t.Fatalf("parse wave gates: %v", err)
	}

	if len(contract.Waves) != 4 {
		t.Fatalf("expected four waves, got %d", len(contract.Waves))
	}
	requiredLanes := []string{"acceptance", "core", "cross_platform", "fast", "risk"}
	for idx, wave := range contract.Waves {
		expectedID := "wave-" + string(rune('1'+idx))
		if wave.ID != expectedID {
			t.Fatalf("expected %s at index %d, got %s", expectedID, idx, wave.ID)
		}
		if wave.Order != idx+1 {
			t.Fatalf("expected %s order=%d, got %d", wave.ID, idx+1, wave.Order)
		}
		actualLanes := append([]string(nil), wave.RequiredLanes...)
		sort.Strings(actualLanes)
		if !reflect.DeepEqual(actualLanes, requiredLanes) {
			t.Fatalf("expected %s lanes %v, got %v", wave.ID, requiredLanes, wave.RequiredLanes)
		}
		if len(wave.RequiredStoryChecks) == 0 {
			t.Fatalf("expected required story checks for %s", wave.ID)
		}
		if idx == 0 {
			if wave.Requires != "" {
				t.Fatalf("wave-1 must not require a predecessor, got %q", wave.Requires)
			}
		} else if wave.Requires != contract.Waves[idx-1].ID {
			t.Fatalf("expected %s to require %s, got %q", wave.ID, contract.Waves[idx-1].ID, wave.Requires)
		}
		if idx < len(contract.Waves)-1 {
			if wave.Successor != contract.Waves[idx+1].ID {
				t.Fatalf("expected %s successor %s, got %q", wave.ID, contract.Waves[idx+1].ID, wave.Successor)
			}
		} else if wave.Successor != "" {
			t.Fatalf("final wave must not define successor, got %q", wave.Successor)
		}
	}

	requiredChecks := loadRequiredChecks(t, repoRoot)
	if !reflect.DeepEqual(contract.MergeGates.RequiredPRChecks, requiredChecks) {
		t.Fatalf("required PR checks must match branch protection contract: wave=%v required=%v", contract.MergeGates.RequiredPRChecks, requiredChecks)
	}
}

func TestScanContract_NoJSONOrExitRegressionAcrossWaves(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	inputPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-diff-no-noise", "input", "local-repos")

	firstPayload, firstCode := runStory21Scan(t, inputPath, filepath.Join(t.TempDir(), "first-state.json"))
	secondPayload, secondCode := runStory21Scan(t, inputPath, filepath.Join(t.TempDir(), "second-state.json"))
	if firstCode != 0 || secondCode != 0 {
		t.Fatalf("expected exit code 0 across repeated scan runs, got first=%d second=%d", firstCode, secondCode)
	}

	for _, payload := range []map[string]any{firstPayload, secondPayload} {
		for _, key := range []string{"findings", "inventory", "ranked_findings"} {
			if _, ok := payload[key]; !ok {
				t.Fatalf("scan payload missing %q: %v", key, payload)
			}
		}
	}

	if !reflect.DeepEqual(normalizeStory21Volatile(firstPayload), normalizeStory21Volatile(secondPayload)) {
		t.Fatalf("expected deterministic scan JSON across repeated runs\nfirst=%v\nsecond=%v", normalizeStory21Volatile(firstPayload), normalizeStory21Volatile(secondPayload))
	}
}

func runStory21Scan(t *testing.T, inputPath, statePath string) (map[string]any, int) {
	t.Helper()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"scan", "--path", inputPath, "--state", statePath, "--json", "--quiet"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
	payload := map[string]any{}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	return payload, code
}

func normalizeStory21Volatile(in map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range in {
		if strings.EqualFold(strings.TrimSpace(key), "generated_at") {
			continue
		}
		out[key] = normalizeStory21Any(value)
	}
	return out
}

func normalizeStory21Any(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := map[string]any{}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			lower := strings.ToLower(strings.TrimSpace(key))
			switch lower {
			case "generated_at", "scan_started_at", "scan_completed_at", "scan_duration_seconds":
				continue
			default:
				out[key] = normalizeStory21Any(typed[key])
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, normalizeStory21Any(item))
		}
		return out
	default:
		return value
	}
}
