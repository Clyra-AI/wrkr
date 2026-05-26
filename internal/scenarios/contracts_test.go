package scenarios

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestScenarioContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRootWithoutTag(t)
	requiredPaths := []string{
		"scenarios/wrkr/scan-mixed-org/repos",
		"scenarios/wrkr/policy-check/repos",
		"scenarios/wrkr/mcp-gateway-posture/repos",
		"scenarios/wrkr/mcp-action-surface/repos",
		"scenarios/wrkr/a2a-agent-cards/repos",
		"scenarios/wrkr/non-human-identities/repos",
		"scenarios/wrkr/webmcp-declarations/repos",
		"scenarios/wrkr/prompt-channel-poisoning/repos",
		"scenarios/wrkr/extension-detectors/repos",
		"scenarios/wrkr/attack-path-correlation/repos",
		"scenarios/wrkr/mcp-enrich-supplychain/repos",
		"scenarios/wrkr/agent-relationship-correlation/repos",
		"scenarios/wrkr/agent-policy-outcomes/repos",
		"scenarios/wrkr/first-offer-noise-pack/repos",
		"scenarios/wrkr/first-offer-noise-pack/expected/standard-scan.json",
		"scenarios/wrkr/first-offer-noise-pack/expected/assessment-scan.json",
		"scenarios/wrkr/first-offer-mixed-governance/repos",
		"scenarios/wrkr/first-offer-mixed-governance/expected/assessment-report.json",
		"scenarios/wrkr/first-offer-duplicate-paths/action_path_fixture.json",
		"scenarios/wrkr/first-offer-duplicate-paths/expected/action-paths.json",
		"scenarios/wrkr/agent-action-bom-demo/before/repos",
		"scenarios/wrkr/agent-action-bom-demo/after/repos",
		"scenarios/wrkr/agent-action-bom-demo/after/runtime-evidence.json",
		"scenarios/wrkr/agent-action-bom-demo/expected/before-scan.json",
		"scenarios/wrkr/agent-action-bom-demo/expected/after-scan.json",
		"scenarios/wrkr/agent-action-bom-demo/expected/before-report.json",
		"scenarios/wrkr/agent-action-bom-demo/expected/after-report.json",
		"scenarios/wrkr/agent-action-bom-demo/expected/after-ingest.json",
		"scenarios/wrkr/agent-action-bom-demo/expected/after-evidence-report.json",
		"scenarios/wrkr/control-evidence-state/repos",
		"scenarios/wrkr/target-classification/repos",
		"scenarios/wrkr/buyer-action-registry-hardening/repos",
		"scenarios/wrkr/buyer-action-registry-hardening/expected/scan-summary.json",
		"scenarios/wrkr/buyer-action-registry-hardening/expected/report-internal-summary.json",
		"scenarios/wrkr/buyer-action-registry-hardening/expected/report-customer-redacted-summary.json",
		"scenarios/wrkr/buyer-action-registry-hardening/expected/design-partner-lines.txt",
		"scenarios/wrkr/buyer-action-registry-hardening/expected/evidence-design-partner-summary.json",
		"scenarios/cross-product/proof-record-interop/records-from-all-3.jsonl",
		"scenarios/cross-product/proof-record-interop/expected.yaml",
		"internal/scenarios/coverage_map.json",
	}
	for _, rel := range requiredPaths {
		if _, err := os.Stat(filepath.Join(repoRoot, rel)); err != nil {
			t.Fatalf("required scenario contract path missing %s: %v", rel, err)
		}
	}

	scenariosRoot := filepath.Join(repoRoot, "scenarios")
	if err := filepath.WalkDir(scenariosRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json":
			payload, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			if !json.Valid(payload) {
				t.Fatalf("invalid JSON fixture: %s", path)
			}
		case ".yaml", ".yml":
			payload, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			var value any
			if yamlErr := yaml.Unmarshal(payload, &value); yamlErr != nil {
				t.Fatalf("invalid YAML fixture %s: %v", path, yamlErr)
			}
		case ".jsonl":
			file, openErr := os.Open(path)
			if openErr != nil {
				return openErr
			}
			defer func() {
				_ = file.Close()
			}()
			scanner := bufio.NewScanner(file)
			line := 0
			for scanner.Scan() {
				line++
				trimmed := strings.TrimSpace(scanner.Text())
				if trimmed == "" {
					continue
				}
				if !json.Valid([]byte(trimmed)) {
					t.Fatalf("invalid JSONL fixture %s line %d", path, line)
				}
			}
			if err := scanner.Err(); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("walk scenarios fixtures: %v", err)
	}

	coveragePath := filepath.Join(repoRoot, "internal", "scenarios", "coverage_map.json")
	payload, err := os.ReadFile(coveragePath)
	if err != nil {
		t.Fatalf("read coverage map: %v", err)
	}
	coverage := map[string][]string{}
	if err := json.Unmarshal(payload, &coverage); err != nil {
		t.Fatalf("parse coverage map: %v", err)
	}

	requiredMappings := []string{"FR11", "FR12", "FR13", "FR14", "FR15", "AC10", "AC11", "AC15", "AC18", "AC19", "AC20", "AC21", "AC22", "AC23", "AC24", "AC25", "AC26", "AC27", "FO14-duplicate", "FO14-mixed-governance", "FO14-noise-pack", "FO15-usefulness", "W5-overclaim-qa"}
	testSymbols := coverageTestSymbols(t, repoRoot)
	for _, key := range requiredMappings {
		mapped, ok := coverage[key]
		if !ok || len(mapped) == 0 {
			t.Fatalf("coverage map missing non-empty mapping for %s", key)
		}
		for _, testName := range mapped {
			if _, exists := testSymbols[strings.TrimSpace(testName)]; !exists {
				t.Fatalf("coverage map for %s references unknown scenario test %q", key, testName)
			}
		}
	}

	checkSprint2ScenarioCoverageMap(t, repoRoot, coverage, testSymbols)
}

func TestSprint2ScenarioCoverageMap(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRootWithoutTag(t)
	coveragePath := filepath.Join(repoRoot, "internal", "scenarios", "coverage_map.json")
	payload, err := os.ReadFile(coveragePath)
	if err != nil {
		t.Fatalf("read coverage map: %v", err)
	}
	coverage := map[string][]string{}
	if err := json.Unmarshal(payload, &coverage); err != nil {
		t.Fatalf("parse coverage map: %v", err)
	}

	checkSprint2ScenarioCoverageMap(t, repoRoot, coverage, coverageTestSymbols(t, repoRoot))
}

func checkSprint2ScenarioCoverageMap(t *testing.T, repoRoot string, coverage map[string][]string, testSymbols map[string]struct{}) {
	t.Helper()

	requiredMappings := []string{
		"S2-11-external-evidence-ingest",
		"S2-12-source-precedence",
		"S2-13-freshness-and-expiry",
		"S2-14-control-declarations",
		"S2-15-contradiction-detection",
		"S2-16-accepted-risk-and-suppression",
		"S2-17-branch-and-deployment-constraints",
		"S2-18-closure-guidance",
		"S2-19-lifecycle-ownership-queue",
		"S2-20-evidence-completeness",
	}

	for _, key := range requiredMappings {
		mapped, ok := coverage[key]
		if !ok || len(mapped) == 0 {
			t.Fatalf("coverage map missing non-empty Sprint 2 mapping for %s", key)
		}
		for _, testName := range mapped {
			if _, exists := testSymbols[strings.TrimSpace(testName)]; !exists {
				t.Fatalf("Sprint 2 coverage map for %s references unknown test %q", key, testName)
			}
		}
	}
}

func coverageTestSymbols(t *testing.T, repoRoot string) map[string]struct{} {
	t.Helper()

	patterns := []string{
		filepath.Join(repoRoot, "internal", "scenarios", "*_test.go"),
		filepath.Join(repoRoot, "internal", "acceptance", "*_test.go"),
		filepath.Join(repoRoot, "testinfra", "contracts", "*_test.go"),
	}
	symbols := map[string]struct{}{}
	pattern := regexp.MustCompile(`func\s+(Test[A-Za-z0-9_]+)\s*\(`)
	for _, globPattern := range patterns {
		files, err := filepath.Glob(globPattern)
		if err != nil {
			t.Fatalf("glob test files for %s: %v", globPattern, err)
		}
		for _, file := range files {
			payload, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}
			for _, match := range pattern.FindAllStringSubmatch(string(payload), -1) {
				if len(match) == 2 {
					symbols[match[1]] = struct{}{}
				}
			}
		}
	}
	return symbols
}

func mustFindRepoRootWithoutTag(t *testing.T) string {
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
