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

	requiredMappings := []string{"FR11", "FR12", "FR13", "AC10", "AC11", "AC15", "AC18", "AC19", "AC20", "AC21"}
	testSymbols := scenarioTestSymbols(t, repoRoot)
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
}

func scenarioTestSymbols(t *testing.T, repoRoot string) map[string]struct{} {
	t.Helper()

	files, err := filepath.Glob(filepath.Join(repoRoot, "internal", "scenarios", "*_test.go"))
	if err != nil {
		t.Fatalf("glob scenario test files: %v", err)
	}
	pattern := regexp.MustCompile(`func\s+(TestScenario[A-Za-z0-9_]+)\s*\(`)
	symbols := map[string]struct{}{}
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
