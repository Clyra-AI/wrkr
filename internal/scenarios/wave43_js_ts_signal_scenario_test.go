//go:build scenario

package scenarios

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

type jsTSEnterpriseReceipt struct {
	ExpectedCoverageConfidence string              `json:"expected_coverage_confidence"`
	ParseFailureCeiling        int                 `json:"parse_failure_ceiling"`
	ExpectedParseDetectors     []string            `json:"expected_parse_detectors"`
	ExpectedGeneratedPaths     []string            `json:"expected_generated_paths"`
	ExpectedNonGeneratedPaths  []string            `json:"expected_non_generated_paths"`
	ExpectedExtensionsPresent  []string            `json:"expected_extensions_present"`
	ExpectedFindingTypesByRepo map[string][]string `json:"expected_finding_types_by_repo"`
	ExpectedCleanRepos         []string            `json:"expected_clean_repos"`
}

func TestScenarioWave43JSTSSignalReceipts(t *testing.T) {
	repoRoot := mustFindRepoRoot(t)
	scenarioRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "js-ts-enterprise")
	reposRoot := filepath.Join(scenarioRoot, "repos")
	receipt := loadJSTSEnterpriseReceipt(t, filepath.Join(scenarioRoot, "expected", "receipt.json"))

	extensionsPresent, pathClassification := collectJSTSEnterpriseFixtureStats(t, reposRoot)
	if strings.Join(extensionsPresent, ",") != strings.Join(receipt.ExpectedExtensionsPresent, ",") {
		t.Fatalf("unexpected JS-family extension set: got %v want %v", extensionsPresent, receipt.ExpectedExtensionsPresent)
	}
	for _, rel := range receipt.ExpectedGeneratedPaths {
		got, ok := pathClassification[rel]
		if !ok {
			t.Fatalf("expected generated fixture path %q to exist in JS/TS enterprise receipt", rel)
		}
		if !got {
			t.Fatalf("expected generated fixture path %q to stay classified as generated", rel)
		}
	}
	for _, rel := range receipt.ExpectedNonGeneratedPaths {
		got, ok := pathClassification[rel]
		if !ok {
			t.Fatalf("expected non-generated fixture path %q to exist in JS/TS enterprise receipt", rel)
		}
		if got {
			t.Fatalf("expected non-generated fixture path %q to stay classified as source", rel)
		}
	}

	statePath := filepath.Join(t.TempDir(), "state.json")
	payload := runScenarioCommandJSON(t, []string{"scan", "--path", reposRoot, "--state", statePath, "--quiet", "--json"})

	scanQuality := requireScenarioObject(t, payload, "scan_quality")
	compact := requireScenarioObject(t, scanQuality, "compact_summary")
	if compact["coverage_confidence"] != receipt.ExpectedCoverageConfidence {
		t.Fatalf("expected coverage confidence %q, got %v", receipt.ExpectedCoverageConfidence, compact["coverage_confidence"])
	}
	parseFailureCount, ok := compact["parse_failure_count"].(float64)
	if !ok {
		t.Fatalf("expected parse_failure_count number, got %T", compact["parse_failure_count"])
	}
	if int(parseFailureCount) > receipt.ParseFailureCeiling {
		t.Fatalf("expected parse failure ceiling %d, got %d", receipt.ParseFailureCeiling, int(parseFailureCount))
	}

	parseIssues := requireScenarioArrayFromObject(t, scanQuality, "parse_errors")
	detectors := make([]string, 0, len(parseIssues))
	for _, raw := range parseIssues {
		issue := requireScenarioMap(t, raw)
		if detectorName, ok := issue["detector"].(string); ok && strings.TrimSpace(detectorName) != "" {
			detectors = append(detectors, strings.TrimSpace(detectorName))
		}
	}
	sort.Strings(detectors)
	detectors = uniqueStrings(detectors)
	if strings.Join(detectors, ",") != strings.Join(receipt.ExpectedParseDetectors, ",") {
		t.Fatalf("unexpected parse-error detectors: got %v want %v", detectors, receipt.ExpectedParseDetectors)
	}

	topFindings := requireArray(t, payload, "top_findings")
	for _, raw := range topFindings {
		finding := requireObjectItem(t, raw)
		if finding["finding_type"] == "parse_error" {
			t.Fatalf("expected parse diagnostics to stay out of ranked top findings, got %v", topFindings)
		}
	}

	findings := requireArray(t, payload, "findings")
	findingsByRepo := map[string]map[string]struct{}{}
	wave3FindingTypes := map[string]struct{}{
		"agent_framework":                  {},
		"mcp_server_candidate":             {},
		"prompt_channel_hidden_text":       {},
		"prompt_channel_override":          {},
		"prompt_channel_semantic":          {},
		"prompt_channel_untrusted_context": {},
		"webmcp_declaration":               {},
	}
	for _, raw := range findings {
		finding := requireObjectItem(t, raw)
		repo, _ := finding["repo"].(string)
		findingType, _ := finding["finding_type"].(string)
		if repo == "" || findingType == "" {
			continue
		}
		if _, ok := findingsByRepo[repo]; !ok {
			findingsByRepo[repo] = map[string]struct{}{}
		}
		findingsByRepo[repo][findingType] = struct{}{}
	}

	for repo, expectedTypes := range receipt.ExpectedFindingTypesByRepo {
		for _, expectedType := range expectedTypes {
			if _, ok := findingsByRepo[repo][expectedType]; !ok {
				t.Fatalf("expected finding type %q for repo %q, got %v", expectedType, repo, findingsByRepo[repo])
			}
		}
	}
	for _, repo := range receipt.ExpectedCleanRepos {
		for findingType := range findingsByRepo[repo] {
			if _, ok := wave3FindingTypes[findingType]; ok {
				t.Fatalf("expected clean repo %q to stay free of Wave 3 detector findings, got %v", repo, findingsByRepo[repo])
			}
		}
	}

	routeDetected := false
	actionPaths := requireArray(t, payload, "action_paths")
	for _, raw := range actionPaths {
		actionPath := requireObjectItem(t, raw)
		if actionPath["repo"] == "parse-edge-repo" && actionPath["location"] == "server/register.mjs" {
			t.Fatalf("expected parse-limited JS surface to stay out of action paths, got %v", actionPaths)
		}
	}
	for _, raw := range findings {
		finding := requireObjectItem(t, raw)
		if finding["repo"] != "route-repo" || finding["finding_type"] != "webmcp_declaration" {
			continue
		}
		evidence, _ := finding["evidence"].([]any)
		for _, item := range evidence {
			ev := requireObjectItem(t, item)
			if ev["key"] == "declaration_method" && ev["value"] == "route_declaration" {
				routeDetected = true
				break
			}
		}
	}
	if !routeDetected {
		t.Fatalf("expected TypeScript route fixture to keep route_declaration evidence, got %v", findingsByRepo["route-repo"])
	}
}

func loadJSTSEnterpriseReceipt(t *testing.T, path string) jsTSEnterpriseReceipt {
	t.Helper()

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read JS/TS enterprise receipt: %v", err)
	}
	var receipt jsTSEnterpriseReceipt
	if err := json.Unmarshal(payload, &receipt); err != nil {
		t.Fatalf("parse JS/TS enterprise receipt: %v", err)
	}
	sort.Strings(receipt.ExpectedParseDetectors)
	return receipt
}

func collectJSTSEnterpriseFixtureStats(t *testing.T, root string) ([]string, map[string]bool) {
	t.Helper()

	extensionsPresent := map[string]struct{}{}
	pathClassification := map[string]bool{}
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		rel = filepath.ToSlash(rel)
		ext := strings.ToLower(filepath.Ext(rel))
		switch ext {
		case ".js", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts":
		default:
			return nil
		}
		extensionsPresent[ext] = struct{}{}
		pathClassification[rel] = detect.IsGeneratedPath(rel)
		return nil
	}); err != nil {
		t.Fatalf("walk JS/TS enterprise fixture: %v", err)
	}
	out := make([]string, 0, len(extensionsPresent))
	for ext := range extensionsPresent {
		out = append(out, ext)
	}
	sort.Strings(out)
	return out, pathClassification
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		set[value] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
