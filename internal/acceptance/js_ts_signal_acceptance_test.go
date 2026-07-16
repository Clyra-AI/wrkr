package acceptance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type jsTSEnterpriseAcceptanceReceipt struct {
	ParseFailureCeiling int `json:"parse_failure_ceiling"`
}

func TestScanQualityParserHonestyOnJSEnterpriseFixture(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scenarioRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "js-ts-enterprise")
	scanRoot := filepath.Join(scenarioRoot, "repos")
	receipt := loadJSTSEnterpriseAcceptanceReceipt(t, filepath.Join(scenarioRoot, "expected", "receipt.json"))

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "last-scan.json")
	mdPath := filepath.Join(tmp, "scan-quality.md")

	scanPayload := runJSONOK(t, "scan", "--path", scanRoot, "--state", statePath, "--quiet", "--json")
	scanQuality := requireObject(t, scanPayload, "scan_quality")
	compact := requireObject(t, scanQuality, "compact_summary")
	if compact["coverage_confidence"] != "reduced" {
		t.Fatalf("expected reduced coverage confidence, got %v", compact)
	}
	parseFailures, ok := compact["parse_failure_count"].(float64)
	if !ok {
		t.Fatalf("expected parse_failure_count number, got %T", compact["parse_failure_count"])
	}
	if int(parseFailures) > receipt.ParseFailureCeiling {
		t.Fatalf("expected parse failure ceiling %d, got %d", receipt.ParseFailureCeiling, int(parseFailures))
	}

	topFindings, ok := scanPayload["top_findings"].([]any)
	if !ok {
		t.Fatalf("expected top_findings array, got %T", scanPayload["top_findings"])
	}
	for _, raw := range topFindings {
		finding := requireObjectItem(t, raw)
		if finding["finding_type"] == "parse_error" {
			t.Fatalf("expected parse diagnostics to stay out of ranked top findings, got %v", topFindings)
		}
	}
	findings := requireArray(t, scanPayload, "findings")
	for _, raw := range findings {
		finding := requireObjectItem(t, raw)
		if finding["finding_type"] == "parse_error" {
			t.Fatalf("expected JS/TS parse diagnostics to stay out of scan findings, got %v", findings)
		}
	}
	actionPaths := requireArray(t, scanPayload, "action_paths")
	for _, raw := range actionPaths {
		actionPath := requireObjectItem(t, raw)
		if actionPath["repo"] == "parse-edge-repo" && actionPath["location"] == "server/register.mjs" {
			t.Fatalf("expected parse-limited JS surface to stay out of action paths, got %v", actionPaths)
		}
	}

	runJSONOK(
		t,
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--share-profile", "customer-redacted",
		"--md", "--md-path", mdPath,
		"--json",
	)
	markdownBytes, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read report markdown: %v", err)
	}
	markdown := string(markdownBytes)
	if !strings.Contains(markdown, "Coverage confidence: reduced") && !strings.Contains(markdown, "coverage_confidence=reduced") {
		t.Fatalf("expected report markdown to surface reduced coverage confidence, got %q", string(markdownBytes))
	}
}

func loadJSTSEnterpriseAcceptanceReceipt(t *testing.T, path string) jsTSEnterpriseAcceptanceReceipt {
	t.Helper()

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read JS/TS enterprise acceptance receipt: %v", err)
	}
	var receipt jsTSEnterpriseAcceptanceReceipt
	if err := json.Unmarshal(payload, &receipt); err != nil {
		t.Fatalf("parse JS/TS enterprise acceptance receipt: %v", err)
	}
	return receipt
}
