//go:build scenario

package scenarios

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestScenarioScanMixedOrgCoverage(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"scan", "--path", scanPath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed with code %d: %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}

	seenTools := map[string]bool{}
	seenCompiled := false
	for _, item := range findings {
		finding, castOK := item.(map[string]any)
		if !castOK {
			continue
		}
		if tool, hasTool := finding["tool_type"].(string); hasTool {
			seenTools[tool] = true
		}
		if findingType, hasType := finding["finding_type"].(string); hasType && findingType == "compiled_action" {
			seenCompiled = true
		}
	}

	for _, required := range []string{"claude", "cursor", "codex", "copilot"} {
		if !seenTools[required] {
			t.Fatalf("expected %s detector coverage in scenario findings", required)
		}
	}
	if !seenCompiled {
		t.Fatal("expected compiled_action finding in mixed-org scenario")
	}

	topFindings, ok := payload["top_findings"].([]any)
	if !ok || len(topFindings) == 0 {
		t.Fatalf("expected top_findings array, got %v", payload["top_findings"])
	}
	top, ok := topFindings[0].(map[string]any)
	if !ok {
		t.Fatalf("invalid top finding shape: %T", topFindings[0])
	}
	findingPayload, ok := top["finding"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested finding payload, got %T", top["finding"])
	}
	if severity, _ := findingPayload["severity"].(string); severity != "critical" {
		t.Fatalf("expected critical finding ranked first, got severity=%q", severity)
	}
}

func TestScenarioPolicyCheckContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"scan", "--path", scanPath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed with code %d: %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}

	ruleResults := map[string]string{}
	for _, item := range findings {
		finding, castOK := item.(map[string]any)
		if !castOK {
			continue
		}
		findingType, _ := finding["finding_type"].(string)
		ruleID, _ := finding["rule_id"].(string)
		checkResult, _ := finding["check_result"].(string)
		if findingType == "policy_check" && ruleID != "" {
			ruleResults[ruleID] = checkResult
		}
	}

	expectations := map[string]string{
		"WRKR-001": "fail",
		"WRKR-002": "fail",
		"WRKR-004": "pass",
		"WRKR-099": "fail",
	}
	for ruleID, want := range expectations {
		if got := ruleResults[ruleID]; got != want {
			t.Fatalf("unexpected %s result: got %q want %q", ruleID, got, want)
		}
	}
}

func mustFindRepoRoot(t *testing.T) string {
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
			t.Fatal("could not find repo root")
		}
		wd = next
	}
}
