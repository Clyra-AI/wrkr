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

func TestScenarioEpic10DiscoveryMethodAC22(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")

	payload := runEpic10ScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})
	findings, ok := payload["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["discovery_method"] != "static" {
			t.Fatalf("expected finding discovery_method=static, got %v", finding)
		}
	}
	inventory, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory payload, got %T", payload["inventory"])
	}
	tools, ok := inventory["tools"].([]any)
	if !ok {
		t.Fatalf("expected tools array, got %T", inventory["tools"])
	}
	for _, item := range tools {
		tool, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if tool["discovery_method"] != "static" {
			t.Fatalf("expected inventory tool discovery_method=static, got %v", tool)
		}
	}

	legacyPath := filepath.Join(tmp, "legacy-baseline.json")
	writeLegacyStateWithoutDiscoveryMethod(t, statePath, legacyPath)
	legacyStatePath := filepath.Join(tmp, "legacy-state.json")
	legacyPayload := runEpic10ScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", legacyStatePath, "--baseline", legacyPath, "--diff", "--json"})
	diffObj, ok := legacyPayload["diff"].(map[string]any)
	if !ok {
		t.Fatalf("expected diff object, got %T", legacyPayload["diff"])
	}
	for _, key := range []string{"added", "removed", "changed"} {
		entries, _ := diffObj[key].([]any)
		if len(entries) != 0 {
			t.Fatalf("expected no diff entries for legacy baseline compatibility key=%s got=%v", key, entries)
		}
	}
}

func TestScenarioEpic10MCPGatewayPostureAC23(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "mcp-gateway-posture", "repos")
	payload := runEpic10ScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})

	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}

	coverageByRepo := map[string]string{}
	hasParseError := false
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["finding_type"] == "parse_error" {
			hasParseError = true
			continue
		}
		if finding["finding_type"] != "mcp_gateway_posture" {
			continue
		}
		repo, _ := finding["repo"].(string)
		evidence, _ := finding["evidence"].([]any)
		for _, record := range evidence {
			entry, ok := record.(map[string]any)
			if !ok || entry["key"] != "coverage" {
				continue
			}
			coverageByRepo[repo], _ = entry["value"].(string)
		}
	}

	for repo, wantCoverage := range map[string]string{"protected-repo": "protected", "unprotected-repo": "unprotected", "unknown-repo": "unknown", "ambiguous-repo": "unknown"} {
		if got := coverageByRepo[repo]; got != wantCoverage {
			t.Fatalf("unexpected coverage for %s: got %q want %q", repo, got, wantCoverage)
		}
	}
	if !hasParseError {
		t.Fatal("expected parse_error finding for ambiguous-repo gateway config")
	}
}

func TestScenarioEpic10A2ADiscoveryAC24(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "a2a-agent-cards", "repos")
	payload := runEpic10ScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})
	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}

	a2aCount := 0
	hasSchemaError := false
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		switch finding["finding_type"] {
		case "a2a_agent_card":
			a2aCount++
			evidence, _ := finding["evidence"].([]any)
			assertEvidenceKeys(t, evidence, []string{"capabilities", "auth_schemes", "protocols"})
		case "parse_error":
			parseError, _ := finding["parse_error"].(map[string]any)
			if parseError["kind"] == "schema_validation_error" {
				hasSchemaError = true
			}
		}
	}
	if a2aCount < 2 {
		t.Fatalf("expected at least two valid a2a_agent_card findings, got %d", a2aCount)
	}
	if !hasSchemaError {
		t.Fatal("expected schema_validation_error parse_error finding for invalid A2A cards")
	}
}

func TestScenarioEpic10WebMCPStaticDetectionAC25(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "webmcp-declarations", "repos")
	payload := runEpic10ScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "state.json"), "--json"})
	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}

	methods := map[string]bool{}
	hasParseError := false
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["finding_type"] == "parse_error" {
			hasParseError = true
			continue
		}
		if finding["finding_type"] != "webmcp_declaration" {
			continue
		}
		location, _ := finding["location"].(string)
		if len(location) >= 4 && (location[:4] == "http" || location[:4] == "HTTP") {
			t.Fatalf("expected static local locations only, got %q", location)
		}
		evidence, _ := finding["evidence"].([]any)
		for _, record := range evidence {
			entry, ok := record.(map[string]any)
			if !ok {
				continue
			}
			if entry["key"] == "declaration_method" {
				method, _ := entry["value"].(string)
				methods[method] = true
			}
			if entry["key"] == "live_probe" || entry["key"] == "http_probe" {
				t.Fatalf("unexpected live probing evidence key in static detection mode: %v", entry)
			}
		}
	}

	for _, required := range []string{"declarative_html", "imperative_js", "route_file", "route_declaration"} {
		if !methods[required] {
			t.Fatalf("expected declaration method %q in webmcp findings, got %v", required, methods)
		}
	}
	if !hasParseError {
		t.Fatal("expected parse_error finding for malformed JavaScript fixture")
	}
}

func runEpic10ScenarioCommandJSON(t *testing.T, args []string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run(args, &out, &errOut); code != 0 {
		t.Fatalf("scenario command failed: args=%v code=%d stderr=%s", args, code, errOut.String())
	}
	payload := map[string]any{}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scenario payload: %v", err)
	}
	return payload
}

func writeLegacyStateWithoutDiscoveryMethod(t *testing.T, sourcePath, outputPath string) {
	t.Helper()
	payload, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	stateDoc := map[string]any{}
	if err := json.Unmarshal(payload, &stateDoc); err != nil {
		t.Fatalf("parse state: %v", err)
	}
	findings, _ := stateDoc["findings"].([]any)
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		delete(finding, "discovery_method")
	}
	updated, err := json.MarshalIndent(stateDoc, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy state: %v", err)
	}
	updated = append(updated, '\n')
	if err := os.WriteFile(outputPath, updated, 0o600); err != nil {
		t.Fatalf("write legacy state: %v", err)
	}
}

func assertEvidenceKeys(t *testing.T, evidence []any, required []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, item := range evidence {
		record, ok := item.(map[string]any)
		if !ok {
			continue
		}
		key, _ := record["key"].(string)
		if key != "" {
			seen[key] = true
		}
	}
	for _, key := range required {
		if !seen[key] {
			t.Fatalf("missing required evidence key %q in %v", key, evidence)
		}
	}
}
