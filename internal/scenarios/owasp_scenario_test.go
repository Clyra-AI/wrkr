//go:build scenario

package scenarios

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestScenarioOWASPPromptChannelAndAttackPaths(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "attack-path-correlation", "repos")
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	payload := runOWASPScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--json"})

	if _, ok := payload["top_attack_paths"].([]any); !ok {
		t.Fatalf("expected top_attack_paths array in payload, got %T", payload["top_attack_paths"])
	}
	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}
	foundPrompt := false
	foundRule16Violation := false
	for _, item := range findings {
		finding, _ := item.(map[string]any)
		if finding["finding_type"] == "prompt_channel_override" {
			foundPrompt = true
		}
		if finding["finding_type"] == "policy_violation" && finding["rule_id"] == "WRKR-016" {
			foundRule16Violation = true
		}
	}
	if !foundPrompt {
		t.Fatal("expected prompt channel finding in attack-path correlation scenario")
	}
	if !foundRule16Violation {
		t.Fatal("expected WRKR-016 policy_violation in attack-path correlation scenario")
	}
}

func TestScenarioOWASPMCPEnrichEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/advisory":
			_ = json.NewEncoder(w).Encode(map[string]any{"vulns": []any{map[string]any{"id": "GHSA-1"}}})
		case r.URL.Path == "/registry/v0/servers/%40scope%2Fserver":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Setenv("WRKR_MCP_ENRICH_ADVISORY_ENDPOINT", server.URL+"/advisory")
	t.Setenv("WRKR_MCP_ENRICH_REGISTRY_BASE", server.URL+"/registry")

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "mcp-enrich-supplychain", "repos")
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	payload := runOWASPScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--enrich", "--github-api", "https://api.github.com", "--json"})

	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}
	foundEnrichedMCP := false
	for _, item := range findings {
		finding, _ := item.(map[string]any)
		if finding["finding_type"] != "mcp_server" {
			continue
		}
		evidence, _ := finding["evidence"].([]any)
		keys := map[string]string{}
		for _, evItem := range evidence {
			ev, _ := evItem.(map[string]any)
			key, _ := ev["key"].(string)
			val, _ := ev["value"].(string)
			keys[key] = val
		}
		if keys["as_of"] != "" && keys["source"] != "" && keys["registry_status"] != "" && keys["enrich_quality"] != "" {
			foundEnrichedMCP = true
		}
	}
	if !foundEnrichedMCP {
		t.Fatal("expected enriched mcp_server evidence fields in enrich scenario")
	}
}

func runOWASPScenarioCommandJSON(t *testing.T, args []string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run(args, &out, &errOut); code != 0 {
		t.Fatalf("scenario command failed args=%v code=%d stderr=%s", args, code, errOut.String())
	}
	payload := map[string]any{}
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scenario payload: %v", err)
	}
	return payload
}
