package contracts

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestConfigSchemaPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	schemaPath := filepath.Join(repoRoot, "schemas", "v1", "config", "config.schema.json")
	if _, err := os.Stat(schemaPath); err != nil {
		t.Fatalf("expected config schema at %s: %v", schemaPath, err)
	}
}

func TestScanJSONContractStableKeys(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/backend":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/backend"}`)
			return
		case "/repos/acme/backend/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[{"path":"AGENTS.md","type":"blob","sha":"blob-1"}]}`)
			return
		case "/repos/acme/backend/git/blobs/blob-1":
			blob := base64.StdEncoding.EncodeToString([]byte("# agents\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, blob)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"scan", "--repo", "acme/backend", "--github-api", server.URL, "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	got := sortedKeys(payload)
	want := []string{
		"action_path_to_control_first",
		"action_paths",
		"agent_privilege_map",
		"attack_paths",
		"compliance_summary",
		"findings",
		"inventory",
		"posture_score",
		"privilege_budget",
		"profile",
		"ranked_findings",
		"repo_exposure_summaries",
		"source_manifest",
		"status",
		"target",
		"top_attack_paths",
		"top_findings",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected top-level keys: got %v want %v", got, want)
	}

	inventoryPayload, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory object in payload, got %T", payload["inventory"])
	}
	if _, present := inventoryPayload["agents"]; !present {
		t.Fatalf("expected additive inventory.agents key, got %v", inventoryPayload)
	}
	if _, ok := inventoryPayload["agents"].([]any); !ok {
		t.Fatalf("expected inventory.agents array, got %T", inventoryPayload["agents"])
	}

	complianceSummary, ok := payload["compliance_summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected compliance_summary object in payload, got %T", payload["compliance_summary"])
	}
	if _, ok := complianceSummary["frameworks"].([]any); !ok {
		t.Fatalf("expected compliance_summary.frameworks array, got %T", complianceSummary["frameworks"])
	}
}

func TestDiffJSONContractStableKeys(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	statePath := filepath.Join(tmp, "state.json")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir alpha: %v", err)
	}

	var firstOut bytes.Buffer
	var firstErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &firstOut, &firstErr); code != 0 {
		t.Fatalf("first scan failed: %d (%s)", code, firstErr.String())
	}

	var diffOut bytes.Buffer
	var diffErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--diff", "--json"}, &diffOut, &diffErr); code != 0 {
		t.Fatalf("diff scan failed: %d (%s)", code, diffErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(diffOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse diff payload: %v", err)
	}
	got := sortedKeys(payload)
	want := []string{"diff", "diff_empty", "source_manifest", "status", "target"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected top-level keys: got %v want %v", got, want)
	}
}

func TestInvalidInputEnvelopeContract(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"scan", "--repo", "acme/backend", "--org", "acme", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}

	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object: %v", payload)
	}
	if errObj["code"] != "invalid_input" {
		t.Fatalf("unexpected error code: %v", errObj["code"])
	}
	if errObj["exit_code"] != float64(6) {
		t.Fatalf("unexpected error exit envelope: %v", errObj["exit_code"])
	}
}

func sortedKeys(in map[string]any) []string {
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
