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
	"regexp"
	"sort"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/cli"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
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
		"control_backlog",
		"findings",
		"inventory",
		"posture_score",
		"privilege_budget",
		"profile",
		"ranked_findings",
		"repo_exposure_summaries",
		"scan_mode",
		"scan_quality",
		"source_manifest",
		"status",
		"target",
		"top_attack_paths",
		"top_findings",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected top-level keys: got %v want %v", got, want)
	}
	if payload["scan_mode"] != "governance" {
		t.Fatalf("expected default scan_mode=governance, got %v", payload["scan_mode"])
	}
	controlBacklog, ok := payload["control_backlog"].(map[string]any)
	if !ok {
		t.Fatalf("expected control_backlog object, got %T", payload["control_backlog"])
	}
	if controlBacklog["control_backlog_version"] != "1" {
		t.Fatalf("unexpected control_backlog_version: %v", controlBacklog["control_backlog_version"])
	}
	scanQuality, ok := payload["scan_quality"].(map[string]any)
	if !ok {
		t.Fatalf("expected scan_quality object, got %T", payload["scan_quality"])
	}
	if scanQuality["scan_quality_version"] != "1" {
		t.Fatalf("unexpected scan_quality_version: %v", scanQuality["scan_quality_version"])
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
	want := []string{"diff", "diff_empty", "scan_mode", "scan_quality", "source_manifest", "status", "target"}
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

func TestActionPathsRemainUniqueForFrozenAgentEcosystemSubset(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	payload, err := os.ReadFile(filepath.Join(repoRoot, "scenarios", "wrkr", "first-offer-agent-ecosystem-subset", "action_path_fixture.json"))
	if err != nil {
		t.Fatalf("read action-path fixture: %v", err)
	}

	var fixture struct {
		AttackPaths []riskattack.ScoredPath `json:"attack_paths"`
		Inventory   agginventory.Inventory  `json:"inventory"`
	}
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatalf("parse action-path fixture: %v", err)
	}

	paths, choice := risk.BuildActionPaths(fixture.AttackPaths, &fixture.Inventory)
	if len(paths) != 2 {
		t.Fatalf("expected frozen subset fixture to collapse to 2 action paths, got %+v", paths)
	}
	if choice == nil {
		t.Fatal("expected action_path_to_control_first output for frozen subset fixture")
	}

	seen := map[string]struct{}{}
	for _, path := range paths {
		if _, ok := seen[path.PathID]; ok {
			t.Fatalf("expected unique path_id values, got duplicate %s in %+v", path.PathID, paths)
		}
		if !regexp.MustCompile(`^apc-[0-9a-f]{12}$`).MatchString(path.PathID) {
			t.Fatalf("expected opaque deterministic path_id format apc-<hex>, got %q", path.PathID)
		}
		seen[path.PathID] = struct{}{}
	}
	if choice.Path.PathID != paths[0].PathID {
		t.Fatalf("expected control-first path to reference sorted action_paths row, choice=%+v paths=%+v", choice.Path, paths)
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
