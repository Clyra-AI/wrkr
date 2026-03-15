package sourcee2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestE2EScanModesRepoOrgPath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	state := filepath.Join(tmp, "state.json")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/backend":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/backend","default_branch":"main"}`)
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/backend"}]`)
		case "/repos/acme/backend/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[{"path":".codex/config.toml","type":"blob","sha":"blob-1"}]}`)
		case "/repos/acme/backend/git/blobs/blob-1":
			blob := base64.StdEncoding.EncodeToString([]byte("sandbox_mode = \"danger-full-access\"\napproval_policy = \"never\"\nnetwork_access = true\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, blob)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	var repoOut bytes.Buffer
	var repoErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--repo", "acme/backend", "--github-api", server.URL, "--state", state, "--json"}, &repoOut, &repoErr); code != 0 {
		t.Fatalf("repo scan failed: %d (%s)", code, repoErr.String())
	}
	var repoPayload map[string]any
	if err := json.Unmarshal(repoOut.Bytes(), &repoPayload); err != nil {
		t.Fatalf("parse repo output: %v", err)
	}
	repoFindings, ok := repoPayload["findings"].([]any)
	if !ok || len(repoFindings) == 0 {
		t.Fatalf("expected detector findings from materialized repo scan, got %v", repoPayload["findings"])
	}
	if !containsToolType(repoFindings, "codex") {
		t.Fatalf("expected codex finding from materialized repo scan, got %v", repoFindings)
	}

	var orgOut bytes.Buffer
	var orgErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--org", "acme", "--github-api", server.URL, "--state", state, "--json"}, &orgOut, &orgErr); code != 0 {
		t.Fatalf("org scan failed: %d (%s)", code, orgErr.String())
	}
	var orgPayload map[string]any
	if err := json.Unmarshal(orgOut.Bytes(), &orgPayload); err != nil {
		t.Fatalf("parse org output: %v", err)
	}
	orgFindings, ok := orgPayload["findings"].([]any)
	if !ok || len(orgFindings) == 0 {
		t.Fatalf("expected detector findings from materialized org scan, got %v", orgPayload["findings"])
	}
	if !containsToolType(orgFindings, "codex") {
		t.Fatalf("expected codex finding from materialized org scan, got %v", orgFindings)
	}

	pathTarget := filepath.Join(tmp, "local-repos")
	if err := os.MkdirAll(filepath.Join(pathTarget, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir local repo: %v", err)
	}
	var pathOut bytes.Buffer
	var pathErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", pathTarget, "--state", state, "--json"}, &pathOut, &pathErr); code != 0 {
		t.Fatalf("path scan failed: %d (%s)", code, pathErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(pathOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	manifest := payload["source_manifest"].(map[string]any)
	repos := manifest["repos"].([]any)
	if len(repos) != 1 {
		t.Fatalf("expected one local repo, got %d", len(repos))
	}
}

func TestE2EAirGappedPathScan(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	pathTarget := filepath.Join(tmp, "air-gapped")
	statePath := filepath.Join(tmp, "state.json")
	if err := os.MkdirAll(filepath.Join(pathTarget, "repo1"), 0o755); err != nil {
		t.Fatalf("mkdir repo1: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"scan", "--path", pathTarget, "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("air-gapped path scan should succeed offline: %d (%s)", code, errOut.String())
	}
}

func TestE2EScanRepoRejectsUnmanagedMaterializedRoot(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, ".wrkr", "state.json")
	materializedRoot := filepath.Join(filepath.Dir(statePath), "materialized-sources")
	if err := os.MkdirAll(materializedRoot, 0o750); err != nil {
		t.Fatalf("mkdir materialized root: %v", err)
	}
	stalePath := filepath.Join(materializedRoot, "unmanaged.txt")
	if err := os.WriteFile(stalePath, []byte("do-not-delete"), 0o600); err != nil {
		t.Fatalf("write unmanaged file: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"scan", "--repo", "acme/backend", "--github-api", "https://example.invalid", "--state", statePath, "--json"}, &out, &errOut)
	if code != 8 {
		t.Fatalf("expected exit 8 for unmanaged materialized root, got %d (%s)", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan error payload: %v", err)
	}
	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object payload: %v", payload)
	}
	if errObj["code"] != "unsafe_operation_blocked" {
		t.Fatalf("expected unsafe_operation_blocked code, got %v", errObj["code"])
	}
	if _, err := os.Stat(stalePath); err != nil {
		t.Fatalf("expected unmanaged file to remain, got %v", err)
	}
}

func TestE2EScanPathMixedReposPreservesSafeFindingsWhenOneRepoIsUnsafe(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	statePath := filepath.Join(tmp, "state.json")
	safeRepo := filepath.Join(reposPath, "alpha", ".codex")
	unsafeRepo := filepath.Join(reposPath, "beta")
	if err := os.MkdirAll(safeRepo, 0o755); err != nil {
		t.Fatalf("mkdir safe repo: %v", err)
	}
	if err := os.MkdirAll(unsafeRepo, 0o755); err != nil {
		t.Fatalf("mkdir unsafe repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(safeRepo, "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write safe codex config: %v", err)
	}
	outside := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(outside, []byte("OPENAI_API_KEY=redacted\n"), 0o600); err != nil {
		t.Fatalf("write outside env: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(unsafeRepo, ".env")); err != nil {
		t.Skipf("symlinks unsupported in this environment: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("path scan failed: %d (%s)", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse path scan payload: %v", err)
	}
	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}
	if !containsFinding(findings, "tool_config", "codex", "alpha", ".codex/config.toml", "") {
		t.Fatalf("expected safe repo codex finding, got %v", findings)
	}
	if !containsFinding(findings, "parse_error", "secret", "beta", ".env", "unsafe_path") {
		t.Fatalf("expected unsafe_path parse error for unsafe repo, got %v", findings)
	}
}

func containsToolType(findings []any, want string) bool {
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		toolType, _ := finding["tool_type"].(string)
		if toolType == want {
			return true
		}
	}
	return false
}

func containsFinding(findings []any, findingType, toolType, repo, location, parseKind string) bool {
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["finding_type"] != findingType || finding["tool_type"] != toolType || finding["repo"] != repo || finding["location"] != location {
			continue
		}
		if parseKind == "" {
			return true
		}
		parseErr, ok := finding["parse_error"].(map[string]any)
		if ok && parseErr["kind"] == parseKind {
			return true
		}
	}
	return false
}
