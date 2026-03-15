package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestScanContinuesOnDetectorError(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("permission fixture is not portable on windows")
	}

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(reposPath, 0o755); err != nil {
		t.Fatalf("mkdir repos: %v", err)
	}

	goodRepo := filepath.Join(reposPath, "alpha")
	if err := os.MkdirAll(filepath.Join(goodRepo, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir good repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(goodRepo, ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	badRepo := filepath.Join(reposPath, "beta")
	if err := os.MkdirAll(badRepo, 0o755); err != nil {
		t.Fatalf("mkdir bad repo: %v", err)
	}
	if err := os.Chmod(badRepo, 0o000); err != nil {
		t.Skipf("chmod 000 unsupported in current environment: %v", err)
	}
	defer func() {
		_ = os.Chmod(badRepo, 0o755)
	}()

	var out bytes.Buffer
	var errOut bytes.Buffer
	statePath := filepath.Join(tmp, "state.json")
	code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed unexpectedly: exit=%d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}

	findings, ok := payload["findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected findings to be preserved, got %v", payload["findings"])
	}
	detectorErrors, ok := payload["detector_errors"].([]any)
	if !ok || len(detectorErrors) == 0 {
		t.Fatalf("expected detector_errors in payload, got %v", payload["detector_errors"])
	}
	firstErr, ok := detectorErrors[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected detector error payload type: %T", detectorErrors[0])
	}
	for _, key := range []string{"detector", "org", "repo", "code", "class", "message"} {
		if _, present := firstErr[key]; !present {
			t.Fatalf("detector error missing key %q: %v", key, firstErr)
		}
	}
}

func TestScanOrgMaterializationFailureReturnsPartialResult(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"},{"full_name":"acme/b"}]`)
		case "/repos/acme/a":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/a","default_branch":"main"}`)
		case "/repos/acme/b":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/b","default_branch":"main"}`)
		case "/repos/acme/a/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		case "/repos/acme/b/git/trees/main":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprint(w, `{"message":"upstream unavailable"}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	var out bytes.Buffer
	var errOut bytes.Buffer

	code := Run([]string{
		"scan",
		"--org", "acme",
		"--github-api", server.URL,
		"--state", statePath,
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed unexpectedly: exit=%d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}
	if partial, ok := payload["partial_result"].(bool); !ok || !partial {
		t.Fatalf("expected partial_result=true, got %v", payload["partial_result"])
	}
	sourceErrors, ok := payload["source_errors"].([]any)
	if !ok || len(sourceErrors) == 0 {
		t.Fatalf("expected source_errors, got %v", payload["source_errors"])
	}
	if degraded, ok := payload["source_degraded"].(bool); !ok || degraded {
		t.Fatalf("expected source_degraded=false for non-degraded failure, got %v", payload["source_degraded"])
	}
}

func TestScanPathRejectsExternalSymlinkedCodexConfig(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	safeRepo := filepath.Join(reposPath, "alpha", ".codex")
	unsafeRepo := filepath.Join(reposPath, "beta", ".codex")
	if err := os.MkdirAll(safeRepo, 0o755); err != nil {
		t.Fatalf("mkdir safe repo: %v", err)
	}
	if err := os.MkdirAll(unsafeRepo, 0o755); err != nil {
		t.Fatalf("mkdir unsafe repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(safeRepo, "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write safe codex config: %v", err)
	}
	outside := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(outside, []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write outside codex config: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(unsafeRepo, "config.toml")); err != nil {
		t.Skipf("symlinks unsupported in this environment: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	statePath := filepath.Join(tmp, "state.json")
	if code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("scan failed unexpectedly: exit=%d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}
	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}
	if !hasFinding(findings, "tool_config", "codex", "alpha", ".codex/config.toml", "") {
		t.Fatalf("expected safe codex finding to remain, got %v", findings)
	}
	if !hasFinding(findings, "parse_error", "codex", "beta", ".codex/config.toml", "unsafe_path") {
		t.Fatalf("expected unsafe_path parse error for beta codex config, got %v", findings)
	}
}

func TestScanPathRejectsExternalSymlinkedEnv(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	safeRepo := filepath.Join(reposPath, "alpha")
	unsafeRepo := filepath.Join(reposPath, "beta")
	if err := os.MkdirAll(filepath.Join(safeRepo, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir safe repo: %v", err)
	}
	if err := os.MkdirAll(unsafeRepo, 0o755); err != nil {
		t.Fatalf("mkdir unsafe repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(safeRepo, ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
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
	statePath := filepath.Join(tmp, "state.json")
	if code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("scan failed unexpectedly: exit=%d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}
	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}
	if !hasFinding(findings, "tool_config", "codex", "alpha", ".codex/config.toml", "") {
		t.Fatalf("expected safe repo findings to remain, got %v", findings)
	}
	if !hasFinding(findings, "parse_error", "secret", "beta", ".env", "unsafe_path") {
		t.Fatalf("expected unsafe_path parse error for beta env file, got %v", findings)
	}
	if hasFinding(findings, "secret_presence", "secret", "beta", ".env", "") {
		t.Fatalf("expected no secret_presence finding for unsafe env symlink, got %v", findings)
	}
}

func TestScanPathSymlinkFailuresRemainDeterministic(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		setupRepo func(t *testing.T, repoRoot string)
		wantKind  string
	}{
		{
			name: "dangling",
			setupRepo: func(t *testing.T, repoRoot string) {
				t.Helper()
				if err := os.Symlink(filepath.Join(repoRoot, "missing.env"), filepath.Join(repoRoot, ".env")); err != nil {
					t.Skipf("symlinks unsupported in this environment: %v", err)
				}
			},
			wantKind: "file_not_found",
		},
		{
			name: "loop",
			setupRepo: func(t *testing.T, repoRoot string) {
				t.Helper()
				first := filepath.Join(repoRoot, ".env")
				second := filepath.Join(repoRoot, ".env.loop")
				if err := os.Symlink(second, first); err != nil {
					t.Skipf("symlinks unsupported in this environment: %v", err)
				}
				if err := os.Symlink(first, second); err != nil {
					t.Skipf("symlinks unsupported in this environment: %v", err)
				}
			},
			wantKind: "parse_error",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tmp := t.TempDir()
			reposPath := filepath.Join(tmp, "repos")
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
			tc.setupRepo(t, unsafeRepo)

			first := scanFindingSignatures(t, reposPath, filepath.Join(tmp, "first-state.json"))
			second := scanFindingSignatures(t, reposPath, filepath.Join(tmp, "second-state.json"))
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("expected deterministic scan findings\nfirst=%v\nsecond=%v", first, second)
			}
			if !containsSignature(first, fmt.Sprintf("parse_error|secret|beta|.env|%s", tc.wantKind)) {
				t.Fatalf("expected parse error signature for %s, got %v", tc.name, first)
			}
			if !containsSignature(first, "tool_config|codex|alpha|.codex/config.toml|") {
				t.Fatalf("expected safe codex finding to remain, got %v", first)
			}
		})
	}
}

func hasFinding(findings []any, findingType, toolType, repo, location, parseKind string) bool {
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

func scanFindingSignatures(t *testing.T, reposPath, statePath string) []string {
	t.Helper()

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("scan failed unexpectedly: exit=%d stderr=%s", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}
	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array, got %T", payload["findings"])
	}
	signatures := make([]string, 0, len(findings))
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		parseKind := ""
		if parseErr, ok := finding["parse_error"].(map[string]any); ok {
			parseKind, _ = parseErr["kind"].(string)
		}
		signatures = append(signatures, fmt.Sprintf("%v|%v|%v|%v|%s", finding["finding_type"], finding["tool_type"], finding["repo"], finding["location"], parseKind))
	}
	return signatures
}

func containsSignature(signatures []string, want string) bool {
	for _, item := range signatures {
		if item == want {
			return true
		}
	}
	return false
}
