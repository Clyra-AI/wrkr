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
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/state"
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

	server := newMaterializationFailureServer(t)
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

	loaded, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load saved partial state: %v", err)
	}
	if !loaded.PartialResult {
		t.Fatalf("expected saved state to preserve partial_result=true")
	}
	if len(loaded.SourceErrors) != len(sourceErrors) {
		t.Fatalf("expected saved state source_errors=%d, got %d", len(sourceErrors), len(loaded.SourceErrors))
	}
	if loaded.SourceDegraded {
		t.Fatalf("expected saved state source_degraded=false")
	}
}

func TestPartialSavedStateBlocksDownstreamArtifacts(t *testing.T) {
	t.Parallel()

	server := newMaterializationFailureServer(t)
	defer server.Close()

	tmp := t.TempDir()
	partialStatePath := filepath.Join(tmp, "partial-state.json")
	var scanOut bytes.Buffer
	var scanErr bytes.Buffer

	code := Run([]string{
		"scan",
		"--org", "acme",
		"--github-api", server.URL,
		"--state", partialStatePath,
		"--json",
	}, &scanOut, &scanErr)
	if code != exitSuccess {
		t.Fatalf("partial scan failed unexpectedly: exit=%d stderr=%s", code, scanErr.String())
	}

	cases := []struct {
		name string
		args []string
	}{
		{
			name: "report",
			args: []string{"report", "--state", partialStatePath, "--json"},
		},
		{
			name: "evidence",
			args: []string{"evidence", "--frameworks", "soc2", "--state", partialStatePath, "--output", filepath.Join(tmp, "evidence"), "--json"},
		},
		{
			name: "export",
			args: []string{"export", "--state", partialStatePath, "--json"},
		},
		{
			name: "export tickets",
			args: []string{"export", "tickets", "--dry-run", "--state", partialStatePath, "--json"},
		},
		{
			name: "regress init",
			args: []string{"regress", "init", "--baseline", partialStatePath, "--output", filepath.Join(tmp, "baseline.json"), "--json"},
		},
		{
			name: "regress run raw partial baseline",
			args: []string{"regress", "run", "--baseline", partialStatePath, "--state", partialStatePath, "--json"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			var errOut bytes.Buffer
			code := Run(tc.args, &out, &errOut)
			if code != exitInvalidInput {
				t.Fatalf("expected exit %d, got %d stdout=%q stderr=%q", exitInvalidInput, code, out.String(), errOut.String())
			}
			assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
			assertIncompleteSavedStateError(t, errOut.Bytes())
		})
	}
}

func TestRegressRunBlocksPartialCurrentState(t *testing.T) {
	t.Parallel()

	server := newMaterializationFailureServer(t)
	defer server.Close()

	tmp := t.TempDir()
	cleanReposPath := filepath.Join(tmp, "clean-repos")
	if err := os.MkdirAll(filepath.Join(cleanReposPath, "alpha", ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir clean repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cleanReposPath, "alpha", ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write clean repo fixture: %v", err)
	}

	cleanStatePath := filepath.Join(tmp, "clean-state.json")
	var cleanScanOut bytes.Buffer
	var cleanScanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", cleanReposPath, "--state", cleanStatePath, "--json"}, &cleanScanOut, &cleanScanErr); code != exitSuccess {
		t.Fatalf("clean scan failed unexpectedly: exit=%d stderr=%s", code, cleanScanErr.String())
	}

	baselinePath := filepath.Join(tmp, "baseline.json")
	var initOut bytes.Buffer
	var initErr bytes.Buffer
	if code := Run([]string{"regress", "init", "--baseline", cleanStatePath, "--output", baselinePath, "--json"}, &initOut, &initErr); code != exitSuccess {
		t.Fatalf("baseline init failed unexpectedly: exit=%d stderr=%s", code, initErr.String())
	}

	partialStatePath := filepath.Join(tmp, "partial-state.json")
	var partialScanOut bytes.Buffer
	var partialScanErr bytes.Buffer
	if code := Run([]string{
		"scan",
		"--org", "acme",
		"--github-api", server.URL,
		"--state", partialStatePath,
		"--json",
	}, &partialScanOut, &partialScanErr); code != exitSuccess {
		t.Fatalf("partial scan failed unexpectedly: exit=%d stderr=%s", code, partialScanErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"regress", "run", "--baseline", baselinePath, "--state", partialStatePath, "--json"}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d stdout=%q stderr=%q", exitInvalidInput, code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
	assertIncompleteSavedStateError(t, errOut.Bytes())
}

func assertIncompleteSavedStateError(t *testing.T, payload []byte) {
	t.Helper()

	envelope := parseTrailingJSONEnvelope(t, payload)
	errorPayload, ok := envelope["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error payload, got %v", envelope)
	}
	message, ok := errorPayload["message"].(string)
	if !ok {
		t.Fatalf("expected error message string, got %v", errorPayload["message"])
	}
	for _, want := range []string{"must be complete", "partial_result=true", "source_errors=1"} {
		if !strings.Contains(message, want) {
			t.Fatalf("expected error message to contain %q, got %q", want, message)
		}
	}
}

func TestScanStatusCompletedPartialResultMatchesScanJSON(t *testing.T) {
	t.Parallel()

	server := newMaterializationFailureServer(t)
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
	if payload["partial_result"] != true {
		t.Fatalf("expected final scan json to remain partial, got %v", payload["partial_result"])
	}

	var statusOut bytes.Buffer
	var statusErr bytes.Buffer
	if statusCode := Run([]string{"scan", "status", "--state", statePath, "--json"}, &statusOut, &statusErr); statusCode != exitSuccess {
		t.Fatalf("scan status failed: %d stderr=%s", statusCode, statusErr.String())
	}
	var status map[string]any
	if err := json.Unmarshal(statusOut.Bytes(), &status); err != nil {
		t.Fatalf("parse scan status: %v", err)
	}
	if status["status"] != "completed" {
		t.Fatalf("expected completed status, got %v", status["status"])
	}
	if status["partial_result"] != true || status["partial_result_marker"] != "partial_result" {
		t.Fatalf("expected completed partial status marker, got %v", status)
	}
}

func TestScanStatusCompletedCleanScanStaysNonPartial(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha", ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reposPath, "alpha", ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write repo fixture: %v", err)
	}

	statePath := filepath.Join(tmp, "state.json")
	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &out, &errOut); code != exitSuccess {
		t.Fatalf("scan failed unexpectedly: exit=%d stderr=%s", code, errOut.String())
	}

	var statusOut bytes.Buffer
	var statusErr bytes.Buffer
	if statusCode := Run([]string{"scan", "status", "--state", statePath, "--json"}, &statusOut, &statusErr); statusCode != exitSuccess {
		t.Fatalf("scan status failed: %d stderr=%s", statusCode, statusErr.String())
	}
	var status map[string]any
	if err := json.Unmarshal(statusOut.Bytes(), &status); err != nil {
		t.Fatalf("parse scan status: %v", err)
	}
	if status["status"] != "completed" {
		t.Fatalf("expected completed status, got %v", status["status"])
	}
	if _, present := status["partial_result"]; present {
		t.Fatalf("expected clean completed scan to omit partial_result, got %v", status["partial_result"])
	}
}

func TestScanPathWorkflowPermissionDeniedSurfaced(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission fixture is not portable on windows")
	}

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha", ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir alpha codex dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reposPath, "alpha", ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write alpha codex config: %v", err)
	}
	workflowDir := filepath.Join(reposPath, "beta", ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("mkdir beta workflow dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "release.yml"), []byte("name: release\n"), 0o600); err != nil {
		t.Fatalf("write workflow fixture: %v", err)
	}
	if err := os.Chmod(workflowDir, 0o000); err != nil {
		t.Skipf("chmod unsupported in current environment: %v", err)
	}
	defer func() {
		_ = os.Chmod(workflowDir, 0o755)
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
	detectorErrors, ok := payload["detector_errors"].([]any)
	if !ok || len(detectorErrors) == 0 {
		t.Fatalf("expected detector_errors in payload, got %v", payload["detector_errors"])
	}
	found := false
	for _, item := range detectorErrors {
		detectorErr, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if detectorErr["repo"] == "beta" && detectorErr["code"] == "permission_denied" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected permission_denied detector error for beta, got %v", detectorErrors)
	}
}

func newMaterializationFailureServer(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}

func TestScanExplainCallsOutPermissionIncompletePosture(t *testing.T) {
	t.Parallel()

	if runtime.GOOS == "windows" {
		t.Skip("chmod-based permission fixture is not portable on windows")
	}

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	workflowDir := filepath.Join(reposPath, "beta", ".github", "workflows")
	if err := os.MkdirAll(workflowDir, 0o755); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workflowDir, "release.yml"), []byte("name: release\n"), 0o600); err != nil {
		t.Fatalf("write workflow fixture: %v", err)
	}
	if err := os.Chmod(workflowDir, 0o000); err != nil {
		t.Skipf("chmod unsupported in current environment: %v", err)
	}
	defer func() {
		_ = os.Chmod(workflowDir, 0o755)
	}()

	var out bytes.Buffer
	var errOut bytes.Buffer
	statePath := filepath.Join(tmp, "state.json")
	code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--explain"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed unexpectedly: exit=%d stderr=%s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "scan completeness: some files or directories could not be read") {
		t.Fatalf("expected explain output to mention incomplete visibility, got %q", out.String())
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

func TestScanPathRejectsExternalSymlinkedGaitPolicy(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	safeRepo := filepath.Join(reposPath, "alpha", ".codex")
	unsafeRepo := filepath.Join(reposPath, "beta")
	if err := os.MkdirAll(safeRepo, 0o755); err != nil {
		t.Fatalf("mkdir safe repo: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(unsafeRepo, ".agents", "skills", "release"), 0o755); err != nil {
		t.Fatalf("mkdir unsafe repo skill dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(safeRepo, "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write safe codex config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(unsafeRepo, ".agents", "skills", "release", "SKILL.md"), []byte(strings.Join([]string{
		"---",
		"allowed-tools:",
		"  - proc.exec",
		"---",
		"",
		"# Release",
	}, "\n")), 0o600); err != nil {
		t.Fatalf("write skill file: %v", err)
	}

	outside := filepath.Join(t.TempDir(), "external.yaml")
	outsidePayload := strings.Join([]string{
		"rules:",
		"  - id: outside-only",
		"    block_tools:",
		"      - proc.exec",
		"    note: SHOULD_NOT_LEAK",
	}, "\n")
	if err := os.WriteFile(outside, []byte(outsidePayload), 0o600); err != nil {
		t.Fatalf("write outside policy: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(unsafeRepo, ".gait"), 0o755); err != nil {
		t.Fatalf("mkdir unsafe repo gait dir: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(unsafeRepo, ".gait", "external.yaml")); err != nil {
		t.Skipf("symlinks unsupported in this environment: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	statePath := filepath.Join(tmp, "state.json")
	if code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("scan failed unexpectedly: exit=%d stderr=%s", code, errOut.String())
	}

	if strings.Contains(out.String(), outside) || strings.Contains(out.String(), "SHOULD_NOT_LEAK") {
		t.Fatalf("expected scan output to avoid leaking outside policy content, got %q", out.String())
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
	if !hasFinding(findings, "parse_error", "gait_policy", "beta", ".gait/external.yaml", "unsafe_path") {
		t.Fatalf("expected unsafe_path parse error for beta gait policy, got %v", findings)
	}
	if hasFinding(findings, "tool_config", "gait_policy", "beta", ".gait/external.yaml", "") {
		t.Fatalf("expected no gait_policy evidence for unsafe symlink, got %v", findings)
	}
	if hasFinding(findings, "skill_policy_conflict", "skill", "beta", ".agents/skills/release/SKILL.md", "") {
		t.Fatalf("expected unsafe gait policy contents to be ignored for skills, got %v", findings)
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
