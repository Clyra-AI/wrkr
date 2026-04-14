package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/config"
)

func TestScanUsesEnvGitHubTokenWhenFlagAndConfigUnset(t *testing.T) {
	t.Setenv("WRKR_GITHUB_TOKEN", "env-token")
	server := newHostedScanAuthServer(t, "Bearer env-token")
	defer server.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--repo", "acme/backend",
		"--github-api", server.URL,
		"--state", filepath.Join(t.TempDir(), "state.json"),
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
}

func TestScanGitHubTokenPrecedenceFlagOverConfigAndEnv(t *testing.T) {
	t.Setenv("WRKR_GITHUB_TOKEN", "env-token")
	configPath := writeScanConfig(t, "config-token")
	server := newHostedScanAuthServer(t, "Bearer flag-token")
	defer server.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--repo", "acme/backend",
		"--github-api", server.URL,
		"--github-token", "flag-token",
		"--config", configPath,
		"--state", filepath.Join(t.TempDir(), "state.json"),
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
}

func TestScanGitHubTokenPrecedenceConfigOverEnv(t *testing.T) {
	t.Setenv("WRKR_GITHUB_TOKEN", "env-token")
	configPath := writeScanConfig(t, "config-token")
	server := newHostedScanAuthServer(t, "Bearer config-token")
	defer server.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--repo", "acme/backend",
		"--github-api", server.URL,
		"--config", configPath,
		"--state", filepath.Join(t.TempDir(), "state.json"),
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
}

func TestScanHostedRateLimitFailureMessageIncludesAuthGuidance(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/backend" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
	}))
	defer server.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--repo", "acme/backend",
		"--github-api", server.URL,
		"--state", filepath.Join(t.TempDir(), "state.json"),
		"--json",
	}, &out, &errOut)
	if code != exitRuntime {
		t.Fatalf("expected exit %d, got %d (%s)", exitRuntime, code, errOut.String())
	}
	assertErrorCode(t, errOut.Bytes(), "rate_limited")

	var envelope map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &envelope); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errorPayload := envelope["error"].(map[string]any)
	message := errorPayload["message"].(string)
	for _, want := range []string{
		"status=403",
		"rate limit exhausted after 3 attempt(s)",
		"WRKR_GITHUB_TOKEN",
		"--github-token",
		"reset window",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("expected actionable rate-limit guidance %q, got %q", want, message)
		}
	}
	if errorPayload["exit_code"] != float64(exitRuntime) {
		t.Fatalf("expected runtime exit code to stay %d, got %v", exitRuntime, errorPayload["exit_code"])
	}
}

func TestScanGitHubAPIBasePrecedenceFlagOverConfigAndEnv(t *testing.T) {
	t.Setenv("WRKR_GITHUB_API_BASE", "http://127.0.0.1:1")
	flagServer := newHostedScanBaseServer(t)
	defer flagServer.Close()

	configPath := writeScanConfigWithHostedBase(t, "", "http://127.0.0.1:2")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--repo", "acme/backend",
		"--github-api", flagServer.URL,
		"--config", configPath,
		"--state", filepath.Join(t.TempDir(), "state.json"),
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
}

func TestScanGitHubAPIBasePrecedenceConfigOverEnv(t *testing.T) {
	t.Setenv("WRKR_GITHUB_API_BASE", "http://127.0.0.1:1")
	configServer := newHostedScanBaseServer(t)
	defer configServer.Close()

	configPath := writeScanConfigWithHostedBase(t, "", configServer.URL)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--repo", "acme/backend",
		"--config", configPath,
		"--state", filepath.Join(t.TempDir(), "state.json"),
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
}

func TestScanUsesConfigHostedGitHubAPIBaseForDefaultTarget(t *testing.T) {
	configServer := newHostedScanBaseServer(t)
	defer configServer.Close()

	configPath := writeScanConfigWithHostedBase(t, "", configServer.URL)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--config", configPath,
		"--state", filepath.Join(t.TempDir(), "state.json"),
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: code=%d stderr=%s", code, errOut.String())
	}
}

func TestScanHostedDependencyMissingMentionsConfigGitHubAPIBase(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--repo", "acme/backend",
		"--json",
	}, &out, &errOut)
	if code != exitDependencyMissing {
		t.Fatalf("expected exit %d, got %d (%s)", exitDependencyMissing, code, errOut.String())
	}

	var envelope map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &envelope); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errorPayload := envelope["error"].(map[string]any)
	message := errorPayload["message"].(string)
	for _, want := range []string{
		"--github-api",
		"config github_api_base",
		"WRKR_GITHUB_API_BASE",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("expected dependency guidance %q, got %q", want, message)
		}
	}
}

func newHostedScanAuthServer(t *testing.T, wantAuth string) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != wantAuth {
			t.Fatalf("expected Authorization=%q, got %q", wantAuth, got)
		}
		switch r.URL.Path {
		case "/repos/acme/backend":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/backend","default_branch":"main"}`)
		case "/repos/acme/backend/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
}

func writeScanConfig(t *testing.T, token string) string {
	t.Helper()

	cfg := config.Default()
	cfg.Auth.Scan.Token = token
	cfg.DefaultTarget = config.Target{Mode: config.TargetRepo, Value: "acme/backend"}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := config.Save(path, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return path
}

func newHostedScanBaseServer(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/backend":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/backend","default_branch":"main"}`)
		case "/repos/acme/backend/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
}

func writeScanConfigWithHostedBase(t *testing.T, token string, githubAPIBase string) string {
	t.Helper()

	cfg := config.Default()
	cfg.Auth.Scan.Token = token
	cfg.DefaultTarget = config.Target{Mode: config.TargetRepo, Value: "acme/backend"}
	cfg.GitHubAPIBase = githubAPIBase
	path := filepath.Join(t.TempDir(), "config.json")
	if err := config.Save(path, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}
	return path
}
