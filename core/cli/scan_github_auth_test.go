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
	assertErrorCode(t, errOut.Bytes(), "runtime_failure")

	var envelope map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &envelope); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errorPayload := envelope["error"].(map[string]any)
	message := errorPayload["message"].(string)
	if !strings.Contains(message, "WRKR_GITHUB_TOKEN") || !strings.Contains(message, "--github-token") {
		t.Fatalf("expected actionable auth guidance, got %q", message)
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
