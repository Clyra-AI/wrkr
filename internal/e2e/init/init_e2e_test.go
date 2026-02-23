package inite2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestE2EInitThenScanWithRepoTarget(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
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
	t.Setenv("WRKR_GITHUB_API_BASE", server.URL)

	var initOut bytes.Buffer
	var initErr bytes.Buffer
	code := cli.Run([]string{"init", "--non-interactive", "--repo", "acme/backend", "--config", configPath, "--json"}, &initOut, &initErr)
	if code != 0 {
		t.Fatalf("init failed exit=%d stderr=%s", code, initErr.String())
	}

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	code = cli.Run([]string{"scan", "--config", configPath, "--state", statePath, "--json"}, &scanOut, &scanErr)
	if code != 0 {
		t.Fatalf("scan failed exit=%d stderr=%s", code, scanErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(scanOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected payload: %v", payload)
	}
}

func TestE2EInitRejectsInvalidTargetCombo(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"init", "--non-interactive", "--repo", "acme/backend", "--org", "acme", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
}
