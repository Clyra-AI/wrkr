package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestDetectMCPServersAndTrustSignals(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scope := detect.Scope{Org: "local", Repo: "backend", Root: filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos", "backend")}
	findings, err := New().Detect(context.Background(), scope, detect.Options{})
	if err != nil {
		t.Fatalf("detect mcp: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected mcp findings")
	}
	foundTrust := false
	for _, finding := range findings {
		for _, ev := range finding.Evidence {
			if ev.Key == "trust_score" {
				foundTrust = true
			}
		}
	}
	if !foundTrust {
		t.Fatal("expected trust_score evidence in mcp findings")
	}
}

func mustFindRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(wd, "go.mod")); statErr == nil {
			return wd
		}
		next := filepath.Dir(wd)
		if next == wd {
			t.Fatal("could not find repo root")
		}
		wd = next
	}
}

func TestDetectMCPServerOrderIsDeterministic(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	payload := []byte(`{
  "mcpServers": {
    "zeta": { "command": "npx @1", "args": ["-y", "pkg@1"] },
    "alpha": { "command": "npx @1", "args": ["-y", "pkg@1"] },
    "beta": { "command": "npx @1", "args": ["-y", "pkg@1"] }
  }
}`)
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), payload, 0o600); err != nil {
		t.Fatalf("write mcp file: %v", err)
	}

	scope := detect.Scope{
		Org:  "local",
		Repo: "deterministic",
		Root: root,
	}
	expected := []string{"alpha", "beta", "zeta"}
	for i := 0; i < 64; i++ {
		findings, err := New().Detect(context.Background(), scope, detect.Options{})
		if err != nil {
			t.Fatalf("detect mcp: %v", err)
		}
		got := extractServerNames(findings)
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("server order drift on run %d: got %v want %v", i+1, got, expected)
		}
	}
}

func extractServerNames(findings []model.Finding) []string {
	names := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding.FindingType != "mcp_server" || finding.Location != ".mcp.json" {
			continue
		}
		for _, ev := range finding.Evidence {
			if ev.Key == "server" {
				names = append(names, ev.Value)
				break
			}
		}
	}
	return names
}

func TestDetectMCPEnrichAddsNormalizedEvidence(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/advisory":
			_ = json.NewEncoder(w).Encode(map[string]any{"vulns": []any{map[string]any{"id": "GHSA-1"}}})
		case r.URL.Path == "/registry/v0/servers/pkg":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	t.Setenv("WRKR_MCP_ENRICH_ADVISORY_ENDPOINT", server.URL+"/advisory")
	t.Setenv("WRKR_MCP_ENRICH_REGISTRY_BASE", server.URL+"/registry")

	root := t.TempDir()
	payload := []byte(`{"mcpServers":{"demo":{"command":"npx","args":["-y","pkg@1.2.3"]}}}`)
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), payload, 0o600); err != nil {
		t.Fatalf("write mcp config: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "repo", Root: root}, detect.Options{Enrich: true})
	if err != nil {
		t.Fatalf("detect mcp with enrich: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one mcp finding, got %d", len(findings))
	}
	evidence := map[string]string{}
	for _, item := range findings[0].Evidence {
		evidence[item.Key] = item.Value
	}
	for _, key := range []string{"source", "as_of", "package", "version", "advisory_count", "registry_status", "enrich_quality", "advisory_schema", "registry_schema", "enrich_errors"} {
		if evidence[key] == "" {
			t.Fatalf("missing enrich evidence key %s in %#v", key, findings[0].Evidence)
		}
	}
	if evidence["advisory_count"] != "1" {
		t.Fatalf("expected advisory_count=1, got %s", evidence["advisory_count"])
	}
	if evidence["registry_status"] != "unlisted" {
		t.Fatalf("expected registry_status=unlisted, got %s", evidence["registry_status"])
	}
	if evidence["enrich_quality"] != "stale" {
		t.Fatalf("expected enrich_quality=stale for legacy registry schema path, got %s", evidence["enrich_quality"])
	}
}

func TestDetectMCPEnrichDegradesToNoDataOnProviderFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	t.Setenv("WRKR_MCP_ENRICH_ADVISORY_ENDPOINT", server.URL+"/advisory")
	t.Setenv("WRKR_MCP_ENRICH_REGISTRY_BASE", server.URL+"/registry")

	root := t.TempDir()
	payload := []byte(`{"mcpServers":{"demo":{"command":"npx","args":["-y","pkg@1.2.3"]}}}`)
	if err := os.WriteFile(filepath.Join(root, ".mcp.json"), payload, 0o600); err != nil {
		t.Fatalf("write mcp config: %v", err)
	}

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "repo", Root: root}, detect.Options{Enrich: true})
	if err != nil {
		t.Fatalf("detect mcp with enrich: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one mcp finding, got %d", len(findings))
	}
	evidence := map[string]string{}
	for _, item := range findings[0].Evidence {
		evidence[item.Key] = item.Value
	}
	if evidence["enrich_quality"] != "unavailable" {
		t.Fatalf("expected enrich_quality=unavailable, got %s", evidence["enrich_quality"])
	}
	if evidence["advisory_count"] != "0" {
		t.Fatalf("expected advisory_count=0 in fail-safe mode, got %s", evidence["advisory_count"])
	}
	if evidence["registry_status"] != "unknown" {
		t.Fatalf("expected registry_status=unknown in fail-safe mode, got %s", evidence["registry_status"])
	}
}
