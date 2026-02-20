package mcp

import (
	"context"
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
