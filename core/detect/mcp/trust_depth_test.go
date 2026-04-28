package mcp

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestMCPTrustDepthCapturesDelegationAndExposure(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeMCPTestFile(t, root, ".mcp.json", `{
  "mcpServers": {
    "public-admin": {
      "url": "https://api.example.com/mcp",
      "permissions": ["write", "admin"],
      "delegation": "delegate",
      "auth_strength": "static_secret"
    }
  }
}`)
	writeMCPTestFile(t, root, "mcp-gateway.yaml", "gateway:\n  default_action: allow\n")

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "repo", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect mcp trust depth: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if got := evidenceMapValue(findings[0], "exposure"); got != "public" {
		t.Fatalf("expected public exposure, got %q", got)
	}
	if got := evidenceMapValue(findings[0], "delegation_model"); got != "agent_delegate" {
		t.Fatalf("expected agent delegation, got %q", got)
	}
	if got := evidenceMapValue(findings[0], "gateway_coverage"); got != "unprotected" {
		t.Fatalf("expected unprotected gateway coverage, got %q", got)
	}
	if got := evidenceMapValue(findings[0], "trust_gaps"); got == "" {
		t.Fatalf("expected trust gaps evidence, got empty")
	}
}

func TestMCPTrustDepthHonorsExplicitStaticSecretAuthStrength(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeMCPTestFile(t, root, ".mcp.json", `{
  "mcpServers": {
    "static-auth": {
      "command": "npx",
      "args": ["-y", "tool@1"],
      "auth_strength": "static_secret"
    }
  }
}`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "repo", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect explicit static secret auth: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if got := evidenceMapValue(findings[0], "auth_strength"); got != "static_secret" {
		t.Fatalf("expected auth_strength=static_secret, got %q", got)
	}
}

func writeMCPTestFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func evidenceMapValue(finding model.Finding, key string) string {
	for _, item := range finding.Evidence {
		if item.Key == key {
			return item.Value
		}
	}
	return ""
}
