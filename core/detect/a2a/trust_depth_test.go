package a2a

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestA2ATrustDepthCapturesPolicyBinding(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeA2ATestFile(t, root, ".well-known/agent.json", `{
  "name":"delegating-agent",
  "capabilities":["delegate.run","search"],
  "auth_schemes":["oauth2"],
  "protocols":["http"]
}`)
	writeA2ATestFile(t, root, "mcp-gateway.yaml", "gateway:\n  default_action: allow\n")

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect a2a trust depth: %v", err)
	}
	finding := mustFindA2AFinding(t, findings)
	if got := evidenceValue(finding, "policy_binding"); got != "missing" {
		t.Fatalf("expected missing policy binding, got %q", got)
	}
	if got := evidenceValue(finding, "trust_gaps"); got == "" {
		t.Fatalf("expected trust gaps evidence, got empty")
	}
}

func writeA2ATestFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}
