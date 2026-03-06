package agentmcpclient

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestMCPClientDetector_FixtureCoverage(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".wrkr/agents/mcp-client.yaml", `agents:
  - name: mcp_orchestrator
    file: agents/orchestrator.py
    tools: [mcp.server.search, mcp.server.docs]
    auth_surfaces: [token]
`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "platform", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.FindingType != "agent_framework" {
		t.Fatalf("expected agent_framework finding type, got %q", finding.FindingType)
	}
	if finding.Detector != detectorID {
		t.Fatalf("expected detector %q, got %q", detectorID, finding.Detector)
	}
	if finding.ToolType != "mcp_client" {
		t.Fatalf("expected tool_type=mcp_client, got %q", finding.ToolType)
	}
}

func TestMCPClientDetector_ParseErrorsAreDeterministic(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".wrkr/agents/mcp-client.json", `{"agents":[`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "broken", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if findings[0].FindingType != "parse_error" {
		t.Fatalf("expected parse_error finding, got %q", findings[0].FindingType)
	}
	if findings[0].ParseError == nil {
		t.Fatalf("expected parse error payload")
	}
	if findings[0].ParseError.Path != ".wrkr/agents/mcp-client.json" {
		t.Fatalf("unexpected parse error path %q", findings[0].ParseError.Path)
	}
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}
