package agentframework

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestDetect_DefaultsDeploymentGateFromHumanGate(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	configPath := ".wrkr/agents/langchain.yaml"
	writeFile(t, root, configPath, `agents:
  - name: release_agent
    file: agents/release.py
    auto_deploy: true
    human_gate: true
`)

	findings, err := Detect(context.Background(), detect.Scope{Org: "acme", Repo: "payments", Root: root}, DetectorConfig{
		DetectorID: "agentframework_langchain",
		Framework:  "langchain",
		ConfigPath: configPath,
		Format:     "yaml",
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if value := evidenceValue(findings[0], "deployment_gate"); value != "enforced" {
		t.Fatalf("expected deployment_gate=enforced, got %q", value)
	}
}

func TestDetect_UsesExplicitDeploymentGate(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	configPath := ".wrkr/agents/openai.yaml"
	writeFile(t, root, configPath, `agents:
  - name: release_agent
    file: agents/release.py
    auto_deploy: true
    human_gate: false
    deployment_gate: approved
`)

	findings, err := Detect(context.Background(), detect.Scope{Org: "acme", Repo: "payments", Root: root}, DetectorConfig{
		DetectorID: "agentframework_openai",
		Framework:  "openai_agents",
		ConfigPath: configPath,
		Format:     "yaml",
	})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	if value := evidenceValue(findings[0], "deployment_gate"); value != "approved" {
		t.Fatalf("expected deployment_gate=approved, got %q", value)
	}
}

func evidenceValue(finding model.Finding, key string) string {
	target := strings.ToLower(strings.TrimSpace(key))
	for _, evidence := range finding.Evidence {
		if strings.ToLower(strings.TrimSpace(evidence.Key)) == target {
			return strings.TrimSpace(evidence.Value)
		}
	}
	return ""
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
