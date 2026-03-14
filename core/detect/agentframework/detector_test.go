package agentframework

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
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

func TestDetectMany_DeterministicAcrossFormats(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".wrkr/agents/autogen.yaml", `agents:
  - name: alpha
    file: agents/alpha.py
`)
	writeFile(t, root, ".wrkr/agents/autogen.toml", `[[agents]]
name = "beta"
file = "agents/beta.py"
`)

	scope := detect.Scope{Org: "acme", Repo: "payments", Root: root}
	configs := []DetectorConfig{
		{DetectorID: "agentframework_autogen", Framework: "autogen", ConfigPath: ".wrkr/agents/autogen.toml", Format: "toml"},
		{DetectorID: "agentframework_autogen", Framework: "autogen", ConfigPath: ".wrkr/agents/autogen.yaml", Format: "yaml"},
	}

	first, err := DetectMany(scope, configs)
	if err != nil {
		t.Fatalf("detect many: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("expected two findings, got %d", len(first))
	}
	for _, finding := range first {
		if finding.ToolType != "autogen" {
			t.Fatalf("expected autogen tool type, got %q", finding.ToolType)
		}
	}
	for i := 0; i < 12; i++ {
		next, err := DetectMany(scope, configs)
		if err != nil {
			t.Fatalf("detect many run %d: %v", i+1, err)
		}
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("non-deterministic output at run %d", i+1)
		}
	}
}

func TestDetectMany_ParseErrorDoesNotAbortOtherConfig(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".wrkr/agents/autogen.json", `{"agents":[`)
	writeFile(t, root, ".wrkr/agents/autogen.yaml", `agents:
  - name: rescue
    file: agents/rescue.py
`)

	findings, err := DetectMany(detect.Scope{Org: "acme", Repo: "payments", Root: root}, []DetectorConfig{
		{DetectorID: "agentframework_autogen", Framework: "autogen", ConfigPath: ".wrkr/agents/autogen.json", Format: "json"},
		{DetectorID: "agentframework_autogen", Framework: "autogen", ConfigPath: ".wrkr/agents/autogen.yaml", Format: "yaml"},
	})
	if err != nil {
		t.Fatalf("detect many: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected one parse error and one finding, got %d", len(findings))
	}

	seenParseErr := false
	seenFramework := false
	for _, finding := range findings {
		switch finding.FindingType {
		case "parse_error":
			seenParseErr = true
		case "agent_framework":
			seenFramework = true
		}
	}
	if !seenParseErr || !seenFramework {
		t.Fatalf("expected parse_error and agent_framework findings, got %+v", findings)
	}
}

func TestDetectMany_SourceOnlyMultiAgentFileYieldsStableSeparateDetections(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "agents/crew.py", `from crewai import Agent
import os

researcher = Agent(
    role="research_agent",
    tools=["search.read"],
    data_sources=["warehouse.events"],
    auth_surfaces=[os.getenv("OPENAI_API_KEY")],
)

publisher = Agent(
    role="publisher_agent",
    tools=["deploy.write"],
    data_sources=["prod-db"],
    auth_surfaces=[os.getenv("GITHUB_TOKEN")],
)
`)

	scope := detect.Scope{Org: "acme", Repo: "payments", Root: root}
	configs := []DetectorConfig{
		{DetectorID: "agentcrewai", Framework: "crewai", ConfigPath: ".wrkr/agents/crewai.yaml", Format: "yaml"},
	}

	first, err := DetectMany(scope, configs)
	if err != nil {
		t.Fatalf("detect many: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("expected two source findings, got %d", len(first))
	}
	if first[0].Location != "agents/crew.py" || first[1].Location != "agents/crew.py" {
		t.Fatalf("expected source findings to point at the same file, got %+v", []string{first[0].Location, first[1].Location})
	}
	if first[0].LocationRange == nil || first[1].LocationRange == nil {
		t.Fatalf("expected source findings to include location ranges, got %+v", first)
	}
	if first[0].LocationRange.StartLine >= first[1].LocationRange.StartLine {
		t.Fatalf("expected findings ordered by source line, got %+v", first)
	}
	if evidenceValue(first[0], "symbol") != "research_agent" {
		t.Fatalf("expected first source symbol research_agent, got %q", evidenceValue(first[0], "symbol"))
	}
	if evidenceValue(first[1], "symbol") != "publisher_agent" {
		t.Fatalf("expected second source symbol publisher_agent, got %q", evidenceValue(first[1], "symbol"))
	}
	if evidenceValue(first[0], "bound_tools") != "search.read" {
		t.Fatalf("unexpected first bound_tools evidence %q", evidenceValue(first[0], "bound_tools"))
	}
	if evidenceValue(first[1], "auth_surfaces") != "GITHUB_TOKEN" {
		t.Fatalf("unexpected second auth_surfaces evidence %q", evidenceValue(first[1], "auth_surfaces"))
	}

	for i := 0; i < 8; i++ {
		next, err := DetectMany(scope, configs)
		if err != nil {
			t.Fatalf("detect many rerun %d: %v", i+1, err)
		}
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("expected deterministic source output on rerun %d", i+1)
		}
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
