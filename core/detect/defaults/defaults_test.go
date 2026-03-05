package defaults

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
)

func TestRegistryRunsCrossDetectorCoverage(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	repoEntries, err := os.ReadDir(scanRoot)
	if err != nil {
		t.Fatalf("read scenario repos: %v", err)
	}

	scopes := make([]detect.Scope, 0)
	for _, entry := range repoEntries {
		if !entry.IsDir() {
			continue
		}
		scopes = append(scopes, detect.Scope{Org: "local", Repo: entry.Name(), Root: filepath.Join(scanRoot, entry.Name())})
	}

	registry, err := Registry()
	if err != nil {
		t.Fatalf("create detector registry: %v", err)
	}
	result, err := registry.Run(context.Background(), scopes, detect.Options{})
	if err != nil {
		t.Fatalf("run detector registry: %v", err)
	}
	if len(result.DetectorErrors) != 0 {
		t.Fatalf("expected no detector errors from fixtures, got %+v", result.DetectorErrors)
	}
	findings := result.Findings
	if len(findings) == 0 {
		t.Fatal("expected detector findings from mixed-org fixtures")
	}

	required := map[string]bool{
		"claude":         false,
		"cursor":         false,
		"codex":          false,
		"copilot":        false,
		"mcp":            false,
		"skills":         false,
		"gaitpolicy":     false,
		"dependency":     false,
		"secrets":        false,
		"compiledaction": false,
		"ciagent":        false,
	}
	for _, finding := range findings {
		if _, ok := required[finding.Detector]; ok {
			required[finding.Detector] = true
		}
	}
	for detectorID, seen := range required {
		if !seen {
			t.Fatalf("expected detector %s to produce at least one finding", detectorID)
		}
	}
}

func TestRegistryIncludesAgentFrameworkDetectors(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFixtureFile(t, root, ".wrkr/agents/langchain.json", `{"agents":[{"name":"lc_agent","file":"agents/lang.py"}]}`)
	writeFixtureFile(t, root, ".wrkr/agents/crewai.yaml", "agents:\n  - name: crew_agent\n    file: agents/crew.py\n")
	writeFixtureFile(t, root, ".wrkr/agents/openai-agents.json", `{"agents":[{"name":"oa_agent","file":"agents/openai.py"}]}`)
	writeFixtureFile(t, root, ".wrkr/agents/autogen.json", `{"agents":[{"name":"ag_agent","file":"agents/autogen.py"}]}`)
	writeFixtureFile(t, root, ".wrkr/agents/llamaindex.yaml", "agents:\n  - name: li_agent\n    file: agents/llamaindex.py\n")

	registry, err := Registry()
	if err != nil {
		t.Fatalf("create detector registry: %v", err)
	}
	result, err := registry.Run(context.Background(), []detect.Scope{{Org: "local", Repo: "frameworks", Root: root}}, detect.Options{})
	if err != nil {
		t.Fatalf("run detector registry: %v", err)
	}
	if len(result.DetectorErrors) != 0 {
		t.Fatalf("expected no detector errors, got %+v", result.DetectorErrors)
	}

	seen := map[string]bool{}
	for _, finding := range result.Findings {
		seen[finding.Detector] = true
	}
	for _, detectorID := range []string{"agentlangchain", "agentcrewai", "agentopenai", "agentautogen", "agentllamaindex"} {
		if !seen[detectorID] {
			t.Fatalf("expected detector %s finding in registry run, got %+v", detectorID, result.Findings)
		}
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

func writeFixtureFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}
