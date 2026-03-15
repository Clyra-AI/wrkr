package agentcustom

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestCustomAgentDetector_RequiresStrongSignalCooccurrence(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".wrkr/agents/custom-agent.yaml", `agents:
  - name: custom_triage
    file: agents/triage.py
`)

	weakFindings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "weak", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect weak: %v", err)
	}
	if len(weakFindings) != 0 {
		t.Fatalf("expected no finding under weak signals, got %+v", weakFindings)
	}

	writeFile(t, root, "AGENTS.md", "# agents\n")
	writeFile(t, root, ".agents/skills/release/SKILL.md", "release policy\n")
	writeFile(t, root, ".github/workflows/release.yml", "jobs:\n  release:\n    steps:\n      - run: codex --full-auto --approval never\n")

	strongFindings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "strong", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect strong: %v", err)
	}
	if len(strongFindings) != 1 {
		t.Fatalf("expected one finding under strong signals, got %d (%+v)", len(strongFindings), strongFindings)
	}
	if strongFindings[0].FindingType != "agent_custom_scaffold" {
		t.Fatalf("unexpected finding type %q", strongFindings[0].FindingType)
	}
	if evidenceValue(strongFindings[0], "signal_count") == "" {
		t.Fatalf("expected signal_count evidence in finding %+v", strongFindings[0])
	}
}

func TestCustomAgentDetector_LowFalsePositiveFixtures(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "README.md", "custom agent architecture discussion only\n")
	writeFile(t, root, ".github/workflows/ci.yml", "jobs:\n  test:\n    steps:\n      - run: go test ./...\n")
	writeFile(t, root, ".agents/skills/docs/SKILL.md", "docs skill\n")

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "low-fp", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no custom-agent findings in low-FP fixture, got %+v", findings)
	}
}

func TestCustomAgentDetector_DeterministicEvidenceKeyOrder(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".wrkr/agents/custom-agent.toml", `[[agents]]
name = "ops_agent"
file = "agents/ops.py"
tools = ["deploy.write", "proc.exec"]
auth_surfaces = ["token"]
`)
	writeFile(t, root, "AGENTS.md", "ops agent\n")
	writeFile(t, root, ".agents/skills/ops/SKILL.md", "ops playbook\n")
	writeFile(t, root, ".github/workflows/ops.yml", "jobs:\n  ops:\n    steps:\n      - run: claude -p \"deploy\"\n")

	scope := detect.Scope{Org: "acme", Repo: "ops", Root: root}
	first, err := New().Detect(context.Background(), scope, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("expected one finding, got %d", len(first))
	}

	for i := 0; i < 12; i++ {
		next, err := New().Detect(context.Background(), scope, detect.Options{})
		if err != nil {
			t.Fatalf("detect run %d: %v", i+1, err)
		}
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("non-deterministic detector output at run %d", i+1)
		}
	}

	if signalSet := evidenceValue(first[0], "signal_set"); signalSet == "" {
		t.Fatalf("expected signal_set evidence")
	}
}

func TestCustomAgentDetector_DetectsExplicitCustomSourceMarkersDeterministically(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "AGENTS.md", "custom source\n")
	writeFile(t, root, ".agents/skills/custom/SKILL.md", "custom skill\n")
	writeFile(t, root, ".github/workflows/release.yml", "jobs:\n  release:\n    steps:\n      - run: codex --full-auto --approval never\n")
	writeFile(t, root, "agents/custom_agents.py", `# wrkr:custom-agent name=triage_agent tools=search.read,ticket.write data=crm.records auth=OPENAI_API_KEY
triage = build_agent()

# wrkr:custom-agent name=release_agent tools=deploy.write auth=GITHUB_TOKEN deploy=.github/workflows/release.yml auto_deploy=true human_gate=true
release = build_agent()
`)

	scope := detect.Scope{Org: "acme", Repo: "custom-source", Root: root}
	first, err := New().Detect(context.Background(), scope, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(first) != 2 {
		t.Fatalf("expected two custom source findings, got %d (%+v)", len(first), first)
	}
	if first[0].FindingType != "agent_custom_source" || first[1].FindingType != "agent_custom_source" {
		t.Fatalf("expected agent_custom_source findings, got %+v", first)
	}
	if evidenceValue(first[0], "symbol") == evidenceValue(first[1], "symbol") {
		t.Fatalf("expected distinct source symbols, got %+v", first)
	}
	if evidenceValue(first[0], "bound_tools") == "" || evidenceValue(first[1], "deployment_artifacts") == "" {
		t.Fatalf("expected explicit source annotation evidence, got %+v", first)
	}

	for i := 0; i < 8; i++ {
		next, err := New().Detect(context.Background(), scope, detect.Options{})
		if err != nil {
			t.Fatalf("detect run %d: %v", i+1, err)
		}
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("non-deterministic source-marker output at run %d", i+1)
		}
	}
}

func TestCustomAgentDetector_FailsClosedForAmbiguousSourceMarkers(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "agents/custom_agents.py", `# wrkr:custom-agent name=notes_only
helper = "not an operational agent declaration"
`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "ambiguous", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected ambiguous marker to fail closed, got %+v", findings)
	}
}

func TestCustomAgentDetector_SkipsNestedDependencyDirectories(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, "AGENTS.md", "custom source\n")
	writeFile(t, root, ".agents/skills/custom/SKILL.md", "custom skill\n")
	writeFile(t, root, ".github/workflows/release.yml", "jobs:\n  release:\n    steps:\n      - run: codex --full-auto --approval never\n")
	writeFile(t, root, "agents/custom_agents.py", `# wrkr:custom-agent name=repo_agent tools=search.read auth=OPENAI_API_KEY
repo_agent = build_agent()
`)
	writeFile(t, root, "apps/web/node_modules/vendor/custom_agents.py", `# wrkr:custom-agent name=dependency_agent tools=deploy.write auth=GITHUB_TOKEN
dependency_agent = build_agent()
`)
	writeFile(t, root, "services/api/vendor/custom_agents.py", `# wrkr:custom-agent name=vendor_agent tools=deploy.write auth=GITHUB_TOKEN
vendor_agent = build_agent()
`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "custom-source", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected only repo-owned source marker finding, got %d (%+v)", len(findings), findings)
	}
	if findings[0].Location != "agents/custom_agents.py" {
		t.Fatalf("expected nested dependency markers to be skipped, got %+v", findings[0])
	}
}

func TestCustomAgentDetector_ParseErrorForMalformedDeclaration(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".wrkr/agents/custom-agent.json", `{"agents":[`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "acme", Repo: "broken", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one parse error finding, got %d", len(findings))
	}
	if findings[0].FindingType != "parse_error" {
		t.Fatalf("expected parse_error finding type, got %q", findings[0].FindingType)
	}
	if findings[0].ParseError == nil || findings[0].ParseError.Path != ".wrkr/agents/custom-agent.json" {
		t.Fatalf("unexpected parse error payload %+v", findings[0].ParseError)
	}
}

func evidenceValue(finding model.Finding, key string) string {
	for _, evidence := range finding.Evidence {
		if evidence.Key == key {
			return evidence.Value
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
