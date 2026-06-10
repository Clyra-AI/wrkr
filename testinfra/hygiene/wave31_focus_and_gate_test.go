package hygiene

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestWave31FocusedRepoWorkflowDocsRemainPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	readme := mustReadFile(t, filepath.Join(repoRoot, "README.md"))
	quickstart := mustReadFile(t, filepath.Join(repoRoot, "docs/examples/quickstart.md"))
	quickstartLLM := mustReadFile(t, filepath.Join(repoRoot, "docs-site/public/llm/quickstart.md"))
	playbook := mustReadFile(t, filepath.Join(repoRoot, "docs/examples/operator-playbooks.md"))

	for _, content := range []string{readme, quickstart, quickstartLLM} {
		for _, required := range []string{
			"wrkr scan --path ./your-repo --profile assessment --json",
			"wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --json",
			"wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.wrkr/wrkr-regress-baseline.json --json",
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("focused repo workflow docs missing %q", required)
			}
		}
	}
	for _, required := range []string{
		"Design-partner control validation workflow",
		"wrkr assess --path ./your-repo --baseline ./.wrkr/wrkr-regress-baseline.json --template design-partner-summary --share-profile design-partner --ticket-format jira --json",
		"summary.repeat_usage_signals",
	} {
		if !strings.Contains(playbook, required) {
			t.Fatalf("operator playbook missing %q", required)
		}
	}
}

func TestWave31SurfaceAreaGateDocsRemainPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	agents := mustReadFile(t, filepath.Join(repoRoot, "AGENTS.md"))
	prTemplate := mustReadFile(t, filepath.Join(repoRoot, ".github/pull_request_template.md"))
	architecture := mustReadFile(t, filepath.Join(repoRoot, "docs/architecture.md"))
	product := mustReadFile(t, filepath.Join(repoRoot, "product/wrkr.md"))

	for _, content := range []string{agents, prTemplate, architecture, product} {
		for _, required := range []string{
			"focused BOM clarity",
			"repeat use",
			"evidence quality",
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("surface-area gate docs missing %q", required)
			}
		}
	}
	if !strings.Contains(prTemplate, "Budget impact:") {
		t.Fatal("pull request template missing budget impact prompt")
	}
}
