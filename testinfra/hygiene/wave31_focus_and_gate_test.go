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
			"wrkr scan --path ./your-repo --profile assessment --state ./.wrkr/last-scan.json --report-md --report-md-path ./.tmp/scan-summary.md",
			"wrkr report --state ./.wrkr/last-scan.json --template agent-action-bom --md --md-path ./.tmp/focused-agent-action-bom.md",
			"wrkr regress init --baseline ./.wrkr/last-scan.json --output ./.wrkr/wrkr-regress-baseline.json --json",
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("focused repo workflow docs missing %q", required)
			}
		}
	}
	for _, required := range []string{
		"Design-partner control validation workflow",
		"wrkr assess --path ./your-repo --baseline ./.wrkr/wrkr-regress-baseline.json --template design-partner-summary --share-profile design-partner --ticket-format jira --output-dir ./.wrkr/assessment",
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

func TestWave31FreezeBlocksNewSurfaceBeforeSprint0Gates(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	agents := mustReadFile(t, filepath.Join(repoRoot, "AGENTS.md"))
	contributing := mustReadFile(t, filepath.Join(repoRoot, "CONTRIBUTING.md"))
	prTemplate := mustReadFile(t, filepath.Join(repoRoot, ".github/pull_request_template.md"))
	changelog := mustReadFile(t, filepath.Join(repoRoot, "CHANGELOG.md"))

	for _, content := range []string{agents, contributing, prTemplate, changelog} {
		for _, required := range []string{
			"Sprint 0",
			"temporary freeze gate",
			"size, redaction, and readability gates are green",
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("Sprint 0 freeze gate docs missing %q", required)
			}
		}
	}
	if !strings.Contains(prTemplate, "Stories 1.1 through 4.2") {
		t.Fatal("pull request template must require explicit Sprint 0 gate justification")
	}
}

func TestWave31FreezeGateRequiresRecursiveRedactionAndCloneStripGreen(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	agents := mustReadFile(t, filepath.Join(repoRoot, "AGENTS.md"))
	contributing := mustReadFile(t, filepath.Join(repoRoot, "CONTRIBUTING.md"))
	planNext := mustReadFile(t, filepath.Join(repoRoot, "product/PLAN_NEXT.md"))

	for _, content := range []string{agents, contributing, planNext} {
		for _, required := range []string{
			"recursive redaction",
			"clone-strip",
			"temporary freeze gate",
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("freeze gate contract missing %q", required)
			}
		}
	}
}

func TestChangelogPrivacyClaimsRequireMeasuredReceipts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	contributing := mustReadFile(t, filepath.Join(repoRoot, "CONTRIBUTING.md"))
	prTemplate := mustReadFile(t, filepath.Join(repoRoot, ".github/pull_request_template.md"))
	changelog := mustReadFile(t, filepath.Join(repoRoot, "CHANGELOG.md"))

	for _, content := range []string{contributing, prTemplate, changelog} {
		for _, required := range []string{
			"measured artifact-size deltas",
			"redaction test names",
			"fixture coverage",
		} {
			if !strings.Contains(content, required) {
				t.Fatalf("receipt governance missing %q", required)
			}
		}
	}
	if !strings.Contains(changelog, "v1.7.3 clarification workflow item") {
		t.Fatal("CHANGELOG must record the v1.7.3 clarification workflow item")
	}
}
