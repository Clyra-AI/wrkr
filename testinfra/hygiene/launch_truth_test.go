package hygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLaunchTruthScenarioFirstOnboarding(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scenarioCmd := "wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json"
	repoFallbackCmd := "wrkr scan --path ./your-repo --json"
	requiredNoiseText := "repo-root fixture noise"

	cases := []struct {
		path string
	}{
		{path: filepath.Join(repoRoot, "README.md")},
		{path: filepath.Join(repoRoot, "docs/examples/quickstart.md")},
		{path: filepath.Join(repoRoot, "docs-site/public/llm/quickstart.md")},
		{path: filepath.Join(repoRoot, "docs-site/src/app/page.tsx")},
	}

	for _, tc := range cases {
		content := mustReadFile(t, tc.path)
		if !strings.Contains(content, scenarioCmd) {
			t.Fatalf("%s missing curated scenario command %q", tc.path, scenarioCmd)
		}
		if !strings.Contains(content, requiredNoiseText) {
			t.Fatalf("%s missing repo-root noise explanation marker %q", tc.path, requiredNoiseText)
		}
		scenarioIdx := strings.Index(content, scenarioCmd)
		fallbackIdx := strings.Index(content, repoFallbackCmd)
		if fallbackIdx >= 0 && scenarioIdx > fallbackIdx {
			t.Fatalf("%s must present the curated scenario before repo-local fallback", tc.path)
		}
	}
}

func TestLaunchTruthReadmeStartHereLeadsWithShippedWedge(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	readme := mustReadFile(t, filepath.Join(repoRoot, "README.md"))
	startHere := substringBetween(readme, "## Start Here", "## Why Wrkr")
	if startHere == "" {
		t.Fatal("README missing Start Here first-screen section")
	}

	for _, required := range []string{
		"wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json",
		"wrkr evidence --frameworks",
		"wrkr verify --chain",
		"wrkr regress init",
	} {
		if !strings.Contains(startHere, required) {
			t.Fatalf("README Start Here missing shipped wedge anchor %q", required)
		}
	}

	for _, forbidden := range []string{
		"wrkr action",
		"board-ready",
		"board ready",
		"open remediation PRs",
		"auto-opens remediation PRs",
	} {
		if strings.Contains(startHere, forbidden) {
			t.Fatalf("README Start Here must not lead with later-wave surface %q", forbidden)
		}
	}
}

func TestLaunchTruthClaimsRequireImplementedCapabilities(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	publicPaths := []string{
		"README.md",
		"product/wrkr.md",
		"docs/positioning.md",
		"docs/concepts/mental_model.md",
		"docs/commands/action.md",
		"docs/commands/fix.md",
		"docs/commands/report.md",
		"docs/examples/quickstart.md",
		"docs/examples/security-team.md",
		"docs/examples/operator-playbooks.md",
		"docs-site/public/llms.txt",
		"docs-site/public/llm/product.md",
		"docs-site/public/llm/quickstart.md",
		"docs-site/src/app/page.tsx",
	}

	var joined strings.Builder
	for _, rel := range publicPaths {
		joined.WriteString(mustReadFile(t, filepath.Join(repoRoot, rel)))
		joined.WriteString("\n")
	}
	publicContent := joined.String()

	if containsAny(publicContent, "wrkr-action@v1", "packaged action", "GitHub Action (`Clyra-AI/wrkr-action@v1`)") {
		if _, err := os.Stat(filepath.Join(repoRoot, "action.yml")); err != nil {
			t.Fatalf("packaged-action claims require repo-root action.yml: %v", err)
		}
	}

	if containsPositiveBoardReadyClaim(publicContent) {
		reportPDF := mustReadFile(t, filepath.Join(repoRoot, "core/cli/report_pdf.go"))
		if strings.Contains(reportPDF, "if len(normalized) > 110") || strings.Contains(reportPDF, "/Count 1") {
			t.Fatal("board-ready PDF claims require wrapped and paginated renderer, not the truncating single-page implementation")
		}
		if !acceptanceContains(repoRoot, "board-ready") && !acceptanceContains(repoRoot, "executive report") {
			t.Fatal("board-ready PDF claims require explicit executive-report acceptance coverage")
		}
	}

	if containsAny(publicContent, "open remediation PRs", "auto-opens remediation PRs", "directly edits repo files", "one PR per finding") {
		fixDoc := mustReadFile(t, filepath.Join(repoRoot, "docs/commands/fix.md"))
		fixCLI := mustReadFile(t, filepath.Join(repoRoot, "core/cli/fix.go"))
		if !strings.Contains(fixDoc, "--apply") || !strings.Contains(fixCLI, "fs.Bool(\"apply\"") {
			t.Fatal("direct-remediation claims require an explicit --apply surface in docs and CLI")
		}
	}
}

func TestLaunchTruthChangelogExpectationForPublicWordingChanges(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	contributing := mustReadFile(t, filepath.Join(repoRoot, "CONTRIBUTING.md"))
	docsMap := mustReadFile(t, filepath.Join(repoRoot, "docs/map.md"))
	changelog := mustReadFile(t, filepath.Join(repoRoot, "CHANGELOG.md"))

	if !strings.Contains(strings.ToLower(contributing), "public contract wording changes") {
		t.Fatal("CONTRIBUTING must explicitly require changelog updates for public contract wording changes")
	}
	if !strings.Contains(strings.ToLower(docsMap), "public contract wording changes") {
		t.Fatal("docs/map.md must describe source-of-truth handling for public contract wording changes")
	}
	if !strings.Contains(strings.ToLower(changelog), "public contract wording changes") {
		t.Fatal("CHANGELOG must describe how public contract wording changes are tracked under Unreleased")
	}
}

func containsAny(text string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(text, needle) {
			return true
		}
	}
	return false
}

func containsPositiveBoardReadyClaim(text string) bool {
	lower := strings.ToLower(text)
	for _, needle := range []string{"board-ready", "board ready"} {
		searchFrom := 0
		for {
			relIdx := strings.Index(lower[searchFrom:], needle)
			if relIdx < 0 {
				break
			}
			idx := searchFrom + relIdx
			start := idx - 32
			if start < 0 {
				start = 0
			}
			end := idx + len(needle) + 32
			if end > len(lower) {
				end = len(lower)
			}
			window := lower[start:end]
			if !strings.Contains(window, "not a board-ready") && !strings.Contains(window, "not board-ready") && !strings.Contains(window, "not a board ready") && !strings.Contains(window, "not board ready") {
				return true
			}
			searchFrom = idx + len(needle)
		}
	}
	return false
}

func acceptanceContains(repoRoot string, needle string) bool {
	matches, err := filepath.Glob(filepath.Join(repoRoot, "internal/acceptance", "*.go"))
	if err != nil {
		return false
	}
	for _, match := range matches {
		payload, readErr := os.ReadFile(match)
		if readErr != nil {
			continue
		}
		if strings.Contains(string(payload), needle) {
			return true
		}
	}
	return false
}

func substringBetween(text string, start string, end string) string {
	startIdx := strings.Index(text, start)
	if startIdx < 0 {
		return ""
	}
	out := text[startIdx:]
	endIdx := strings.Index(out, end)
	if endIdx < 0 {
		return out
	}
	return out[:endIdx]
}
