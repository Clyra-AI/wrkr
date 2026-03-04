package hygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallDocsSmokeGoOnlyPath(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	readme := mustReadFile(t, filepath.Join(repoRoot, "README.md"))
	installDoc := mustReadFile(t, filepath.Join(repoRoot, "docs/install/minimal-dependencies.md"))

	for _, forbidden := range []string{
		"gh release view",
		"python3 -c",
	} {
		if strings.Contains(readme, forbidden) {
			t.Fatalf("README install path must not require %q", forbidden)
		}
	}

	for _, required := range []string{
		"go install github.com/Clyra-AI/wrkr/cmd/wrkr@\"${WRKR_VERSION}\"",
		"curl -fsSL https://api.github.com/repos/Clyra-AI/wrkr/releases/latest",
		"sed -nE",
	} {
		if !strings.Contains(readme, required) {
			t.Fatalf("README missing install requirement %q", required)
		}
	}

	if !strings.Contains(installDoc, "Go-only pinned install") {
		t.Fatal("install docs missing go-only section")
	}
}

func TestDocsLifecyclePathConsistency(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	lifecycle := mustReadFile(t, filepath.Join(repoRoot, "docs/state_lifecycle.md"))
	quickstart := mustReadFile(t, filepath.Join(repoRoot, "docs/examples/quickstart.md"))
	regressDoc := mustReadFile(t, filepath.Join(repoRoot, "docs/commands/regress.md"))

	for _, required := range []string{
		".wrkr/last-scan.json",
		".wrkr/wrkr-regress-baseline.json",
		".wrkr/wrkr-manifest.yaml",
		".wrkr/proof-chain.json",
	} {
		if !strings.Contains(lifecycle, required) {
			t.Fatalf("state lifecycle doc missing canonical path %q", required)
		}
	}
	if !strings.Contains(quickstart, ".wrkr/wrkr-regress-baseline.json") {
		t.Fatal("quickstart missing canonical baseline path")
	}
	if !strings.Contains(regressDoc, ".wrkr/wrkr-regress-baseline.json") {
		t.Fatal("regress command docs missing canonical baseline path")
	}
}

func TestDocsSourceOfTruthSectionsPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	docsMap := mustReadFile(t, filepath.Join(repoRoot, "docs/map.md"))
	readme := mustReadFile(t, filepath.Join(repoRoot, "README.md"))
	contributing := mustReadFile(t, filepath.Join(repoRoot, "CONTRIBUTING.md"))

	for _, required := range []string{
		"## Source-of-truth model",
		"## Required validation bundle",
		"make test-docs-consistency",
		"make docs-site-check",
	} {
		if !strings.Contains(docsMap, required) {
			t.Fatalf("docs map missing %q", required)
		}
	}
	if !strings.Contains(readme, "docs/map.md") {
		t.Fatal("README missing docs source-of-truth map link")
	}
	if !strings.Contains(contributing, "Docs Source of Truth") {
		t.Fatal("CONTRIBUTING missing docs source-of-truth section")
	}
}

func TestContributingContainsRequiredWorkflowSections(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	content := mustReadFile(t, filepath.Join(repoRoot, "CONTRIBUTING.md"))
	for _, required := range []string{
		"## Required Toolchain",
		"## Optional Toolchain",
		"## Go-Only Contributor Path (Default)",
		"## CI Lane Map",
		"## Determinism Requirements",
		"## Detector Authoring Guidance",
		"## Pull Request Workflow",
	} {
		if !strings.Contains(content, required) {
			t.Fatalf("CONTRIBUTING missing section %q", required)
		}
	}
}

func TestCommunityTemplatesPresentAndStructured(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	files := []string{
		".github/ISSUE_TEMPLATE/bug_report.yml",
		".github/ISSUE_TEMPLATE/feature_request.yml",
		".github/ISSUE_TEMPLATE/docs_change.yml",
		".github/pull_request_template.md",
	}
	for _, rel := range files {
		path := filepath.Join(repoRoot, filepath.Clean(rel))
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("required community template missing: %s (%v)", rel, err)
		}
	}

	bug := mustReadFile(t, filepath.Join(repoRoot, ".github/ISSUE_TEMPLATE/bug_report.yml"))
	feature := mustReadFile(t, filepath.Join(repoRoot, ".github/ISSUE_TEMPLATE/feature_request.yml"))
	docs := mustReadFile(t, filepath.Join(repoRoot, ".github/ISSUE_TEMPLATE/docs_change.yml"))
	pr := mustReadFile(t, filepath.Join(repoRoot, ".github/pull_request_template.md"))

	if !strings.Contains(bug, "Contract surface affected") {
		t.Fatal("bug template missing contract surface prompt")
	}
	if !strings.Contains(feature, "Contract impact") {
		t.Fatal("feature template missing contract impact prompt")
	}
	if !strings.Contains(docs, "Validation commands") {
		t.Fatal("docs template missing validation command prompt")
	}
	if !strings.Contains(pr, "## Contract Impact") || !strings.Contains(pr, "## Tests and Lane Evidence") {
		t.Fatal("PR template missing contract/test evidence sections")
	}
}

func TestCommunityHealthFilesAndLinks(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	for _, rel := range []string{"CODE_OF_CONDUCT.md", "CHANGELOG.md"} {
		if _, err := os.Stat(filepath.Join(repoRoot, rel)); err != nil {
			t.Fatalf("required community health file missing: %s (%v)", rel, err)
		}
	}

	readme := mustReadFile(t, filepath.Join(repoRoot, "README.md"))
	if !strings.Contains(readme, "CODE_OF_CONDUCT.md") {
		t.Fatal("README missing code of conduct link")
	}
	if !strings.Contains(readme, "CHANGELOG.md") {
		t.Fatal("README missing changelog link")
	}
}

func TestGovernancePolicyDocsPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	governanceDoc := mustReadFile(t, filepath.Join(repoRoot, "docs/governance/content-visibility.md"))
	productNotice := mustReadFile(t, filepath.Join(repoRoot, "product/README.md"))
	skillsNotice := mustReadFile(t, filepath.Join(repoRoot, ".agents/skills/README.md"))

	for _, required := range []string{
		"Policy A: `product/` visibility",
		"Policy B: `.agents/skills/` visibility",
		"Directory notices and review checklist",
	} {
		if !strings.Contains(governanceDoc, required) {
			t.Fatalf("governance policy missing %q", required)
		}
	}
	if !strings.Contains(productNotice, "docs/governance/content-visibility.md") {
		t.Fatal("product notice missing governance link")
	}
	if !strings.Contains(skillsNotice, "docs/governance/content-visibility.md") {
		t.Fatal("skills notice missing governance link")
	}
}

func TestReadmeContractSectionsPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	readme := mustReadFile(t, filepath.Join(repoRoot, "README.md"))
	contract := mustReadFile(t, filepath.Join(repoRoot, "docs/contracts/readme_contract.md"))
	roadmap := mustReadFile(t, filepath.Join(repoRoot, "docs/roadmap/cross-repo-readme-alignment.md"))

	for _, section := range []string{
		"## Install",
		"## First 10 Minutes (Offline, No Setup)",
		"## Integration (One PR)",
		"## Command Surface",
		"## Governance and Support",
	} {
		if !strings.Contains(readme, section) {
			t.Fatalf("README missing section %q", section)
		}
	}

	for _, required := range []string{
		"## Required sections",
		"1. Install",
		"2. First 10 Minutes",
		"3. Integration",
		"4. Command Surface",
		"5. Governance and Support",
	} {
		if !strings.Contains(contract, required) {
			t.Fatalf("README contract doc missing %q", required)
		}
	}

	if !strings.Contains(roadmap, "Clyra-AI/proof") || !strings.Contains(roadmap, "Clyra-AI/gait") {
		t.Fatal("cross-repo roadmap missing proof/gait follow-ups")
	}
	if !strings.Contains(roadmap, "2026-03-31") || !strings.Contains(roadmap, "2026-04-07") {
		t.Fatal("cross-repo roadmap missing explicit due dates")
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file %s: %v", path, err)
	}
	return string(payload)
}
