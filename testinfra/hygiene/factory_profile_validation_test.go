package hygiene

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFactoryProfileValidationPassesForValidProfile(t *testing.T) {
	t.Parallel()

	repoRoot := writeProfileFixtureRepo(t, profileFixtureOptions{})
	result := runProfileValidation(t, repoRoot)

	if result.Status != "pass" {
		t.Fatalf("expected pass, failures=%v", result.Failures)
	}
	if len(result.Checked) == 0 {
		t.Fatal("expected checked paths to be recorded")
	}
}

func TestFactoryProfileValidationFailsMissingHighRiskSurface(t *testing.T) {
	t.Parallel()

	repoRoot := writeProfileFixtureRepo(t, profileFixtureOptions{
		OmitWebMCPSurface: true,
	})
	_, stderr, err := runProfileValidationRaw(t, repoRoot)
	if err == nil {
		t.Fatal("expected missing high-risk surface validation to fail")
	}
	if !strings.Contains(stderr, "code_review.high_risk_surfaces") || !strings.Contains(stderr, "core/detect/webmcp") {
		t.Fatalf("expected missing webmcp surface failure, got %s", stderr)
	}
}

func TestFactoryProfileValidationAllowsVirtualSurfaceMarkers(t *testing.T) {
	t.Parallel()

	repoRoot := writeProfileFixtureRepo(t, profileFixtureOptions{
		UseVirtualSurface: true,
	})
	result := runProfileValidation(t, repoRoot)

	if result.Status != "pass" {
		t.Fatalf("expected virtual surface to pass, failures=%v", result.Failures)
	}
}

type profileValidationResult struct {
	Status   string              `json:"status"`
	Failures []string            `json:"failures"`
	Checked  []map[string]string `json:"checked"`
}

type profileFixtureOptions struct {
	OmitWebMCPSurface bool
	UseVirtualSurface bool
}

func runProfileValidation(t *testing.T, repoRoot string) profileValidationResult {
	t.Helper()

	stdout, stderr, err := runProfileValidationRaw(t, repoRoot)
	if err != nil {
		t.Fatalf("run profile validation: %v\nstderr=%s", err, stderr)
	}

	var result profileValidationResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("parse profile validation json: %v\nstdout=%s", err, stdout)
	}
	return result
}

func runProfileValidationRaw(t *testing.T, repoRoot string) (string, string, error) {
	t.Helper()

	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available in test environment")
	}

	scriptPath := filepath.Join(mustFindRepoRoot(t), "scripts", "validate_profiles.py")
	cmd := exec.Command(
		pythonPath,
		scriptPath,
		"--repo-root", repoRoot,
		"--profile", "wrkr",
		"--json",
	)
	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if err != nil {
		return "", text, err
	}
	return text, "", nil
}

func writeProfileFixtureRepo(t *testing.T, opts profileFixtureOptions) string {
	t.Helper()

	repoRoot := t.TempDir()
	for _, rel := range []string{
		"factory/profiles",
		"product",
		"docs/trust",
		"docs-site/public/llm",
		"core/source",
		"core/detect/mcp",
		"core/detect/mcpgateway",
		"docs",
		"docs-site",
	} {
		if err := os.MkdirAll(filepath.Join(repoRoot, rel), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
	}
	if !opts.OmitWebMCPSurface {
		if err := os.MkdirAll(filepath.Join(repoRoot, "core/detect/webmcp"), 0o755); err != nil {
			t.Fatalf("mkdir webmcp: %v", err)
		}
	}

	for _, rel := range []string{
		"AGENTS.md",
		"README.md",
		"CHANGELOG.md",
		"product/wrkr.md",
		"product/dev_guides.md",
		"product/architecture_guides.md",
		"product/PLAN_v1.md",
		"docs-site/public/llms.txt",
	} {
		if err := os.WriteFile(filepath.Join(repoRoot, rel), []byte("fixture\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	profileText := strings.Join([]string{
		"project: wrkr",
		"product_name: Wrkr",
		"repo_root: .",
		"default_branch: main",
		"",
		"match:",
		"  directory_names:",
		"    - wrkr",
		"  remotes:",
		"    - Clyra-AI/wrkr",
		"",
		"standards:",
		"  repo_contract: AGENTS.md",
		"  product_contract: product/wrkr.md",
		"  dev_guide: product/dev_guides.md",
		"  architecture_guide: product/architecture_guides.md",
		"  plan_reference: product/PLAN_v1.md",
		"",
		"docs:",
		"  user_facing_paths:",
		"    - README.md",
		"    - docs/",
		"    - docs-site/public/llms.txt",
		"    - docs-site/public/llm/",
		"    - CHANGELOG.md",
		"",
		"code_review:",
		"  high_risk_surfaces:",
		"    - core/source",
		"    - core/detect/mcp",
		"    - core/detect/mcpgateway",
	}, "\n")
	if opts.UseVirtualSurface {
		profileText += "\n    - virtual:core/future-mcp"
	} else {
		profileText += "\n    - core/detect/webmcp"
	}
	profileText += "\n    - docs\n    - docs-site\n"

	profilePath := filepath.Join(repoRoot, "factory", "profiles", "wrkr.yaml")
	if err := os.WriteFile(profilePath, []byte(profileText), 0o644); err != nil {
		t.Fatalf("write profile fixture: %v", err)
	}

	return repoRoot
}
