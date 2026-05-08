package attribution

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
)

func TestLocalFindsCommitIntroducingWorkflowLine(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	runGit(t, repoRoot, nil, "init")
	runGit(t, repoRoot, nil, "config", "user.name", "Wrkr Test")
	runGit(t, repoRoot, nil, "config", "user.email", "wrkr@example.com")

	workflowPath := filepath.Join(repoRoot, ".github", "workflows")
	if err := os.MkdirAll(workflowPath, 0o755); err != nil {
		t.Fatalf("mkdir workflow path: %v", err)
	}
	rel := ".github/workflows/release.yml"
	abs := filepath.Join(repoRoot, rel)
	if err := os.WriteFile(abs, []byte("name: release\njobs:\n  release:\n    runs-on: ubuntu-latest\n"), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	runGit(t, repoRoot, gitEnv("2026-04-28T10:00:00Z"), "add", ".")
	runGit(t, repoRoot, gitEnv("2026-04-28T10:00:00Z"), "commit", "-m", "initial workflow")

	if err := os.WriteFile(abs, []byte("name: release\njobs:\n  release:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n"), 0o600); err != nil {
		t.Fatalf("update workflow: %v", err)
	}
	runGit(t, repoRoot, gitEnv("2026-04-29T11:00:00Z"), "add", rel)
	runGit(t, repoRoot, gitEnv("2026-04-29T11:00:00Z"), "commit", "-m", "add write permission")

	result := Local(repoRoot, rel, &model.LocationRange{StartLine: 5, EndLine: 6})
	if result == nil {
		t.Fatal("expected attribution result")
	}
	if result.Source != SourceLocalGit || result.Confidence != ConfidenceHigh {
		t.Fatalf("expected high-confidence local_git attribution, got %+v", result)
	}
	if result.CommitSHA == "" || result.Author != "Wrkr Test" {
		t.Fatalf("expected commit sha and author, got %+v", result)
	}
	if !strings.HasPrefix(result.Timestamp, "2026-04-29T11:00:00") {
		t.Fatalf("expected second commit timestamp, got %+v", result)
	}
}

func TestLocalReturnsExplicitLowConfidenceWhenGitMetadataMissing(t *testing.T) {
	t.Parallel()

	result := Local(t.TempDir(), ".github/workflows/release.yml", &model.LocationRange{StartLine: 1, EndLine: 1})
	if result == nil {
		t.Fatal("expected attribution result")
	}
	if result.Confidence != ConfidenceLow || result.MissingReason == "" {
		t.Fatalf("expected explicit low-confidence missing attribution, got %+v", result)
	}
}

func TestLocalWithoutLineRangeFallsBackToLatestCommit(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	runGit(t, repoRoot, nil, "init")
	runGit(t, repoRoot, nil, "config", "user.name", "Wrkr Test")
	runGit(t, repoRoot, nil, "config", "user.email", "wrkr@example.com")

	workflowPath := filepath.Join(repoRoot, ".github", "workflows")
	if err := os.MkdirAll(workflowPath, 0o755); err != nil {
		t.Fatalf("mkdir workflow path: %v", err)
	}
	rel := ".github/workflows/release.yml"
	abs := filepath.Join(repoRoot, rel)
	if err := os.WriteFile(abs, []byte("name: release\njobs:\n  release:\n    runs-on: ubuntu-latest\n"), 0o600); err != nil {
		t.Fatalf("write workflow: %v", err)
	}
	runGit(t, repoRoot, gitEnv("2026-04-28T10:00:00Z"), "add", ".")
	runGit(t, repoRoot, gitEnv("2026-04-28T10:00:00Z"), "commit", "-m", "initial workflow")

	if err := os.WriteFile(abs, []byte("name: release\njobs:\n  release:\n    runs-on: ubuntu-latest\n    permissions:\n      contents: write\n"), 0o600); err != nil {
		t.Fatalf("update workflow: %v", err)
	}
	runGit(t, repoRoot, gitEnv("2026-04-29T11:00:00Z"), "add", rel)
	runGit(t, repoRoot, gitEnv("2026-04-29T11:00:00Z"), "commit", "-m", "add write permission")

	result := Local(repoRoot, rel, nil)
	if result == nil {
		t.Fatal("expected attribution result")
	}
	if result.Confidence != ConfidenceLow || result.MissingReason != "line_range_unavailable" {
		t.Fatalf("expected low-confidence latest-commit fallback, got %+v", result)
	}
	if result.CommitSHA == "" || result.Author != "Wrkr Test" {
		t.Fatalf("expected latest commit metadata in fallback, got %+v", result)
	}
}

func TestResolvePrefersGitHubEventMetadataWhenChangedFileMatches(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".wrkr", "provenance"), 0o755); err != nil {
		t.Fatalf("mkdir provenance dir: %v", err)
	}
	payload := `{
  "pull_request": {
    "number": 42,
    "html_url": "https://github.com/acme/demo/pull/42",
    "updated_at": "2026-05-08T11:58:00Z",
    "user": {"login": "octocat"},
    "head": {"sha": "abc123def"}
  },
  "commits": [
    {"added": [".github/workflows/release.yml"], "modified": ["AGENTS.md"], "removed": []}
  ]
}`
	if err := os.WriteFile(filepath.Join(repoRoot, ".wrkr", "provenance", "github-event.json"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write github event payload: %v", err)
	}

	result := Resolve(LoadContext(repoRoot), ".github/workflows/release.yml", &model.LocationRange{StartLine: 1, EndLine: 1})
	if result == nil {
		t.Fatal("expected attribution result")
	}
	if result.Source != SourceGitHubEvent || result.PRNumber != 42 || result.ProviderURL == "" {
		t.Fatalf("expected GitHub event attribution, got %+v", result)
	}
	if result.CommitSHA != "abc123def" || result.Author != "octocat" {
		t.Fatalf("expected GitHub event commit metadata, got %+v", result)
	}
}

func TestResolveUnderstandsGitLabMergeRequestMetadata(t *testing.T) {
	t.Parallel()

	repoRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repoRoot, ".wrkr", "provenance"), 0o755); err != nil {
		t.Fatalf("mkdir provenance dir: %v", err)
	}
	payload := `{
  "user": {"username": "gitlab-user"},
  "object_attributes": {
    "iid": 17,
    "url": "https://gitlab.example.com/acme/demo/-/merge_requests/17",
    "updated_at": "2026-05-08T11:59:00Z",
    "last_commit": {"id": "feedbeef"}
  },
  "changes": {"modified_paths": ["AGENTS.md"]}
}`
	if err := os.WriteFile(filepath.Join(repoRoot, ".wrkr", "provenance", "gitlab-event.json"), []byte(payload), 0o600); err != nil {
		t.Fatalf("write gitlab event payload: %v", err)
	}

	result := Resolve(LoadContext(repoRoot), "AGENTS.md", nil)
	if result == nil {
		t.Fatal("expected attribution result")
	}
	if result.Source != SourceGitLabEvent || result.PRNumber != 17 {
		t.Fatalf("expected GitLab merge request attribution, got %+v", result)
	}
	if result.CommitSHA != "feedbeef" || result.Author != "gitlab-user" {
		t.Fatalf("expected GitLab commit metadata, got %+v", result)
	}
}

func runGit(t *testing.T, repoRoot string, env []string, args ...string) {
	t.Helper()

	cmd := exec.Command("git", append([]string{"-C", repoRoot}, args...)...) // #nosec G204 -- deterministic test fixture setup.
	cmd.Env = append(os.Environ(), env...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, output)
	}
}

func gitEnv(timestamp string) []string {
	return []string{
		"GIT_AUTHOR_DATE=" + timestamp,
		"GIT_COMMITTER_DATE=" + timestamp,
	}
}
