package action

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/config"
)

func TestEntrypointE2EUsesRepositoryFallbackTarget(t *testing.T) {
	t.Parallel()

	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available in test environment")
	}

	repoRoot := mustFindRepoRoot(t)
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin dir: %v", err)
	}

	logPath := filepath.Join(tmp, "wrkr.log")
	wrkrPath := filepath.Join(binDir, "wrkr")
	wrkrScript := "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"${WRKR_LOG}\"\n"
	if err := os.WriteFile(wrkrPath, []byte(wrkrScript), 0o755); err != nil {
		t.Fatalf("write wrkr stub: %v", err)
	}

	cmd := exec.Command(bashPath, filepath.Join(repoRoot, "action", "entrypoint.sh"), "scheduled", "5", "", "", "")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"WRKR_LOG="+logPath,
		"GITHUB_REPOSITORY=acme/backend",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run entrypoint: %v output=%s", err, out)
	}

	loggedBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read wrkr log: %v", err)
	}
	lines := nonEmptyLines(string(loggedBytes))
	if len(lines) != 3 {
		t.Fatalf("expected three wrkr invocations, got %d (%v)", len(lines), lines)
	}
	if lines[0] != "scan --json --repo acme/backend" {
		t.Fatalf("expected explicit repo target in scan invocation, got %q", lines[0])
	}
	if lines[1] != "report --top 5 --md --md-path ./.tmp/wrkr-action-summary.md --template operator --share-profile internal --json" {
		t.Fatalf("unexpected report invocation: %q", lines[1])
	}
	if lines[2] != "score --json" {
		t.Fatalf("unexpected score invocation: %q", lines[2])
	}
}

func TestActionMetadataIncludesExplicitTargetInputs(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	payload, err := os.ReadFile(filepath.Join(repoRoot, "action", "action.yaml"))
	if err != nil {
		t.Fatalf("read action metadata: %v", err)
	}
	content := string(payload)
	for _, token := range []string{"target_mode", "target_value", "config_path", "${{ inputs.target_mode }}", "${{ inputs.target_value }}"} {
		if !strings.Contains(content, token) {
			t.Fatalf("expected action metadata to include %q", token)
		}
	}
}

func TestRootActionMetadataIncludesOutputsAndRemediationInputs(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	payload, err := os.ReadFile(filepath.Join(repoRoot, "action.yml"))
	if err != nil {
		t.Fatalf("read root action metadata: %v", err)
	}
	content := string(payload)
	for _, token := range []string{"remediation_mode", "remediation_max_prs", "summary_path", "posture_score", "trend_delta", "compliance_delta"} {
		if !strings.Contains(content, token) {
			t.Fatalf("expected root action metadata to include %q", token)
		}
	}
}

func TestEntrypointE2ERejectsIncompleteExplicitTargetInputs(t *testing.T) {
	t.Parallel()

	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available in test environment")
	}

	repoRoot := mustFindRepoRoot(t)
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin dir: %v", err)
	}

	logPath := filepath.Join(tmp, "wrkr.log")
	wrkrPath := filepath.Join(binDir, "wrkr")
	wrkrScript := "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"${WRKR_LOG}\"\n"
	if err := os.WriteFile(wrkrPath, []byte(wrkrScript), 0o755); err != nil {
		t.Fatalf("write wrkr stub: %v", err)
	}

	cases := []struct {
		name        string
		targetMode  string
		targetValue string
		wantErrText string
	}{
		{
			name:        "mode without value",
			targetMode:  "repo",
			targetValue: "",
			wantErrText: "target_mode requires target_value",
		},
		{
			name:        "value without mode",
			targetMode:  "",
			targetValue: "acme/backend",
			wantErrText: "target_value requires target_mode",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(bashPath, filepath.Join(repoRoot, "action", "entrypoint.sh"), "scheduled", "5", tc.targetMode, tc.targetValue, "")
			cmd.Dir = repoRoot
			cmd.Env = append(os.Environ(),
				"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"WRKR_LOG="+logPath,
				"GITHUB_REPOSITORY=acme/backend",
			)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Fatalf("expected entrypoint to fail, output=%s", out)
			}
			if !strings.Contains(string(out), tc.wantErrText) {
				t.Fatalf("expected error to contain %q, got %q", tc.wantErrText, string(out))
			}
		})
	}

	if _, err := os.Stat(logPath); err == nil {
		loggedBytes, readErr := os.ReadFile(logPath)
		if readErr != nil {
			t.Fatalf("read wrkr log: %v", readErr)
		}
		if len(nonEmptyLines(string(loggedBytes))) > 0 {
			t.Fatalf("expected no wrkr invocation when explicit target inputs are incomplete, got %q", string(loggedBytes))
		}
	}
}

func TestEntrypointPRModeFallsBackToEventPathsWhenGitDiffFails(t *testing.T) {
	t.Parallel()

	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available in test environment")
	}

	repoRoot := mustFindRepoRoot(t)
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin dir: %v", err)
	}

	logPath := filepath.Join(tmp, "wrkr.log")
	wrkrPath := filepath.Join(binDir, "wrkr")
	wrkrScript := "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"${WRKR_LOG}\"\n"
	if err := os.WriteFile(wrkrPath, []byte(wrkrScript), 0o755); err != nil {
		t.Fatalf("write wrkr stub: %v", err)
	}

	eventPath := filepath.Join(tmp, "event.json")
	eventPayload := `{"pull_request":{"number":42},"commits":[{"added":[".codex/config.toml"],"modified":[],"removed":[]}]}`
	if err := os.WriteFile(eventPath, []byte(eventPayload), 0o600); err != nil {
		t.Fatalf("write event payload: %v", err)
	}

	cmd := exec.Command(bashPath, filepath.Join(repoRoot, "action", "entrypoint.sh"), "pr", "5", "", "", "")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"WRKR_LOG="+logPath,
		"GITHUB_REPOSITORY=acme/backend",
		"GITHUB_BASE_REF=refs/heads/main",
		"GITHUB_EVENT_PATH="+eventPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run entrypoint: %v output=%s", err, out)
	}

	loggedBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read wrkr log: %v", err)
	}
	lines := nonEmptyLines(string(loggedBytes))
	if len(lines) != 4 {
		t.Fatalf("expected four wrkr invocations in pr mode, got %d (%v)", len(lines), lines)
	}
	if !strings.Contains(lines[3], "action pr-comment") {
		t.Fatalf("expected pr-comment invocation, got %q", lines[3])
	}
	if !strings.Contains(lines[3], "--changed-paths .codex/config.toml") {
		t.Fatalf("expected changed paths fallback from event payload, got %q", lines[3])
	}
}

func TestEntrypointScheduledApplyInvokesFixForRepoTargets(t *testing.T) {
	t.Parallel()

	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available in test environment")
	}

	repoRoot := mustFindRepoRoot(t)
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin dir: %v", err)
	}

	logPath := filepath.Join(tmp, "wrkr.log")
	wrkrPath := filepath.Join(binDir, "wrkr")
	wrkrScript := "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"${WRKR_LOG}\"\nif [[ \"$1\" == \"scan\" ]]; then printf '{\"profile\":{\"delta_percent\":-1.25}}'; elif [[ \"$1\" == \"score\" ]]; then printf '{\"score\":81.4,\"trend_delta\":1.6}'; else printf '{\"status\":\"ok\"}'; fi\n"
	if err := os.WriteFile(wrkrPath, []byte(wrkrScript), 0o755); err != nil {
		t.Fatalf("write wrkr stub: %v", err)
	}

	cmd := exec.Command(bashPath, filepath.Join(repoRoot, "scripts", "action_entrypoint.sh"), "scheduled", "5", "", "", "")
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"WRKR_LOG="+logPath,
		"GITHUB_REPOSITORY=acme/backend",
		"WRKR_ACTION_REMEDIATION_MODE=apply",
		"WRKR_ACTION_REMEDIATION_MAX_PRS=2",
		"GITHUB_TOKEN=fix-token",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run entrypoint: %v output=%s", err, out)
	}

	loggedBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read wrkr log: %v", err)
	}
	lines := nonEmptyLines(string(loggedBytes))
	if len(lines) != 4 {
		t.Fatalf("expected four wrkr invocations, got %d (%v)", len(lines), lines)
	}
	if !strings.Contains(lines[3], "fix --top 5 --apply --open-pr --max-prs 2 --repo acme/backend") {
		t.Fatalf("expected scheduled apply invocation, got %q", lines[3])
	}
}

func TestEntrypointScheduledApplyUsesConfiguredRepoTarget(t *testing.T) {
	t.Parallel()

	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available in test environment")
	}

	repoRoot := mustFindRepoRoot(t)
	tmp := t.TempDir()
	binDir := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin dir: %v", err)
	}

	configPath := filepath.Join(tmp, "config.json")
	cfg := config.Default()
	cfg.DefaultTarget = config.Target{Mode: config.TargetRepo, Value: "acme/backend"}
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	logPath := filepath.Join(tmp, "wrkr.log")
	wrkrPath := filepath.Join(binDir, "wrkr")
	wrkrScript := "#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >> \"${WRKR_LOG}\"\nif [[ \"$1\" == \"scan\" ]]; then printf '{\"profile\":{\"delta_percent\":-1.25}}'; elif [[ \"$1\" == \"score\" ]]; then printf '{\"score\":81.4,\"trend_delta\":1.6}'; else printf '{\"status\":\"ok\"}'; fi\n"
	if err := os.WriteFile(wrkrPath, []byte(wrkrScript), 0o755); err != nil {
		t.Fatalf("write wrkr stub: %v", err)
	}

	cmd := exec.Command(bashPath, filepath.Join(repoRoot, "scripts", "action_entrypoint.sh"), "scheduled", "5", "", "", configPath)
	cmd.Dir = repoRoot
	cmd.Env = append(os.Environ(),
		"PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"),
		"WRKR_LOG="+logPath,
		"GITHUB_REPOSITORY=acme/automation",
		"WRKR_ACTION_REMEDIATION_MODE=apply",
		"WRKR_ACTION_REMEDIATION_MAX_PRS=2",
		"GITHUB_TOKEN=fix-token",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("run entrypoint: %v output=%s", err, out)
	}

	loggedBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read wrkr log: %v", err)
	}
	lines := nonEmptyLines(string(loggedBytes))
	if len(lines) != 4 {
		t.Fatalf("expected four wrkr invocations, got %d (%v)", len(lines), lines)
	}
	if lines[0] != "scan --json --config "+configPath {
		t.Fatalf("expected config-backed scan invocation, got %q", lines[0])
	}
	if !strings.Contains(lines[3], "fix --top 5 --apply --open-pr --max-prs 2 --repo acme/backend") {
		t.Fatalf("expected scheduled apply invocation to use config repo target, got %q", lines[3])
	}
	if strings.Contains(lines[3], "--repo acme/automation") {
		t.Fatalf("expected scheduled apply invocation to avoid workflow repo target, got %q", lines[3])
	}
}

func nonEmptyLines(in string) []string {
	parts := strings.Split(in, "\n")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func mustFindRepoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get wd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(wd, "go.mod")); err == nil {
			return wd
		}
		next := filepath.Dir(wd)
		if next == wd {
			t.Fatalf("could not locate repo root from %s", wd)
		}
		wd = next
	}
}
