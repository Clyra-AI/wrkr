package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"gopkg.in/yaml.v3"
)

func TestRunJSON(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(out.String(), `"status":"ok"`) {
		t.Fatalf("expected json status output, got %q", out.String())
	}
}

func TestRunHelpReturnsExit0(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--help"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(errOut.String(), "Usage of wrkr:") {
		t.Fatalf("expected help usage output, got %q", errOut.String())
	}
	if !strings.Contains(errOut.String(), "Commands:") {
		t.Fatalf("expected command catalog in help output, got %q", errOut.String())
	}
}

func TestRunRootHelpListsCommands(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--help"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}

	expectedAnchors := []string{
		"  scan       discover tools and emit inventory/risk state",
		"  score      compute posture score and breakdown",
		"  evidence   build compliance-ready evidence bundles",
		"  fix        plan deterministic remediations (repo writes require --open-pr)",
		"Examples:",
		"Global flags:",
	}
	for _, anchor := range expectedAnchors {
		if !strings.Contains(errOut.String(), anchor) {
			t.Fatalf("expected help output to contain %q, got %q", anchor, errOut.String())
		}
	}
}

func TestRunHelpAliasReturnsExit0(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"help"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(errOut.String(), "Usage of wrkr:") {
		t.Fatalf("expected root usage for help alias, got %q", errOut.String())
	}
}

func TestRunHelpSubcommandAliasReturnsExit0(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"help", "scan"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(errOut.String(), "Usage of scan:") {
		t.Fatalf("expected scan usage for help subcommand alias, got %q", errOut.String())
	}
}

func TestRunSubcommandHelpReturnsExit0(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
	}{
		{name: "init", args: []string{"init", "--help"}},
		{name: "scan", args: []string{"scan", "--help"}},
		{name: "action", args: []string{"action", "--help"}},
		{name: "action pr-mode", args: []string{"action", "pr-mode", "--help"}},
		{name: "action pr-comment", args: []string{"action", "pr-comment", "--help"}},
		{name: "evidence", args: []string{"evidence", "--help"}},
		{name: "report", args: []string{"report", "--help"}},
		{name: "campaign", args: []string{"campaign", "--help"}},
		{name: "campaign aggregate", args: []string{"campaign", "aggregate", "--help"}},
		{name: "verify", args: []string{"verify", "--help"}},
		{name: "fix", args: []string{"fix", "--help"}},
		{name: "lifecycle", args: []string{"lifecycle", "--help"}},
		{name: "regress", args: []string{"regress", "--help"}},
		{name: "regress run", args: []string{"regress", "run", "--help"}},
		{name: "manifest", args: []string{"manifest", "--help"}},
		{name: "manifest generate", args: []string{"manifest", "generate", "--help"}},
		{name: "identity", args: []string{"identity", "--help"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			var errOut bytes.Buffer
			code := Run(tc.args, &out, &errOut)
			if code != 0 {
				t.Fatalf("expected exit 0 for %v, got %d (stderr=%q)", tc.args, code, errOut.String())
			}
		})
	}
}

func TestRegressRunHelpMentionsCompatibleBaselineInputs(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"regress", "run", "--help"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d", code)
	}
	if !strings.Contains(errOut.String(), "baseline artifact path or raw scan snapshot path") {
		t.Fatalf("expected regress run help to mention compatible baseline inputs, got %q", errOut.String())
	}
}

func TestScanRejectsMixedMySetupAndPathTargets(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--my-setup", "--path", ".", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object: %v", payload)
	}
	if errObj["code"] != "invalid_input" {
		t.Fatalf("unexpected code: %v", errObj["code"])
	}
}

func TestScanGitHubOrgAliasMatchesOrgContract(t *testing.T) {
	t.Parallel()

	cases := [][]string{
		{"scan", "--org", "acme", "--json"},
		{"scan", "--github-org", "acme", "--json"},
	}
	for _, args := range cases {
		var out bytes.Buffer
		var errOut bytes.Buffer
		code := Run(args, &out, &errOut)
		if code != 7 {
			t.Fatalf("expected dependency-missing exit for %v, got %d stderr=%s", args, code, errOut.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
			t.Fatalf("parse error payload for %v: %v", args, err)
		}
		errObj, ok := payload["error"].(map[string]any)
		if !ok {
			t.Fatalf("expected error object for %v: %v", args, payload)
		}
		if errObj["code"] != "dependency_missing" {
			t.Fatalf("unexpected code for %v: %v", args, errObj["code"])
		}
	}
}

func TestScanMySetupReturnsLocalMachineTarget(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--my-setup", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d %s", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	target, ok := payload["target"].(map[string]any)
	if !ok {
		t.Fatalf("expected target payload: %v", payload["target"])
	}
	if target["mode"] != "my_setup" {
		t.Fatalf("unexpected target mode: %v", target["mode"])
	}
}

func TestScanMySetupFindsEnvironmentKeysAndProjectMarkers(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)
	t.Setenv("OPENAI_API_KEY", "redacted")
	t.Setenv("ANTHROPIC_API_KEY", "redacted")

	projectRoot := filepath.Join(tmpHome, "Projects", "demo-agent")
	if err := os.MkdirAll(filepath.Join(projectRoot, ".agents"), 0o755); err != nil {
		t.Fatalf("mkdir project: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "AGENTS.md"), []byte("agent"), 0o600); err != nil {
		t.Fatalf("write AGENTS.md: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--my-setup", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	findings, ok := payload["findings"].([]any)
	if !ok {
		t.Fatalf("expected findings array: %T", payload["findings"])
	}

	foundEnv := false
	foundProject := false
	for _, item := range findings {
		finding, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if finding["location"] == "process:env" {
			foundEnv = true
		}
		if finding["tool_type"] == "agent_project" {
			foundProject = true
		}
	}
	if !foundEnv {
		t.Fatal("expected process env finding")
	}
	if !foundProject {
		t.Fatal("expected agent project finding")
	}
}

func TestScanMySetupActivationPrefersConcreteSignals(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv("USERPROFILE", tmpHome)
	t.Setenv("OPENAI_API_KEY", "redacted")

	if err := os.MkdirAll(filepath.Join(tmpHome, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir codex: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, ".codex", "config.toml"), []byte("model = \"gpt-5\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmpHome, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpHome, ".claude", "settings.json"), []byte(`{"allowedTools":["bash"]}`), 0o600); err != nil {
		t.Fatalf("write claude settings: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--my-setup", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	activation, ok := payload["activation"].(map[string]any)
	if !ok {
		t.Fatalf("expected activation payload for my_setup scan: %v", payload)
	}
	items, ok := activation["items"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("expected activation items, got %v", activation["items"])
	}
	for _, item := range items {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if row["tool_type"] == "policy" {
			t.Fatalf("policy finding leaked into activation items: %v", items)
		}
	}

	topFindings, ok := payload["top_findings"].([]any)
	if !ok || len(topFindings) == 0 {
		t.Fatalf("expected raw top_findings to remain present: %v", payload["top_findings"])
	}
	foundPolicyTopFinding := false
	for _, item := range topFindings {
		row, ok := item.(map[string]any)
		if !ok {
			continue
		}
		finding, _ := row["finding"].(map[string]any)
		if finding["tool_type"] == "policy" {
			foundPolicyTopFinding = true
			break
		}
	}
	if !foundPolicyTopFinding {
		t.Fatalf("expected raw top_findings to remain unchanged and still expose policy-ranked items: %v", topFindings)
	}
}

func TestRunInvalidFlagReturnsExit6(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--nope"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
}

func TestRunInvalidFlagWithJSONReturnsMachineReadableError(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--json", "--nope"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on parse error, got %q", out.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("expected parsable JSON error output, got %q (%v)", errOut.String(), err)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in payload, got %v", payload)
	}
	if errorPayload["code"] != "invalid_input" {
		t.Fatalf("unexpected error code: %v", errorPayload["code"])
	}
	if errorPayload["exit_code"] != float64(6) {
		t.Fatalf("unexpected exit code envelope: %v", errorPayload["exit_code"])
	}
}

func TestRunInvalidFlagBeforeJSONReturnsMachineReadableError(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--nope", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on parse error, got %q", out.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("expected parsable JSON error output, got %q (%v)", errOut.String(), err)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in payload, got %v", payload)
	}
	if errorPayload["code"] != "invalid_input" {
		t.Fatalf("unexpected error code: %v", errorPayload["code"])
	}
	if errorPayload["exit_code"] != float64(6) {
		t.Fatalf("unexpected exit code envelope: %v", errorPayload["exit_code"])
	}
}

func TestRunUnknownCommandReturnsExit6(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"unknown-cmd"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout for unknown command, got %q", out.String())
	}
	if !strings.Contains(errOut.String(), "unsupported command") {
		t.Fatalf("expected unsupported command error, got %q", errOut.String())
	}
}

func TestRunUnknownCommandWithJSONReturnsMachineReadableError(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"unknown-cmd", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout for unknown command, got %q", out.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("expected parsable JSON error output, got %q (%v)", errOut.String(), err)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in payload, got %v", payload)
	}
	if errorPayload["code"] != "invalid_input" {
		t.Fatalf("unexpected error code: %v", errorPayload["code"])
	}
	if errorPayload["exit_code"] != float64(6) {
		t.Fatalf("unexpected exit code envelope: %v", errorPayload["exit_code"])
	}
}

func TestRunQuietExplainWithoutJSONReturnsExit6(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"--quiet", "--explain"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout for invalid flag combination, got %q", out.String())
	}
	if !strings.Contains(errOut.String(), "--quiet and --explain") {
		t.Fatalf("expected quiet/explain validation message, got %q", errOut.String())
	}
}

func TestInitNonInteractiveWritesConfig(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"init", "--non-interactive", "--repo", "acme/backend", "--config", configPath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d with stderr %q", code, errOut.String())
	}

	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("expected config file to exist: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse json output: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected status: %v", payload["status"])
	}
}

func TestScanMutuallyExclusiveTargetsExit6(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--repo", "acme/backend", "--org", "acme", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}

	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error payload, got %v", payload)
	}
	if errorPayload["code"] != "invalid_input" {
		t.Fatalf("unexpected error code: %v", errorPayload["code"])
	}
}

func TestScanUsesConfiguredDefaultTarget(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	statePath := filepath.Join(tmp, "last-scan.json")
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir repos fixture: %v", err)
	}

	var initOut bytes.Buffer
	var initErr bytes.Buffer
	initCode := Run([]string{"init", "--non-interactive", "--path", reposPath, "--config", configPath, "--json"}, &initOut, &initErr)
	if initCode != 0 {
		t.Fatalf("init failed: exit %d stderr %s", initCode, initErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--config", configPath, "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: exit %d stderr %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse json output: %v", err)
	}
	target := payload["target"].(map[string]any)
	if target["mode"] != "path" || target["value"] != reposPath {
		t.Fatalf("unexpected target: %v", target)
	}
}

func TestScanDiffOnlyReturnsDelta(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir pathA: %v", err)
	}

	var out1 bytes.Buffer
	var err1 bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &out1, &err1)
	if code != 0 {
		t.Fatalf("first scan failed: %d %s", code, err1.String())
	}
	if err := os.MkdirAll(filepath.Join(reposPath, "beta"), 0o755); err != nil {
		t.Fatalf("mkdir beta: %v", err)
	}

	var out2 bytes.Buffer
	var err2 bytes.Buffer
	code = Run([]string{"scan", "--path", reposPath, "--state", statePath, "--diff", "--json"}, &out2, &err2)
	if code != 0 {
		t.Fatalf("diff scan failed: %d %s", code, err2.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out2.Bytes(), &payload); err != nil {
		t.Fatalf("parse diff output: %v", err)
	}
	diffPayload, ok := payload["diff"].(map[string]any)
	if !ok {
		t.Fatalf("expected diff object, got %v", payload)
	}
	added, _ := diffPayload["added"].([]any)
	if len(added) == 0 {
		t.Fatalf("expected added findings, got none payload=%v", payload)
	}
	foundNewRepo := false
	for _, item := range added {
		finding, castOK := item.(map[string]any)
		if !castOK {
			continue
		}
		if finding["tool_type"] == "source_repo" && finding["repo"] == "beta" {
			foundNewRepo = true
			break
		}
	}
	if !foundNewRepo {
		t.Fatalf("expected diff to include beta source discovery, payload=%v", payload)
	}
	removed, _ := diffPayload["removed"].([]any)
	if len(removed) != 0 {
		t.Fatalf("expected no removed findings, got %d", len(removed))
	}
}

func TestScanEnrichRequiresNetworkSource(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--repo", "acme/backend", "--enrich", "--json"}, &out, &errOut)
	if code != 7 {
		t.Fatalf("expected exit 7, got %d", code)
	}

	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errorPayload, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", payload)
	}
	if errorPayload["code"] != "dependency_missing" {
		t.Fatalf("unexpected error code: %v", errorPayload["code"])
	}
}

func TestScanRepoAndOrgRequireGitHubAPI(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
	}{
		{name: "repo", args: []string{"scan", "--repo", "acme/backend", "--json"}},
		{name: "org", args: []string{"scan", "--org", "acme", "--json"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			var errOut bytes.Buffer
			code := Run(tc.args, &out, &errOut)
			if code != 7 {
				t.Fatalf("expected exit 7, got %d", code)
			}
			if out.Len() != 0 {
				t.Fatalf("expected no stdout on dependency error, got %q", out.String())
			}

			payload := parseTrailingJSONEnvelope(t, errOut.Bytes())
			errorPayload, ok := payload["error"].(map[string]any)
			if !ok {
				t.Fatalf("expected error object, got %v", payload)
			}
			if errorPayload["code"] != "dependency_missing" {
				t.Fatalf("unexpected error code: %v", errorPayload["code"])
			}
		})
	}
}

func TestScanRepoAndOrgWithUnreachableGitHubAPIReturnRuntimeFailure(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
	}{
		{name: "repo", args: []string{"scan", "--repo", "acme/backend", "--github-api", "http://127.0.0.1:1", "--json"}},
		{name: "org", args: []string{"scan", "--org", "acme", "--github-api", "http://127.0.0.1:1", "--json"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			var errOut bytes.Buffer
			code := Run(tc.args, &out, &errOut)
			if code != 1 {
				t.Fatalf("expected exit 1, got %d", code)
			}
			if out.Len() != 0 {
				t.Fatalf("expected no stdout on runtime error, got %q", out.String())
			}

			payload := parseTrailingJSONEnvelope(t, errOut.Bytes())
			errorPayload, ok := payload["error"].(map[string]any)
			if !ok {
				t.Fatalf("expected error object, got %v", payload)
			}
			if errorPayload["code"] != "runtime_failure" {
				t.Fatalf("unexpected error code: %v", errorPayload["code"])
			}
		})
	}
}

func TestScanIncludesInventoryProfileAndScore(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--profile", "standard", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}
	for _, key := range []string{"inventory", "privilege_budget", "agent_privilege_map", "repo_exposure_summaries", "profile", "posture_score", "ranked_findings"} {
		if _, present := payload[key]; !present {
			t.Fatalf("missing %s in payload: %v", key, payload)
		}
	}
}

func TestScanIncludesPrivilegeBudgetAndAgentMap(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "payments-prod")
	if err := os.MkdirAll(filepath.Join(repoPath, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	codexCfg := []byte("sandbox_mode = \"danger-full-access\"\napproval_policy = \"never\"\nnetwork_access = true\n")
	if err := os.WriteFile(filepath.Join(repoPath, ".codex", "config.toml"), codexCfg, 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	targetsPath := filepath.Join(tmp, "production-targets.yaml")
	targetsPayload := []byte("schema_version: v1\ntargets:\n  repos:\n    exact:\n      - payments-prod\n")
	if err := os.WriteFile(targetsPath, targetsPayload, 0o600); err != nil {
		t.Fatalf("write production targets: %v", err)
	}

	statePath := filepath.Join(tmp, "state.json")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--production-targets", targetsPath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}

	budget, ok := payload["privilege_budget"].(map[string]any)
	if !ok {
		t.Fatalf("expected privilege_budget object in payload: %v", payload)
	}
	if budget["write_capable_tools"] == nil || budget["credential_access_tools"] == nil || budget["exec_capable_tools"] == nil {
		t.Fatalf("expected budget counters in payload: %v", budget)
	}
	productionWrite, ok := budget["production_write"].(map[string]any)
	if !ok {
		t.Fatalf("expected production_write object in budget: %v", budget)
	}
	if productionWrite["configured"] != true {
		t.Fatalf("expected production_write.configured=true, got %v", productionWrite["configured"])
	}
	if productionWrite["status"] != "configured" {
		t.Fatalf("expected production_write.status=configured, got %v", productionWrite["status"])
	}
	if count, ok := productionWrite["count"].(float64); !ok || count < 1 {
		t.Fatalf("expected production_write.count >= 1, got %v", productionWrite["count"])
	}

	agentMap, ok := payload["agent_privilege_map"].([]any)
	if !ok || len(agentMap) == 0 {
		t.Fatalf("expected non-empty agent_privilege_map: %v", payload["agent_privilege_map"])
	}
	first, ok := agentMap[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected agent map entry type: %T", agentMap[0])
	}
	for _, key := range []string{"agent_id", "agent_instance_id", "framework", "location", "approval_classification", "security_visibility_status", "deployment_status", "write_capable", "credential_access", "exec_capable", "production_write"} {
		if _, present := first[key]; !present {
			t.Fatalf("agent privilege entry missing %s: %v", key, first)
		}
	}
}

func TestScanProductionTargetsMissingNonStrictEmitsWarningAndNullCount(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "payments-prod")
	if err := os.MkdirAll(filepath.Join(repoPath, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	codexCfg := []byte("sandbox_mode = \"danger-full-access\"\napproval_policy = \"never\"\nnetwork_access = true\n")
	if err := os.WriteFile(filepath.Join(repoPath, ".codex", "config.toml"), codexCfg, 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	statePath := filepath.Join(tmp, "state.json")
	missingTargetsPath := filepath.Join(tmp, "missing-targets.yaml")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--production-targets", missingTargetsPath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected scan success in non-strict mode, got %d: %s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}
	warnings, ok := payload["policy_warnings"].([]any)
	if !ok || len(warnings) == 0 {
		t.Fatalf("expected policy_warnings in payload, got %v", payload["policy_warnings"])
	}
	budget, ok := payload["privilege_budget"].(map[string]any)
	if !ok {
		t.Fatalf("expected privilege_budget object in payload: %v", payload)
	}
	productionWrite, ok := budget["production_write"].(map[string]any)
	if !ok {
		t.Fatalf("expected production_write object in budget: %v", budget)
	}
	if productionWrite["configured"] != false {
		t.Fatalf("expected production_write.configured=false, got %v", productionWrite["configured"])
	}
	if productionWrite["status"] != "invalid" {
		t.Fatalf("expected production_write.status=invalid, got %v", productionWrite["status"])
	}
	if productionWrite["count"] != nil {
		t.Fatalf("expected production_write.count=null, got %v", productionWrite["count"])
	}
}

func TestScanApprovedToolsInvalidFailsClosed(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "backend")
	if err := os.MkdirAll(filepath.Join(repoPath, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	approvedPath := filepath.Join(tmp, "approved-tools.yaml")
	if err := os.WriteFile(approvedPath, []byte("schema_version: v2\n"), 0o600); err != nil {
		t.Fatalf("write invalid approved tools policy: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", filepath.Join(tmp, "state.json"), "--approved-tools", approvedPath, "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6 for invalid approved-tools input, got %d (%s)", code, errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on invalid approved-tools input, got %q", out.String())
	}
}

func TestScanApprovedToolsPolicyReclassifiesInventory(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "backend")
	if err := os.MkdirAll(filepath.Join(repoPath, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, ".codex", "config.toml"), []byte("approval_policy = \"never\"\n"), 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	approvedPath := filepath.Join(tmp, "approved-tools.yaml")
	approvedPolicy := []byte(`
schema_version: v1
approved:
  tool_types:
    exact:
      - codex
`)
	if err := os.WriteFile(approvedPath, approvedPolicy, 0o600); err != nil {
		t.Fatalf("write approved tools policy: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", filepath.Join(tmp, "state.json"), "--approved-tools", approvedPath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan output: %v", err)
	}
	inventory, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory object in payload: %v", payload)
	}
	tools, ok := inventory["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatalf("expected non-empty inventory.tools: %v", inventory["tools"])
	}
	firstTool, ok := tools[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected tool payload: %T", tools[0])
	}
	if firstTool["approval_classification"] != "approved" {
		t.Fatalf("expected approval_classification=approved, got %v", firstTool["approval_classification"])
	}
	approvalSummary, ok := inventory["approval_summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected approval_summary object: %v", inventory)
	}
	approvedTools, approvedOk := approvalSummary["approved_tools"].(float64)
	unapprovedTools, unapprovedOk := approvalSummary["unapproved_tools"].(float64)
	if !approvedOk || !unapprovedOk {
		t.Fatalf("unexpected approval summary counters: %v", approvalSummary)
	}
	if approvedTools < 1 {
		t.Fatalf("expected at least one approved tool, got %v", approvalSummary)
	}
	if unapprovedTools < 0 {
		t.Fatalf("unexpected approval summary: %v", approvalSummary)
	}
}

func TestScanProductionTargetsMissingStrictFails(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "payments-prod")
	if err := os.MkdirAll(filepath.Join(repoPath, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	codexCfg := []byte("sandbox_mode = \"danger-full-access\"\napproval_policy = \"never\"\nnetwork_access = true\n")
	if err := os.WriteFile(filepath.Join(repoPath, ".codex", "config.toml"), codexCfg, 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	statePath := filepath.Join(tmp, "state.json")
	missingTargetsPath := filepath.Join(tmp, "missing-targets.yaml")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--production-targets", missingTargetsPath, "--production-targets-strict", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected strict mode exit 6 for missing production targets, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on strict-mode input error, got %q", out.String())
	}
}

func TestScanProductionTargetsStrictWithoutPathFails(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	repoPath := filepath.Join(reposPath, "payments-prod")
	if err := os.MkdirAll(filepath.Join(repoPath, ".codex"), 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	codexCfg := []byte("sandbox_mode = \"danger-full-access\"\napproval_policy = \"never\"\nnetwork_access = true\n")
	if err := os.WriteFile(filepath.Join(repoPath, ".codex", "config.toml"), codexCfg, 0o600); err != nil {
		t.Fatalf("write codex config: %v", err)
	}

	statePath := filepath.Join(tmp, "state.json")
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--path", reposPath, "--state", statePath, "--production-targets-strict", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected strict mode exit 6 without production targets path, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on strict-mode input error, got %q", out.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse strict-mode error payload: %v", err)
	}
	errorObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", payload)
	}
	if errorObj["code"] != "invalid_input" {
		t.Fatalf("expected invalid_input code, got %v", errorObj["code"])
	}
}

func TestScanProductionTargetsStrictWithoutPathPrecedesDependencyChecks(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--repo", "acme/payments", "--production-targets-strict", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected strict mode exit 6 without production targets path, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on strict-mode input error, got %q", out.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse strict-mode error payload: %v", err)
	}
	errorObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", payload)
	}
	if errorObj["code"] != "invalid_input" {
		t.Fatalf("expected invalid_input code, got %v", errorObj["code"])
	}
}

func TestReportExportScoreCommands(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := Run([]string{"report", "--top", "5", "--state", statePath, "--json"}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report failed: %d %s", code, reportErr.String())
	}
	var reportPayload map[string]any
	if err := json.Unmarshal(reportOut.Bytes(), &reportPayload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	if _, ok := reportPayload["top_findings"].([]any); !ok {
		t.Fatalf("expected top_findings array in report payload: %v", reportPayload)
	}

	var exportOut bytes.Buffer
	var exportErr bytes.Buffer
	if code := Run([]string{"export", "--format", "inventory", "--state", statePath, "--json"}, &exportOut, &exportErr); code != 0 {
		t.Fatalf("export failed: %d %s", code, exportErr.String())
	}
	var exportPayload map[string]any
	if err := json.Unmarshal(exportOut.Bytes(), &exportPayload); err != nil {
		t.Fatalf("parse export payload: %v", err)
	}
	if _, present := exportPayload["tools"]; !present {
		t.Fatalf("expected tools in export payload: %v", exportPayload)
	}

	var scoreOut bytes.Buffer
	var scoreErr bytes.Buffer
	if code := Run([]string{"score", "--state", statePath, "--json"}, &scoreOut, &scoreErr); code != 0 {
		t.Fatalf("score failed: %d %s", code, scoreErr.String())
	}
	var scorePayload map[string]any
	if err := json.Unmarshal(scoreOut.Bytes(), &scorePayload); err != nil {
		t.Fatalf("parse score payload: %v", err)
	}
	if _, present := scorePayload["grade"]; !present {
		t.Fatalf("expected grade in score payload: %v", scorePayload)
	}
}

func TestScoreQuietAndExplainContracts(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"score", "--state", statePath, "--quiet"}, &out, &errOut); code != 0 {
		t.Fatalf("score --quiet failed: %d %s", code, errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout for score --quiet, got %q", out.String())
	}

	out.Reset()
	errOut.Reset()
	if code := Run([]string{"score", "--state", statePath, "--explain"}, &out, &errOut); code != 0 {
		t.Fatalf("score --explain failed: %d %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "wrkr score") {
		t.Fatalf("expected explain output, got %q", out.String())
	}

	out.Reset()
	errOut.Reset()
	code := Run([]string{"score", "--state", statePath, "--quiet", "--explain"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6 for score --quiet --explain, got %d", code)
	}
}

func TestReportUsesRankedFindingsWhenTopExceedsStoredTopN(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")

	snapshot := map[string]any{
		"version": "v1",
		"risk_report": map[string]any{
			"generated_at": "2026-02-20T12:00:00Z",
			"top_findings": []any{
				map[string]any{
					"canonical_key": "k1",
					"risk_score":    9.1,
					"finding":       map[string]any{"finding_type": "policy_violation", "location": "WRKR-001"},
				},
			},
			"ranked_findings": []any{
				map[string]any{
					"canonical_key": "k1",
					"risk_score":    9.1,
					"finding":       map[string]any{"finding_type": "policy_violation", "location": "WRKR-001"},
				},
				map[string]any{
					"canonical_key": "k2",
					"risk_score":    8.0,
					"finding":       map[string]any{"finding_type": "policy_violation", "location": "WRKR-002"},
				},
				map[string]any{
					"canonical_key": "k3",
					"risk_score":    7.0,
					"finding":       map[string]any{"finding_type": "policy_violation", "location": "WRKR-003"},
				},
			},
		},
	}
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if err := os.WriteFile(statePath, append(payload, '\n'), 0o600); err != nil {
		t.Fatalf("write state snapshot: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"report", "--top", "3", "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("report failed: %d %s", code, errOut.String())
	}

	var reportPayload map[string]any
	if err := json.Unmarshal(out.Bytes(), &reportPayload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	topFindings, ok := reportPayload["top_findings"].([]any)
	if !ok {
		t.Fatalf("expected top_findings array, got %T", reportPayload["top_findings"])
	}
	if len(topFindings) != 3 {
		t.Fatalf("expected 3 top findings from ranked set, got %d", len(topFindings))
	}
}

func TestIdentityAndLifecycleCommands(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(scanOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	inventoryPayload, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory payload, got %T", payload["inventory"])
	}
	tools, ok := inventoryPayload["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatalf("expected inventory tools, got %v", inventoryPayload["tools"])
	}
	firstTool, ok := tools[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected first tool shape: %T", tools[0])
	}
	agentID, ok := firstTool["agent_id"].(string)
	if !ok || agentID == "" {
		t.Fatalf("expected agent_id in first inventory tool: %v", firstTool)
	}
	if firstTool["discovery_method"] != "static" {
		t.Fatalf("expected discovery_method=static in inventory tool, got %v", firstTool["discovery_method"])
	}
	org, _ := firstTool["org"].(string)

	var approveOut bytes.Buffer
	var approveErr bytes.Buffer
	if code := Run([]string{"identity", "approve", agentID, "--approver", "@maria", "--scope", "read-only", "--expires", "90d", "--state", statePath, "--json"}, &approveOut, &approveErr); code != 0 {
		t.Fatalf("identity approve failed: %d %s", code, approveErr.String())
	}

	var showOut bytes.Buffer
	var showErr bytes.Buffer
	if code := Run([]string{"identity", "show", agentID, "--state", statePath, "--json"}, &showOut, &showErr); code != 0 {
		t.Fatalf("identity show failed: %d %s", code, showErr.String())
	}
	var showPayload map[string]any
	if err := json.Unmarshal(showOut.Bytes(), &showPayload); err != nil {
		t.Fatalf("parse identity show payload: %v", err)
	}
	identityPayload, ok := showPayload["identity"].(map[string]any)
	if !ok {
		t.Fatalf("expected identity object, got %T", showPayload["identity"])
	}
	status, _ := identityPayload["status"].(string)
	if status != "approved" && status != "active" {
		t.Fatalf("expected approved/active status after approval, got %q", status)
	}

	var lifecycleOut bytes.Buffer
	var lifecycleErr bytes.Buffer
	if code := Run([]string{"lifecycle", "--org", org, "--state", statePath, "--json"}, &lifecycleOut, &lifecycleErr); code != 0 {
		t.Fatalf("lifecycle failed: %d %s", code, lifecycleErr.String())
	}
	var lifecyclePayload map[string]any
	if err := json.Unmarshal(lifecycleOut.Bytes(), &lifecyclePayload); err != nil {
		t.Fatalf("parse lifecycle payload: %v", err)
	}
	if _, ok := lifecyclePayload["identities"].([]any); !ok {
		t.Fatalf("expected identities array in lifecycle payload: %v", lifecyclePayload)
	}
}

func TestIdentityAndLifecycleCommandsFilterLegacyNonToolManifestEntries(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	manifestPath := manifest.ResolvePath(statePath)
	loaded := manifest.Manifest{
		Version: manifest.Version,
		Identities: []manifest.IdentityRecord{
			{
				AgentID:       "wrkr:source-repo-aaaaaaaaaa:acme",
				ToolID:        "source-repo-aaaaaaaaaa",
				ToolType:      "source_repo",
				Org:           "acme",
				Status:        "under_review",
				ApprovalState: "missing",
				Present:       true,
			},
			{
				AgentID:       "wrkr:codex-bbbbbbbbbb:acme",
				ToolID:        "codex-bbbbbbbbbb",
				ToolType:      "codex",
				Org:           "acme",
				Status:        "under_review",
				ApprovalState: "missing",
				Present:       true,
			},
		},
	}
	if err := manifest.Save(manifestPath, loaded); err != nil {
		t.Fatalf("save manifest: %v", err)
	}

	var listOut bytes.Buffer
	var listErr bytes.Buffer
	if code := Run([]string{"identity", "list", "--state", statePath, "--json"}, &listOut, &listErr); code != 0 {
		t.Fatalf("identity list failed: %d %s", code, listErr.String())
	}
	var listPayload map[string]any
	if err := json.Unmarshal(listOut.Bytes(), &listPayload); err != nil {
		t.Fatalf("parse identity list payload: %v", err)
	}
	identities, ok := listPayload["identities"].([]any)
	if !ok || len(identities) != 1 {
		t.Fatalf("expected one real-tool identity, got %v", listPayload["identities"])
	}
	identityPayload, ok := identities[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected identity payload type: %T", identities[0])
	}
	agentID, _ := identityPayload["agent_id"].(string)
	if agentID != "wrkr:codex-bbbbbbbbbb:acme" {
		t.Fatalf("expected codex identity only, got %v", identityPayload)
	}

	var lifecycleOut bytes.Buffer
	var lifecycleErr bytes.Buffer
	if code := Run([]string{"lifecycle", "--state", statePath, "--json"}, &lifecycleOut, &lifecycleErr); code != 0 {
		t.Fatalf("lifecycle failed: %d %s", code, lifecycleErr.String())
	}
	var lifecyclePayload map[string]any
	if err := json.Unmarshal(lifecycleOut.Bytes(), &lifecyclePayload); err != nil {
		t.Fatalf("parse lifecycle payload: %v", err)
	}
	lifecycleIdentities, ok := lifecyclePayload["identities"].([]any)
	if !ok || len(lifecycleIdentities) != 1 {
		t.Fatalf("expected one lifecycle identity after filtering, got %v", lifecyclePayload["identities"])
	}

	var showOut bytes.Buffer
	var showErr bytes.Buffer
	if code := Run([]string{"identity", "show", "wrkr:source-repo-aaaaaaaaaa:acme", "--state", statePath, "--json"}, &showOut, &showErr); code != 6 {
		t.Fatalf("expected filtered legacy identity to be not found, got %d stdout=%q stderr=%q", code, showOut.String(), showErr.String())
	}
}

func TestIdentityNonApprovedTransitionsUseDeterministicDefaultReasonAndRevokeApproval(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		subcommand     string
		expectedState  string
		expectedReason string
	}{
		{name: "review", subcommand: "review", expectedState: "under_review", expectedReason: "manual_transition_under_review"},
		{name: "deprecate", subcommand: "deprecate", expectedState: "deprecated", expectedReason: "manual_transition_deprecated"},
		{name: "revoke", subcommand: "revoke", expectedState: "revoked", expectedReason: "manual_transition_revoked"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tmp := t.TempDir()
			statePath := filepath.Join(tmp, "state.json")
			repoRoot := mustFindRepoRoot(t)
			scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

			var scanOut bytes.Buffer
			var scanErr bytes.Buffer
			if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
				t.Fatalf("scan failed: %d %s", code, scanErr.String())
			}

			var payload map[string]any
			if err := json.Unmarshal(scanOut.Bytes(), &payload); err != nil {
				t.Fatalf("parse scan payload: %v", err)
			}
			inventoryPayload, ok := payload["inventory"].(map[string]any)
			if !ok {
				t.Fatalf("expected inventory payload, got %T", payload["inventory"])
			}
			tools, ok := inventoryPayload["tools"].([]any)
			if !ok || len(tools) == 0 {
				t.Fatalf("expected inventory tools, got %v", inventoryPayload["tools"])
			}
			firstTool, ok := tools[0].(map[string]any)
			if !ok {
				t.Fatalf("unexpected first tool shape: %T", tools[0])
			}
			agentID, ok := firstTool["agent_id"].(string)
			if !ok || agentID == "" {
				t.Fatalf("missing agent_id in first tool: %v", firstTool)
			}

			var approveOut bytes.Buffer
			var approveErr bytes.Buffer
			if code := Run([]string{"identity", "approve", agentID, "--approver", "@maria", "--scope", "read-only", "--expires", "90d", "--state", statePath, "--json"}, &approveOut, &approveErr); code != 0 {
				t.Fatalf("identity approve failed: %d %s", code, approveErr.String())
			}

			var transitionOut bytes.Buffer
			var transitionErr bytes.Buffer
			if code := Run([]string{"identity", tc.subcommand, agentID, "--state", statePath, "--json"}, &transitionOut, &transitionErr); code != 0 {
				t.Fatalf("identity %s failed: %d %s", tc.subcommand, code, transitionErr.String())
			}
			var transitionPayload map[string]any
			if err := json.Unmarshal(transitionOut.Bytes(), &transitionPayload); err != nil {
				t.Fatalf("parse transition payload: %v", err)
			}
			transitionObj, ok := transitionPayload["transition"].(map[string]any)
			if !ok {
				t.Fatalf("expected transition payload object, got %v", transitionPayload)
			}
			if gotState, _ := transitionObj["new_state"].(string); gotState != tc.expectedState {
				t.Fatalf("expected new_state=%s, got %q", tc.expectedState, gotState)
			}
			diffObj, ok := transitionObj["diff"].(map[string]any)
			if !ok {
				t.Fatalf("expected transition diff object, got %v", transitionObj["diff"])
			}
			if gotReason, _ := diffObj["reason"].(string); gotReason != tc.expectedReason {
				t.Fatalf("expected reason=%q, got %q", tc.expectedReason, gotReason)
			}

			var showOut bytes.Buffer
			var showErr bytes.Buffer
			if code := Run([]string{"identity", "show", agentID, "--state", statePath, "--json"}, &showOut, &showErr); code != 0 {
				t.Fatalf("identity show failed: %d %s", code, showErr.String())
			}
			var showPayload map[string]any
			if err := json.Unmarshal(showOut.Bytes(), &showPayload); err != nil {
				t.Fatalf("parse identity show payload: %v", err)
			}
			identityObj, ok := showPayload["identity"].(map[string]any)
			if !ok {
				t.Fatalf("expected identity payload object, got %T", showPayload["identity"])
			}
			if gotStatus, _ := identityObj["status"].(string); gotStatus != tc.expectedState {
				t.Fatalf("expected identity status %q, got %q", tc.expectedState, gotStatus)
			}
			if approvalStatus, _ := identityObj["approval_status"].(string); approvalStatus != "revoked" {
				t.Fatalf("expected approval_status=revoked, got %q", approvalStatus)
			}
		})
	}
}

func TestVerifyAndEvidenceCommands(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	if code := Run([]string{"verify", "--chain", "--state", statePath, "--json"}, &verifyOut, &verifyErr); code != 0 {
		t.Fatalf("verify failed: %d %s", code, verifyErr.String())
	}
	var verifyPayload map[string]any
	if err := json.Unmarshal(verifyOut.Bytes(), &verifyPayload); err != nil {
		t.Fatalf("parse verify payload: %v", err)
	}
	chainPayload, ok := verifyPayload["chain"].(map[string]any)
	if !ok {
		t.Fatalf("expected chain payload, got %T", verifyPayload["chain"])
	}
	if intact, _ := chainPayload["intact"].(bool); !intact {
		t.Fatalf("expected intact chain payload: %v", chainPayload)
	}
	if chainPayload["verification_mode"] != "chain_and_attestation" {
		t.Fatalf("expected attestation verification mode, got %v", chainPayload["verification_mode"])
	}
	if chainPayload["authenticity_status"] != "verified" {
		t.Fatalf("expected verified authenticity status, got %v", chainPayload["authenticity_status"])
	}

	outputDir := filepath.Join(tmp, "wrkr-evidence")
	var evidenceOut bytes.Buffer
	var evidenceErr bytes.Buffer
	if code := Run([]string{"evidence", "--frameworks", "soc2,eu-ai-act", "--state", statePath, "--output", outputDir, "--json"}, &evidenceOut, &evidenceErr); code != 0 {
		t.Fatalf("evidence failed: %d %s", code, evidenceErr.String())
	}
	var evidencePayload map[string]any
	if err := json.Unmarshal(evidenceOut.Bytes(), &evidencePayload); err != nil {
		t.Fatalf("parse evidence payload: %v", err)
	}
	if evidencePayload["status"] != "ok" {
		t.Fatalf("unexpected evidence status: %v", evidencePayload["status"])
	}
	if _, err := os.Stat(filepath.Join(outputDir, "manifest.json")); err != nil {
		t.Fatalf("expected manifest.json in evidence output: %v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "inventory.yaml")); err != nil {
		t.Fatalf("expected inventory.yaml in evidence output: %v", err)
	}
}

func TestVerifyTamperedChainReturnsExit2(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	chainPath := filepath.Join(filepath.Dir(statePath), "proof-chain.json")
	payload, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	var chain map[string]any
	if err := json.Unmarshal(payload, &chain); err != nil {
		t.Fatalf("parse chain json: %v", err)
	}
	records, ok := chain["records"].([]any)
	if !ok || len(records) == 0 {
		t.Fatalf("expected records in proof chain: %v", chain)
	}
	first, ok := records[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected record shape: %T", records[0])
	}
	integrity, ok := first["integrity"].(map[string]any)
	if !ok {
		t.Fatalf("missing integrity block in first record: %v", first)
	}
	integrity["record_hash"] = "sha256:tampered"
	mutated, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		t.Fatalf("marshal tampered chain: %v", err)
	}
	mutated = append(mutated, '\n')
	if err := os.WriteFile(chainPath, mutated, 0o600); err != nil {
		t.Fatalf("write tampered chain: %v", err)
	}

	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	code := Run([]string{"verify", "--chain", "--state", statePath, "--json"}, &verifyOut, &verifyErr)
	if code != 2 {
		t.Fatalf("expected exit 2 for tampered chain, got %d", code)
	}
	var errorPayload map[string]any
	if err := json.Unmarshal(verifyErr.Bytes(), &errorPayload); err != nil {
		t.Fatalf("parse verify error payload: %v", err)
	}
	errObject, ok := errorPayload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in verify payload: %v", errorPayload)
	}
	if errObject["code"] != "verification_failure" {
		t.Fatalf("unexpected verification error code: %v", errObject["code"])
	}
}

func TestVerifyMalformedChainReturnsExit2(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	chainPath := filepath.Join(filepath.Dir(statePath), "proof-chain.json")
	if err := os.WriteFile(chainPath, []byte("{invalid-json"), 0o600); err != nil {
		t.Fatalf("write malformed chain: %v", err)
	}

	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	code := Run([]string{"verify", "--chain", "--state", statePath, "--json"}, &verifyOut, &verifyErr)
	if code != 2 {
		t.Fatalf("expected exit 2 for malformed chain, got %d", code)
	}
	var errorPayload map[string]any
	if err := json.Unmarshal(verifyErr.Bytes(), &errorPayload); err != nil {
		t.Fatalf("parse verify error payload: %v", err)
	}
	errObject, ok := errorPayload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in verify payload: %v", errorPayload)
	}
	if errObject["code"] != "verification_failure" {
		t.Fatalf("unexpected verification error code: %v", errObject["code"])
	}
	if errObject["reason"] != "chain_parse_error" {
		t.Fatalf("unexpected malformed-chain reason: %v", errObject["reason"])
	}
	if errObject["exit_code"] != float64(2) {
		t.Fatalf("unexpected malformed-chain exit code: %v", errObject["exit_code"])
	}
}

func TestVerifyUsesStatePathVerifierKeyWhenChainPathOverrides(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	chainPath := filepath.Join(filepath.Dir(statePath), "proof-chain.json")
	payload, err := os.ReadFile(chainPath)
	if err != nil {
		t.Fatalf("read chain: %v", err)
	}
	var chain proof.Chain
	if err := json.Unmarshal(payload, &chain); err != nil {
		t.Fatalf("parse chain json: %v", err)
	}
	chain.Records[0].Event["finding_type"] = "tampered"
	rehashCLIChain(t, &chain)

	copiedDir := filepath.Join(tmp, "copied")
	if err := os.MkdirAll(copiedDir, 0o755); err != nil {
		t.Fatalf("create copied dir: %v", err)
	}
	copiedChainPath := filepath.Join(copiedDir, "proof-chain.json")
	mutated, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		t.Fatalf("marshal copied chain: %v", err)
	}
	mutated = append(mutated, '\n')
	if err := os.WriteFile(copiedChainPath, mutated, 0o600); err != nil {
		t.Fatalf("write copied chain: %v", err)
	}

	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	code := Run([]string{"verify", "--chain", "--state", statePath, "--path", copiedChainPath, "--json"}, &verifyOut, &verifyErr)
	if code != 2 {
		t.Fatalf("expected exit 2 for copied chain with stale signature, got %d stdout=%s stderr=%s", code, verifyOut.String(), verifyErr.String())
	}
	var errorPayload map[string]any
	if err := json.Unmarshal(verifyErr.Bytes(), &errorPayload); err != nil {
		t.Fatalf("parse verify error payload: %v", err)
	}
	errObject, ok := errorPayload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in verify payload: %v", errorPayload)
	}
	if errObject["code"] != "verification_failure" {
		t.Fatalf("unexpected verification error code: %v", errObject["code"])
	}
}

func TestVerifyExplicitChainPathIgnoresAmbientWRKRStatePath(t *testing.T) {
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	t.Setenv("WRKR_STATE_PATH", filepath.Join(tmp, "missing", "state.json"))
	chainPath := filepath.Join(filepath.Dir(statePath), "proof-chain.json")

	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	if code := Run([]string{"verify", "--chain", "--path", chainPath, "--json"}, &verifyOut, &verifyErr); code != 0 {
		t.Fatalf("verify failed: %d stdout=%s stderr=%s", code, verifyOut.String(), verifyErr.String())
	}

	var verifyPayload map[string]any
	if err := json.Unmarshal(verifyOut.Bytes(), &verifyPayload); err != nil {
		t.Fatalf("parse verify payload: %v", err)
	}
	chainPayload, ok := verifyPayload["chain"].(map[string]any)
	if !ok {
		t.Fatalf("expected chain payload, got %T", verifyPayload["chain"])
	}
	if chainPayload["verification_mode"] != "chain_and_attestation" {
		t.Fatalf("expected explicit --path to preserve attestation lookup, got %v", chainPayload["verification_mode"])
	}
	if chainPayload["authenticity_status"] != "verified" {
		t.Fatalf("expected explicit --path to preserve verified authenticity, got %v", chainPayload["authenticity_status"])
	}
}

func TestVerifyExplicitStateStillOverridesAmbientWRKRStatePath(t *testing.T) {
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	t.Setenv("WRKR_STATE_PATH", filepath.Join(tmp, "missing", "state.json"))

	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	if code := Run([]string{"verify", "--chain", "--state", statePath, "--json"}, &verifyOut, &verifyErr); code != 0 {
		t.Fatalf("verify failed: %d stdout=%s stderr=%s", code, verifyOut.String(), verifyErr.String())
	}

	var verifyPayload map[string]any
	if err := json.Unmarshal(verifyOut.Bytes(), &verifyPayload); err != nil {
		t.Fatalf("parse verify payload: %v", err)
	}
	chainPayload, ok := verifyPayload["chain"].(map[string]any)
	if !ok {
		t.Fatalf("expected chain payload, got %T", verifyPayload["chain"])
	}
	if chainPayload["verification_mode"] != "chain_and_attestation" {
		t.Fatalf("expected explicit --state to preserve attestation lookup, got %v", chainPayload["verification_mode"])
	}
	if chainPayload["authenticity_status"] != "verified" {
		t.Fatalf("expected explicit --state to preserve verified authenticity, got %v", chainPayload["authenticity_status"])
	}
}

func TestVerifyMissingVerifierKeyReturnsExplicitStructuralOnlyResult(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	keyPath := filepath.Join(filepath.Dir(statePath), "proof-signing-key.json")
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove signing key: %v", err)
	}

	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	if code := Run([]string{"verify", "--chain", "--state", statePath, "--json"}, &verifyOut, &verifyErr); code != 0 {
		t.Fatalf("verify failed without key: %d %s", code, verifyErr.String())
	}
	var verifyPayload map[string]any
	if err := json.Unmarshal(verifyOut.Bytes(), &verifyPayload); err != nil {
		t.Fatalf("parse verify payload: %v", err)
	}
	chainPayload, ok := verifyPayload["chain"].(map[string]any)
	if !ok {
		t.Fatalf("expected chain payload, got %T", verifyPayload["chain"])
	}
	if chainPayload["verification_mode"] != "chain_only" {
		t.Fatalf("expected chain_only verification mode, got %v", chainPayload["verification_mode"])
	}
	if chainPayload["authenticity_status"] != "unavailable" {
		t.Fatalf("expected unavailable authenticity status, got %v", chainPayload["authenticity_status"])
	}
}

func TestVerifyInvalidVerifierKeyFailsClosed(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	keyPath := filepath.Join(filepath.Dir(statePath), "proof-signing-key.json")
	if err := os.WriteFile(keyPath, []byte("{\"not\":\"a valid key file\"}\n"), 0o600); err != nil {
		t.Fatalf("write invalid signing key: %v", err)
	}

	var verifyOut bytes.Buffer
	var verifyErr bytes.Buffer
	code := Run([]string{"verify", "--chain", "--state", statePath, "--json"}, &verifyOut, &verifyErr)
	if code != 2 {
		t.Fatalf("expected exit 2 for invalid verifier key, got %d stdout=%s stderr=%s", code, verifyOut.String(), verifyErr.String())
	}
	var errorPayload map[string]any
	if err := json.Unmarshal(verifyErr.Bytes(), &errorPayload); err != nil {
		t.Fatalf("parse verify error payload: %v", err)
	}
	errObject, ok := errorPayload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object in verify payload: %v", errorPayload)
	}
	if errObject["code"] != "verification_failure" {
		t.Fatalf("unexpected verification error code: %v", errObject["code"])
	}
	if errObject["reason"] != "verifier_key_error" {
		t.Fatalf("unexpected verifier-key failure reason: %v", errObject["reason"])
	}
}

func TestVerifyInvalidCLIArgsRemainExit6(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"verify", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6 for invalid verify args, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout for invalid verify args, got %q", out.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse verify invalid-args payload: %v", err)
	}
	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object payload: %v", payload)
	}
	if errObj["code"] != "invalid_input" {
		t.Fatalf("expected invalid_input code, got %v", errObj["code"])
	}
	if errObj["exit_code"] != float64(6) {
		t.Fatalf("unexpected verify invalid-args exit code: %v", errObj["exit_code"])
	}
}

func rehashCLIChain(t *testing.T, chain *proof.Chain) {
	t.Helper()

	prev := ""
	for i := range chain.Records {
		chain.Records[i].Integrity.PreviousRecordHash = prev
		hash, err := proof.ComputeRecordHash(&chain.Records[i])
		if err != nil {
			t.Fatalf("compute record hash: %v", err)
		}
		chain.Records[i].Integrity.RecordHash = hash
		prev = hash
	}
	chain.HeadHash = prev
	chain.RecordCount = len(chain.Records)
}

func TestReportPDFCommandWritesDeterministicPDFEnvelope(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	pdfPath := filepath.Join(tmp, "report.pdf")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := Run([]string{"report", "--pdf", "--pdf-path", pdfPath, "--state", statePath, "--json"}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report --pdf failed: %d %s", code, reportErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(reportOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected report payload: %v", payload)
	}
	if payload["pdf_path"] != pdfPath {
		t.Fatalf("unexpected pdf_path value: %v", payload["pdf_path"])
	}

	pdfBytes, err := os.ReadFile(pdfPath)
	if err != nil {
		t.Fatalf("read generated pdf: %v", err)
	}
	if !bytes.HasPrefix(pdfBytes, []byte("%PDF-1.4\n")) {
		t.Fatalf("expected PDF header, got %q", string(pdfBytes[:minInt(len(pdfBytes), 16)]))
	}
}

func TestReportMarkdownPublicShareContract(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	mdPath := filepath.Join(tmp, "report-public.md")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := Run([]string{"report", "--state", statePath, "--md", "--md-path", mdPath, "--template", "public", "--share-profile", "public", "--json"}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report public markdown failed: %d %s", code, reportErr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(reportOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	if payload["md_path"] != mdPath {
		t.Fatalf("unexpected md_path: %v", payload["md_path"])
	}
	if _, err := os.Stat(mdPath); err != nil {
		t.Fatalf("expected markdown output file: %v", err)
	}
	findings, ok := payload["top_findings"].([]any)
	if !ok || len(findings) == 0 {
		t.Fatalf("expected top_findings array: %v", payload)
	}
	firstFinding, _ := findings[0].(map[string]any)
	findingPayload, _ := firstFinding["finding"].(map[string]any)
	location, _ := findingPayload["location"].(string)
	if strings.Contains(location, "/") {
		t.Fatalf("expected public share location redaction, got %q", location)
	}
}

func TestReportRejectsInvalidTemplateAndShareProfile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed to seed state: %d", code)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"report", "--state", statePath, "--template", "unknown", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6 for invalid template, got %d", code)
	}

	out.Reset()
	errOut.Reset()
	code = Run([]string{"report", "--state", statePath, "--share-profile", "external", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6 for invalid share profile, got %d", code)
	}
}

func TestManifestGenerateCreatesUnderReviewBaseline(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	manifestPath := filepath.Join(tmp, "generated-manifest.yaml")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(scanOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	inventoryPayload, ok := payload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("expected inventory payload, got %T", payload["inventory"])
	}
	tools, ok := inventoryPayload["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatalf("expected non-empty inventory tools")
	}
	firstTool, ok := tools[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected tool payload: %T", tools[0])
	}
	agentID, _ := firstTool["agent_id"].(string)
	if agentID == "" {
		t.Fatalf("missing agent_id in inventory tool: %v", firstTool)
	}

	var approveOut bytes.Buffer
	var approveErr bytes.Buffer
	if code := Run([]string{"identity", "approve", agentID, "--approver", "@maria", "--scope", "read-only", "--expires", "90d", "--state", statePath, "--json"}, &approveOut, &approveErr); code != 0 {
		t.Fatalf("identity approve failed: %d %s", code, approveErr.String())
	}

	var manifestOut bytes.Buffer
	var manifestErr bytes.Buffer
	if code := Run([]string{"manifest", "generate", "--state", statePath, "--output", manifestPath, "--json"}, &manifestOut, &manifestErr); code != 0 {
		t.Fatalf("manifest generate failed: %d %s", code, manifestErr.String())
	}

	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read generated manifest: %v", err)
	}
	var generated struct {
		Identities []struct {
			Status        string `yaml:"status"`
			ApprovalState string `yaml:"approval_status"`
		} `yaml:"identities"`
	}
	if err := yaml.Unmarshal(manifestBytes, &generated); err != nil {
		t.Fatalf("parse generated manifest yaml: %v", err)
	}
	if len(generated.Identities) == 0 {
		t.Fatal("expected manifest identities")
	}
	for _, record := range generated.Identities {
		if record.Status != "under_review" {
			t.Fatalf("expected under_review status, got %q", record.Status)
		}
		if record.ApprovalState != "missing" {
			t.Fatalf("expected missing approval status, got %q", record.ApprovalState)
		}
	}
}

func TestEvidenceCommandClassifiesMissingStateAsRuntimeFailure(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "missing-state.json")
	outputDir := filepath.Join(tmp, "output")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"evidence", "--frameworks", "soc2", "--state", statePath, "--output", outputDir, "--json"}, &out, &errOut)
	if code != 1 {
		t.Fatalf("expected exit 1, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on runtime error, got %q", out.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse evidence error payload: %v", err)
	}
	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object payload: %v", payload)
	}
	if errObj["code"] != "runtime_failure" {
		t.Fatalf("unexpected error code: %v", errObj["code"])
	}
	if errObj["exit_code"] != float64(1) {
		t.Fatalf("unexpected error exit code: %v", errObj["exit_code"])
	}
}

func TestEvidenceCommandClassifiesUnknownFrameworkAsInvalidInput(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	outputDir := filepath.Join(tmp, "output")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"evidence", "--frameworks", "unknown-framework", "--state", statePath, "--output", outputDir, "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on invalid input error, got %q", out.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse evidence error payload: %v", err)
	}
	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object payload: %v", payload)
	}
	if errObj["code"] != "invalid_input" {
		t.Fatalf("unexpected error code: %v", errObj["code"])
	}
	if errObj["exit_code"] != float64(6) {
		t.Fatalf("unexpected error exit code: %v", errObj["exit_code"])
	}
}

func TestEvidenceCommandRetainsUnsafePathAsExit8(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	outputDir := filepath.Join(tmp, "unsafe-output")
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		t.Fatalf("mkdir output dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "not-managed.txt"), []byte("do-not-delete"), 0o600); err != nil {
		t.Fatalf("write non-managed file: %v", err)
	}

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d %s", code, scanErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"evidence", "--frameworks", "soc2", "--state", statePath, "--output", outputDir, "--json"}, &out, &errOut)
	if code != 8 {
		t.Fatalf("expected exit 8, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on unsafe path error, got %q", out.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse evidence error payload: %v", err)
	}
	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object payload: %v", payload)
	}
	if errObj["code"] != "unsafe_operation_blocked" {
		t.Fatalf("unexpected error code: %v", errObj["code"])
	}
	if errObj["exit_code"] != float64(8) {
		t.Fatalf("unexpected error exit code: %v", errObj["exit_code"])
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
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
