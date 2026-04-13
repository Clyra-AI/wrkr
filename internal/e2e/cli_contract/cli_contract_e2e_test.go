package clicontracte2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestE2EScanQuietJSONRemainsMachineReadable(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	statePath := filepath.Join(tmp, "state.json")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir repo fixture: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"scan", "--path", reposPath, "--quiet", "--json", "--state", statePath}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected scan payload: %v", payload)
	}
}

func TestE2ECLIParseErrorsRemainJSONForFlagOrderingVariants(t *testing.T) {
	t.Parallel()

	cases := [][]string{
		{"--json", "--bad-flag"},
		{"--bad-flag", "--json"},
	}

	for _, args := range cases {
		args := args
		t.Run(args[0], func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			var errOut bytes.Buffer
			code := cli.Run(args, &out, &errOut)
			if code != 6 {
				t.Fatalf("expected exit 6, got %d for args=%v", code, args)
			}
			if out.Len() != 0 {
				t.Fatalf("expected no stdout on parse error, got %q", out.String())
			}
			var payload map[string]any
			if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
				t.Fatalf("expected JSON error output, got %q (%v)", errOut.String(), err)
			}
			errObj, ok := payload["error"].(map[string]any)
			if !ok {
				t.Fatalf("missing error payload: %v", payload)
			}
			if errObj["code"] != "invalid_input" {
				t.Fatalf("unexpected error code: %v", errObj["code"])
			}
		})
	}
}

func TestE2EHelpContractMatrixReturnsExit0(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
	}{
		{name: "root", args: []string{"--help"}},
		{name: "init", args: []string{"init", "--help"}},
		{name: "scan", args: []string{"scan", "--help"}},
		{name: "evidence", args: []string{"evidence", "--help"}},
		{name: "regress run", args: []string{"regress", "run", "--help"}},
		{name: "report", args: []string{"report", "--help"}},
		{name: "verify", args: []string{"verify", "--help"}},
		{name: "fix", args: []string{"fix", "--help"}},
		{name: "lifecycle", args: []string{"lifecycle", "--help"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out bytes.Buffer
			var errOut bytes.Buffer
			code := cli.Run(tc.args, &out, &errOut)
			if code != 0 {
				t.Fatalf("expected exit 0 for %v, got %d (stderr=%q)", tc.args, code, errOut.String())
			}
		})
	}
}

func TestE2EIdentityTransitionWithoutReasonUsesDeterministicDefaultReason(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	reposPath := filepath.Join(tmp, "repos")
	statePath := filepath.Join(tmp, "state.json")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir repo fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reposPath, "alpha", "AGENTS.md"), []byte("alpha agent instructions\n"), 0o600); err != nil {
		t.Fatalf("write AGENTS.md fixture: %v", err)
	}

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}
	var scanPayload map[string]any
	if err := json.Unmarshal(scanOut.Bytes(), &scanPayload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	inventoryObj, ok := scanPayload["inventory"].(map[string]any)
	if !ok {
		t.Fatalf("missing inventory payload: %v", scanPayload)
	}
	tools, ok := inventoryObj["tools"].([]any)
	if !ok || len(tools) == 0 {
		t.Fatalf("missing inventory tools payload: %v", inventoryObj)
	}
	firstTool, ok := tools[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected tool payload type: %T", tools[0])
	}
	agentID, _ := firstTool["agent_id"].(string)
	if agentID == "" {
		t.Fatalf("missing agent_id in tool payload: %v", firstTool)
	}
	if firstTool["discovery_method"] != "static" {
		t.Fatalf("missing discovery_method=static in tool payload: %v", firstTool)
	}

	var approveOut bytes.Buffer
	var approveErr bytes.Buffer
	if code := cli.Run([]string{"identity", "approve", agentID, "--approver", "@qa", "--scope", "contract", "--expires", "90d", "--state", statePath, "--json"}, &approveOut, &approveErr); code != 0 {
		t.Fatalf("approve failed: %d (%s)", code, approveErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run([]string{"identity", "revoke", agentID, "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("revoke failed: %d (%s)", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse revoke payload: %v", err)
	}
	transition, ok := payload["transition"].(map[string]any)
	if !ok {
		t.Fatalf("missing transition payload: %v", payload)
	}
	diffObj, ok := transition["diff"].(map[string]any)
	if !ok {
		t.Fatalf("missing transition diff: %v", transition)
	}
	if diffObj["reason"] != "manual_transition_revoked" {
		t.Fatalf("unexpected default reason: %v", diffObj["reason"])
	}
}

func TestE2EMySetupActivationProjectionRemainsAdditive(t *testing.T) {
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

	statePath := filepath.Join(t.TempDir(), "state.json")
	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--my-setup", "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}
	var scanPayload map[string]any
	if err := json.Unmarshal(scanOut.Bytes(), &scanPayload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	activation, ok := scanPayload["activation"].(map[string]any)
	if !ok {
		t.Fatalf("missing activation payload: %v", scanPayload)
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
			t.Fatalf("policy findings must not appear in activation items: %v", items)
		}
	}
	topFindings, ok := scanPayload["top_findings"].([]any)
	if !ok || len(topFindings) == 0 {
		t.Fatalf("expected raw top_findings to remain available: %v", scanPayload["top_findings"])
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	if code := cli.Run([]string{"report", "--state", statePath, "--json"}, &reportOut, &reportErr); code != 0 {
		t.Fatalf("report failed: %d (%s)", code, reportErr.String())
	}
	var reportPayload map[string]any
	if err := json.Unmarshal(reportOut.Bytes(), &reportPayload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("missing summary payload: %v", reportPayload)
	}
	if _, ok := summary["activation"].(map[string]any); !ok {
		t.Fatalf("expected additive activation summary: %v", summary)
	}
}

func TestE2EOrgJSONProgressStaysOnStderr(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"}]`)
		case "/repos/acme/a":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/a","default_branch":"main"}`)
		case "/repos/acme/a/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[]}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	statePath := filepath.Join(t.TempDir(), "state.json")
	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := cli.Run([]string{
		"scan",
		"--org", "acme",
		"--github-api", server.URL,
		"--state", statePath,
		"--json",
	}, &out, &errOut); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse scan payload: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected scan payload: %v", payload)
	}
	if strings.Contains(out.String(), "progress target=org") {
		t.Fatalf("expected progress output to stay off stdout, got %q", out.String())
	}
	if !strings.Contains(errOut.String(), "progress target=org org=acme event=complete repo_total=1 completed=1 failed=0") {
		t.Fatalf("expected stderr completion progress, got %q", errOut.String())
	}
}
