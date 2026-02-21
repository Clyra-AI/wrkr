package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestStory5SchemasPresent(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	required := []string{
		"schemas/v1/cli/command-envelope.schema.json",
		"schemas/v1/regress/regress-baseline.schema.json",
		"schemas/v1/regress/regress-result.schema.json",
	}
	for _, rel := range required {
		if _, err := os.Stat(filepath.Join(repoRoot, rel)); err != nil {
			t.Fatalf("expected schema %s: %v", rel, err)
		}
	}
}

func TestRootInvalidFlagOrderingJSONContract(t *testing.T) {
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
				t.Fatalf("expected no stdout, got %q", out.String())
			}

			var payload map[string]any
			if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
				t.Fatalf("parse JSON error envelope: %v (%q)", err, errOut.String())
			}
			errObj, ok := payload["error"].(map[string]any)
			if !ok {
				t.Fatalf("missing error object: %v", payload)
			}
			if errObj["code"] != "invalid_input" {
				t.Fatalf("unexpected error code: %v", errObj["code"])
			}
			if errObj["exit_code"] != float64(6) {
				t.Fatalf("unexpected error exit code: %v", errObj["exit_code"])
			}
		})
	}
}

func TestUnsupportedCommandExitCodeContract(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"not-a-command", "--json"}, &out, &errOut)
	if code != 6 {
		t.Fatalf("expected exit 6, got %d", code)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout, got %q", out.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse JSON error envelope: %v (%q)", err, errOut.String())
	}
	errObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("missing error object: %v", payload)
	}
	if errObj["code"] != "invalid_input" {
		t.Fatalf("unexpected error code: %v", errObj["code"])
	}
	if errObj["exit_code"] != float64(6) {
		t.Fatalf("unexpected error exit code: %v", errObj["exit_code"])
	}
}

func TestRegressDriftExitCodeContract(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	baselinePath := filepath.Join(tmp, "baseline.json")
	reposPath := filepath.Join(tmp, "repos")
	if err := os.MkdirAll(filepath.Join(reposPath, "alpha"), 0o755); err != nil {
		t.Fatalf("mkdir alpha fixture: %v", err)
	}

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	var initOut bytes.Buffer
	var initErr bytes.Buffer
	if code := cli.Run([]string{"regress", "init", "--baseline", statePath, "--output", baselinePath, "--json"}, &initOut, &initErr); code != 0 {
		t.Fatalf("regress init failed: %d (%s)", code, initErr.String())
	}

	if err := os.MkdirAll(filepath.Join(reposPath, "beta"), 0o755); err != nil {
		t.Fatalf("mkdir beta fixture: %v", err)
	}
	scanOut.Reset()
	scanErr.Reset()
	if code := cli.Run([]string{"scan", "--path", reposPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("second scan failed: %d (%s)", code, scanErr.String())
	}

	var runOut bytes.Buffer
	var runErr bytes.Buffer
	code := cli.Run([]string{"regress", "run", "--baseline", baselinePath, "--state", statePath, "--json"}, &runOut, &runErr)
	if code != 5 {
		t.Fatalf("expected drift exit 5, got %d (%s)", code, runErr.String())
	}
	if runErr.Len() != 0 {
		t.Fatalf("expected JSON drift payload on stdout only, got stderr=%q", runErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(runOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse regress payload: %v", err)
	}
	if payload["status"] != "drift" {
		t.Fatalf("expected status=drift, got %v", payload["status"])
	}
	if payload["drift_detected"] != true {
		t.Fatalf("expected drift_detected=true, got %v", payload["drift_detected"])
	}
}
