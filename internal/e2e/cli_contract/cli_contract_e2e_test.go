package clicontracte2e

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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
