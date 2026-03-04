package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestVersionCommandHumanAndJSON(t *testing.T) {
	t.Parallel()

	var humanOut bytes.Buffer
	var humanErr bytes.Buffer
	if code := Run([]string{"version"}, &humanOut, &humanErr); code != 0 {
		t.Fatalf("version command failed: code=%d stderr=%q", code, humanErr.String())
	}
	if !strings.HasPrefix(strings.TrimSpace(humanOut.String()), "wrkr ") {
		t.Fatalf("unexpected human version output: %q", humanOut.String())
	}

	var jsonOut bytes.Buffer
	var jsonErr bytes.Buffer
	if code := Run([]string{"version", "--json"}, &jsonOut, &jsonErr); code != 0 {
		t.Fatalf("version --json failed: code=%d stderr=%q", code, jsonErr.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(jsonOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse version json: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected status: %v", payload["status"])
	}
	if strings.TrimSpace(payload["version"].(string)) == "" {
		t.Fatalf("expected non-empty version in payload: %v", payload)
	}
}

func TestRootVersionFlag(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"--version"}, &out, &errOut); code != 0 {
		t.Fatalf("--version failed: code=%d stderr=%q", code, errOut.String())
	}
	if !strings.HasPrefix(strings.TrimSpace(out.String()), "wrkr ") {
		t.Fatalf("unexpected --version output: %q", out.String())
	}

	out.Reset()
	errOut.Reset()
	if code := Run([]string{"--version", "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("--version --json failed: code=%d stderr=%q", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse --version --json output: %v", err)
	}
	if payload["status"] != "ok" {
		t.Fatalf("unexpected status: %v", payload["status"])
	}
	if strings.TrimSpace(payload["version"].(string)) == "" {
		t.Fatalf("expected non-empty version in payload: %v", payload)
	}
}
