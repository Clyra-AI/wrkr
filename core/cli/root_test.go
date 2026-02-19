package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
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
	if _, ok := payload["error"]; !ok {
		t.Fatalf("expected error object in payload, got %v", payload)
	}
}

func TestRunInvalidFlagWithJSONFirstReturnsMachineReadableError(t *testing.T) {
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
	if _, ok := payload["error"]; !ok {
		t.Fatalf("expected error object in payload, got %v", payload)
	}
}
