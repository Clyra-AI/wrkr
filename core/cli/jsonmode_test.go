package cli

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestSharedJSONModeParsingCases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		args []string
		want bool
	}{
		{name: "explicit json flag", args: []string{"--json"}, want: true},
		{name: "json true", args: []string{"--json=true"}, want: true},
		{name: "json false", args: []string{"--json=false"}, want: false},
		{name: "malformed bool falls back to json errors", args: []string{"--json=maybe"}, want: true},
		{name: "no json flag", args: []string{"scan", "--path", "."}, want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := wantsJSONOutput(tc.args); got != tc.want {
				t.Fatalf("wantsJSONOutput(%v)=%v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestMalformedJSONModeFlagEmitsJSONErrorsAcrossCommands(t *testing.T) {
	t.Parallel()

	commands := [][]string{
		{"--json=maybe", "--nope"},
		{"scan", "--json=maybe", "--path"},
	}

	for _, cmd := range commands {
		var out bytes.Buffer
		var errOut bytes.Buffer
		code := Run(cmd, &out, &errOut)
		if code != exitInvalidInput {
			t.Fatalf("expected exit %d for %v, got %d", exitInvalidInput, cmd, code)
		}
		var payload map[string]any
		if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
			t.Fatalf("expected JSON error payload for %v, got %q (%v)", cmd, errOut.String(), err)
		}
	}
}
