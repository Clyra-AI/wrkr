package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestActionPRModeJSON(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"action", "pr-mode",
		"--changed-paths", "README.md,.codex/config.toml",
		"--risk-delta", "6.2",
		"--compliance-delta", "-1.4",
		"--block-threshold", "6.0",
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("action pr-mode failed: %d (%s)", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if payload["should_comment"] != true {
		t.Fatalf("expected should_comment=true, got %v", payload["should_comment"])
	}
	if payload["block_merge"] != true {
		t.Fatalf("expected block_merge=true, got %v", payload["block_merge"])
	}
}

func TestActionPRCommentSkipsDocsOnlyWithoutToken(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"action", "pr-comment",
		"--changed-paths", "README.md,docs/usage.md",
		"--risk-delta", "2.0",
		"--compliance-delta", "0.0",
		"--owner", "acme",
		"--repo", "backend",
		"--pr-number", "12",
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected docs-only pr-comment to succeed without token, got code=%d stderr=%s", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if payload["published"] != false {
		t.Fatalf("expected published=false for docs-only change, got %v", payload["published"])
	}
}

func TestActionPRCommentPublishesIdempotently(t *testing.T) {
	t.Parallel()

	commentBody := ""
	commentID := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/backend/issues/12/comments":
			if commentID == 0 {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			_, _ = w.Write([]byte(`[{"id":7,"body":` + jsonString(t, commentBody) + `}]`))
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/backend/issues/12/comments":
			var payload struct {
				Body string `json:"body"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			commentBody = payload.Body
			commentID = 7
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":7,"body":` + jsonString(t, commentBody) + `}`))
		case r.Method == http.MethodPatch && r.URL.Path == "/repos/acme/backend/issues/comments/7":
			var payload struct {
				Body string `json:"body"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			commentBody = payload.Body
			_, _ = w.Write([]byte(`{"id":7,"body":` + jsonString(t, commentBody) + `}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	run := func() map[string]any {
		var out bytes.Buffer
		var errOut bytes.Buffer
		code := Run([]string{
			"action", "pr-comment",
			"--changed-paths", ".codex/config.toml",
			"--risk-delta", "1.2",
			"--compliance-delta", "-0.5",
			"--owner", "acme",
			"--repo", "backend",
			"--pr-number", "12",
			"--github-api", server.URL,
			"--github-token", "token",
			"--fingerprint", "wrkr-action-pr-mode-v1",
			"--json",
		}, &out, &errOut)
		if code != 0 {
			t.Fatalf("action pr-comment failed: %d (%s)", code, errOut.String())
		}
		var payload map[string]any
		if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
			t.Fatalf("parse payload: %v", err)
		}
		return payload
	}

	first := run()
	if first["comment_action"] != "created" {
		t.Fatalf("expected first action=created, got %v", first["comment_action"])
	}
	second := run()
	if second["comment_action"] != "noop" {
		t.Fatalf("expected second action=noop, got %v", second["comment_action"])
	}
}

func jsonString(t *testing.T, value string) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json string: %v", err)
	}
	return string(payload)
}
