package githubpre2e

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/github/pr"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestE2EPRUpsertIdempotentWithSimulatedAPI(t *testing.T) {
	t.Parallel()

	var storedBody string
	var headExists bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/git/ref/heads/wrkr-bot/remediation/backend/weekly/abc123"):
			if !headExists {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"Not Found"}`))
				return
			}
			_, _ = w.Write([]byte(`{"object":{"sha":"head-sha"}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
			_, _ = w.Write([]byte(`{"object":{"sha":"base-sha"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			headExists = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ref":"refs/heads/wrkr-bot/remediation/backend/weekly/abc123"}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pulls"):
			if storedBody == "" {
				_, _ = w.Write([]byte(`[]`))
				return
			}
			_, _ = w.Write([]byte(`[{"number":42,"html_url":"https://example/pr/42","title":"wrkr remediation","body":` + jsonString(storedBody) + `,"head":{"ref":"wrkr-bot/remediation/backend/weekly/abc123"},"base":{"ref":"main"}}]`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			var payload struct {
				Body string `json:"body"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			storedBody = payload.Body
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"number":42,"html_url":"https://example/pr/42","title":"wrkr remediation","body":` + jsonString(storedBody) + `,"head":{"ref":"wrkr-bot/remediation/backend/weekly/abc123"},"base":{"ref":"main"}}`))
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/pulls/"):
			var payload struct {
				Body string `json:"body"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			storedBody = payload.Body
			_, _ = w.Write([]byte(`{"number":42,"html_url":"https://example/pr/42","title":"wrkr remediation","body":` + jsonString(storedBody) + `,"head":{"ref":"wrkr-bot/remediation/backend/weekly/abc123"},"base":{"ref":"main"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client := pr.NewGitHubClient(server.URL, "token", server.Client())
	input := pr.UpsertInput{
		Owner:       "acme",
		Repo:        "backend",
		HeadBranch:  "wrkr-bot/remediation/backend/weekly/abc123",
		BaseBranch:  "main",
		Title:       "wrkr remediation",
		Body:        "summary",
		Fingerprint: "abc123",
	}

	first, err := pr.Upsert(context.Background(), client, input)
	if err != nil {
		t.Fatalf("first upsert failed: %v", err)
	}
	if first.Action != "created" {
		t.Fatalf("expected created action, got %q", first.Action)
	}

	second, err := pr.Upsert(context.Background(), client, input)
	if err != nil {
		t.Fatalf("second upsert failed: %v", err)
	}
	if second.Action != "noop" {
		t.Fatalf("expected noop on identical rerun, got %q", second.Action)
	}
}

func TestE2EFixOpenPRFailsClosedWithScanOnlyToken(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	configPath := filepath.Join(tmp, "config.json")

	cfg := config.Default()
	cfg.DefaultTarget = config.Target{Mode: config.TargetRepo, Value: "acme/backend"}
	cfg.Auth.Scan.Token = "scan-token-only"
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	snapshot := state.Snapshot{
		Version: state.SnapshotVersion,
		Target:  source.Target{Mode: "repo", Value: "acme/backend"},
		Findings: []model.Finding{
			{FindingType: "policy_violation", RuleID: "WRKR-004", Severity: model.SeverityHigh, ToolType: "ci", Location: ".github/workflows/pr.yml", Repo: "backend", Org: "acme"},
		},
		RiskReport: &risk.Report{Ranked: []risk.ScoredFinding{{Score: 9.8, Finding: model.Finding{FindingType: "policy_violation", RuleID: "WRKR-004", Severity: model.SeverityHigh, ToolType: "ci", Location: ".github/workflows/pr.yml", Repo: "backend", Org: "acme"}}}},
	}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"fix", "--state", statePath, "--config", configPath, "--open-pr", "--repo", "acme/backend", "--json"}, &out, &errOut)
	if code != 4 {
		t.Fatalf("expected exit 4 for scan-only token, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errorObj, ok := payload["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error object, got %v", payload)
	}
	if errorObj["code"] != "approval_required" {
		t.Fatalf("expected approval_required code, got %v", errorObj["code"])
	}
}

func jsonString(in string) string {
	blob, _ := json.Marshal(in)
	return string(blob)
}
