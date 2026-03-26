package githubpre2e

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/cli"
	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/github/pr"
	"github.com/Clyra-AI/wrkr/core/manifest"
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

func TestE2EFixApplyOpenPRWritesRealRepoFileDiff(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	configPath := filepath.Join(tmp, "config.json")

	cfg := config.Default()
	cfg.DefaultTarget = config.Target{Mode: config.TargetRepo, Value: "acme/backend"}
	cfg.Auth.Scan.Token = "scan-read-token"
	cfg.Auth.Fix.Token = "fix-write-token"
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	snapshot := applyStateFixture()
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}

	server, api := newFixGitHubAPIServer(t)
	defer server.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"fix", "--state", statePath, "--config", configPath, "--apply", "--open-pr", "--repo", "acme/backend", "--github-api", server.URL, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected success, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if payload["mode"] != "apply" {
		t.Fatalf("expected mode=apply, got %v", payload["mode"])
	}
	if len(api.filesByBranch) != 1 {
		t.Fatalf("expected one branch with files, got %v", api.filesByBranch)
	}
	for _, files := range api.filesByBranch {
		if _, ok := files[".wrkr/wrkr-manifest.yaml"]; !ok {
			t.Fatalf("expected apply manifest file in branch contents, got %v", files)
		}
	}
}

func TestE2EFixOpenPRMaxPRsCreatesDeterministicGroups(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	configPath := filepath.Join(tmp, "config.json")

	cfg := config.Default()
	cfg.DefaultTarget = config.Target{Mode: config.TargetRepo, Value: "acme/backend"}
	cfg.Auth.Scan.Token = "scan-read-token"
	cfg.Auth.Fix.Token = "fix-write-token"
	if err := config.Save(configPath, cfg); err != nil {
		t.Fatalf("save config: %v", err)
	}

	snapshot := previewStateFixture()
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}

	server, api := newFixGitHubAPIServer(t)
	defer server.Close()

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"fix", "--state", statePath, "--config", configPath, "--open-pr", "--max-prs", "2", "--repo", "acme/backend", "--github-api", server.URL, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected success, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	prs, ok := payload["pull_requests"].([]any)
	if !ok || len(prs) != 2 {
		t.Fatalf("expected two pull_requests, got %v", payload["pull_requests"])
	}
	if len(api.pullRequests) != 2 {
		t.Fatalf("expected two created PRs, got %v", api.pullRequests)
	}
}

func jsonString(in string) string {
	blob, _ := json.Marshal(in)
	return string(blob)
}

type fixGitHubAPI struct {
	heads         map[string]bool
	filesByBranch map[string]map[string]string
	pullRequests  map[string]pr.PullRequest
	nextPR        int
}

func newFixGitHubAPIServer(t *testing.T) (*httptest.Server, *fixGitHubAPI) {
	t.Helper()

	api := &fixGitHubAPI{
		heads:         map[string]bool{},
		filesByBranch: map[string]map[string]string{},
		pullRequests:  map[string]pr.PullRequest{},
		nextPR:        40,
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
			_, _ = w.Write([]byte(`{"object":{"sha":"base-sha"}}`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/git/ref/heads/"):
			branch := strings.TrimPrefix(r.URL.Path, "/repos/acme/backend/git/ref/heads/")
			if !api.heads[branch] {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"Not Found"}`))
				return
			}
			_, _ = w.Write([]byte(`{"object":{"sha":"head-sha"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			var payload struct {
				Ref string `json:"ref"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			api.heads[strings.TrimPrefix(payload.Ref, "refs/heads/")] = true
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"ref":"` + payload.Ref + `"}`))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/contents/"):
			branch := r.URL.Query().Get("ref")
			filePath := strings.TrimPrefix(r.URL.Path, "/repos/acme/backend/contents/")
			files := api.filesByBranch[branch]
			content, ok := files[filePath]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"message":"Not Found"}`))
				return
			}
			encoded := base64.StdEncoding.EncodeToString([]byte(content))
			_, _ = w.Write([]byte(`{"sha":"sha-` + filePath + `","encoding":"base64","content":"` + encoded + `"}`))
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/contents/"):
			filePath := strings.TrimPrefix(r.URL.Path, "/repos/acme/backend/contents/")
			var payload struct {
				Branch  string `json:"branch"`
				Content string `json:"content"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			decoded, err := base64.StdEncoding.DecodeString(payload.Content)
			if err != nil {
				t.Fatalf("decode contents payload: %v", err)
			}
			if api.filesByBranch[payload.Branch] == nil {
				api.filesByBranch[payload.Branch] = map[string]string{}
			}
			api.filesByBranch[payload.Branch][filePath] = string(decoded)
			_, _ = w.Write([]byte(`{"content":{"path":"` + filePath + `"}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pulls"):
			branch := strings.TrimPrefix(r.URL.Query().Get("head"), "acme:")
			if item, ok := api.pullRequests[branch]; ok {
				_, _ = w.Write([]byte(`[{"number":` + strconv.Itoa(item.Number) + `,"html_url":` + jsonString(item.URL) + `,"title":` + jsonString(item.Title) + `,"body":` + jsonString(item.Body) + `,"head":{"ref":` + jsonString(item.Head) + `},"base":{"ref":` + jsonString(item.Base) + `}}]`))
				return
			}
			_, _ = w.Write([]byte(`[]`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			var payload struct {
				Title string `json:"title"`
				Head  string `json:"head"`
				Base  string `json:"base"`
				Body  string `json:"body"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			api.nextPR++
			item := pr.PullRequest{
				Number: api.nextPR,
				URL:    "https://example/pr/" + strconv.Itoa(api.nextPR),
				Title:  payload.Title,
				Body:   payload.Body,
				Head:   payload.Head,
				Base:   payload.Base,
			}
			api.pullRequests[payload.Head] = item
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"number":` + strconv.Itoa(item.Number) + `,"html_url":` + jsonString(item.URL) + `,"title":` + jsonString(item.Title) + `,"body":` + jsonString(item.Body) + `,"head":{"ref":` + jsonString(item.Head) + `},"base":{"ref":` + jsonString(item.Base) + `}}`))
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/pulls/"):
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/repos/acme/backend/pulls/"), "/")
			number, _ := strconv.Atoi(parts[0])
			var payload struct {
				Title string `json:"title"`
				Body  string `json:"body"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			for branch, item := range api.pullRequests {
				if item.Number == number {
					item.Title = payload.Title
					item.Body = payload.Body
					api.pullRequests[branch] = item
					_, _ = w.Write([]byte(`{"number":` + strconv.Itoa(item.Number) + `,"html_url":` + jsonString(item.URL) + `,"title":` + jsonString(item.Title) + `,"body":` + jsonString(item.Body) + `,"head":{"ref":` + jsonString(item.Head) + `},"base":{"ref":` + jsonString(item.Base) + `}}`))
					return
				}
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	return server, api
}

func applyStateFixture() state.Snapshot {
	now := "2026-03-26T12:00:00Z"
	return state.Snapshot{
		Version: state.SnapshotVersion,
		Target:  source.Target{Mode: "repo", Value: "acme/backend"},
		Findings: []model.Finding{
			{FindingType: "tool_config", Severity: model.SeverityMedium, ToolType: "codex", Location: ".codex/config.toml", Repo: "backend", Org: "acme"},
		},
		RiskReport: &risk.Report{
			GeneratedAt: now,
			Ranked: []risk.ScoredFinding{
				{Score: 7.7, Finding: model.Finding{FindingType: "tool_config", Severity: model.SeverityMedium, ToolType: "codex", Location: ".codex/config.toml", Repo: "backend", Org: "acme"}},
			},
		},
		Inventory: &agginventory.Inventory{
			Org: "acme",
			Tools: []agginventory.Tool{
				{
					ToolID:          "codex-config",
					AgentID:         "wrkr:codex-config:acme",
					ToolType:        "codex",
					Org:             "acme",
					DiscoveryMethod: "static",
					EndpointClass:   "fs.read",
					DataClass:       "source_code",
					AutonomyLevel:   "interactive",
					RiskScore:       7.7,
					ApprovalStatus:  "missing",
					ApprovalClass:   "under_review",
					LifecycleState:  "discovered",
					Locations: []agginventory.ToolLocation{
						{Repo: "backend", Location: ".codex/config.toml"},
					},
				},
			},
		},
		Identities: []manifest.IdentityRecord{
			{
				AgentID:       "wrkr:codex-config:acme",
				ToolID:        "codex-config",
				ToolType:      "codex",
				Org:           "acme",
				Repo:          "backend",
				Location:      ".codex/config.toml",
				Status:        "discovered",
				ApprovalState: "missing",
				FirstSeen:     now,
				LastSeen:      now,
				Present:       true,
				DataClass:     "source_code",
				EndpointClass: "fs.read",
				AutonomyLevel: "interactive",
				RiskScore:     7.7,
			},
		},
	}
}

func previewStateFixture() state.Snapshot {
	return state.Snapshot{
		Version: state.SnapshotVersion,
		Target:  source.Target{Mode: "repo", Value: "acme/backend"},
		Findings: []model.Finding{
			{FindingType: "policy_violation", RuleID: "WRKR-004", Severity: model.SeverityHigh, ToolType: "ci", Location: ".github/workflows/pr.yml", Repo: "backend", Org: "acme"},
			{FindingType: "skill_policy_conflict", Severity: model.SeverityHigh, ToolType: "skill", Location: ".agents/skills/release/SKILL.md", Repo: "backend", Org: "acme"},
			{FindingType: "mcp_server", Severity: model.SeverityMedium, ToolType: "mcp", Location: ".codex/config.toml", Repo: "backend", Org: "acme"},
		},
		RiskReport: &risk.Report{
			Ranked: []risk.ScoredFinding{
				{Score: 9.9, Finding: model.Finding{FindingType: "policy_violation", RuleID: "WRKR-004", Severity: model.SeverityHigh, ToolType: "ci", Location: ".github/workflows/pr.yml", Repo: "backend", Org: "acme"}},
				{Score: 9.4, Finding: model.Finding{FindingType: "skill_policy_conflict", Severity: model.SeverityHigh, ToolType: "skill", Location: ".agents/skills/release/SKILL.md", Repo: "backend", Org: "acme"}},
				{Score: 8.7, Finding: model.Finding{FindingType: "mcp_server", Severity: model.SeverityMedium, ToolType: "mcp", Location: ".codex/config.toml", Repo: "backend", Org: "acme"}},
			},
		},
	}
}
