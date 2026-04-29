package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAcquireRepoRequiresBaseURL(t *testing.T) {
	t.Parallel()

	connector := NewConnector("", "", nil)
	if _, err := connector.AcquireRepo(context.Background(), "acme/backend"); err == nil {
		t.Fatal("expected missing base URL to fail")
	}
}

func TestListOrgReposIntegrationSimulatedAPI(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/acme/repos" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_, _ = fmt.Fprint(w, `[{"full_name":"acme/a"},{"name":"b"}]`)
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "test-token", server.Client())
	repos, err := connector.ListOrgRepos(context.Background(), "acme")
	if err != nil {
		t.Fatalf("list org repos: %v", err)
	}
	if len(repos) != 2 || repos[0] != "acme/a" || repos[1] != "acme/b" {
		t.Fatalf("unexpected repos: %v", repos)
	}
}

func TestListOrgReposPaginatesDeterministically(t *testing.T) {
	t.Parallel()

	var pages []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/acme/repos" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		page := r.URL.Query().Get("page")
		if page == "" {
			page = "1"
		}
		pages = append(pages, page)
		if r.URL.Query().Get("per_page") != "100" {
			t.Fatalf("expected per_page=100, got %q", r.URL.Query().Get("per_page"))
		}
		switch page {
		case "1":
			items := make([]map[string]string, 0, 100)
			for i := 99; i >= 0; i-- {
				items = append(items, map[string]string{"full_name": fmt.Sprintf("acme/repo-%03d", i)})
			}
			_ = json.NewEncoder(w).Encode(items)
		case "2":
			_ = json.NewEncoder(w).Encode([]map[string]string{
				{"full_name": "acme/repo-050"},
				{"name": "addon"},
			})
		default:
			t.Fatalf("unexpected page request: %s", page)
		}
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	repos, err := connector.ListOrgRepos(context.Background(), "acme")
	if err != nil {
		t.Fatalf("list org repos: %v", err)
	}
	if len(pages) != 2 || pages[0] != "1" || pages[1] != "2" {
		t.Fatalf("expected deterministic paging [1,2], got %v", pages)
	}

	if len(repos) != 101 {
		t.Fatalf("expected 101 deduplicated repos, got %d", len(repos))
	}
	expected := append([]string{}, repos...)
	sort.Strings(expected)
	if strings.Join(expected, ",") != strings.Join(repos, ",") {
		t.Fatalf("expected sorted deterministic output, got %v", repos)
	}
	if repos[0] != "acme/addon" || repos[len(repos)-1] != "acme/repo-099" {
		t.Fatalf("unexpected boundaries: first=%s last=%s", repos[0], repos[len(repos)-1])
	}
}

func TestListOrgReposRetriesTransientPageFailure(t *testing.T) {
	t.Parallel()

	var page2Attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if page == "" {
			page = "1"
		}
		switch page {
		case "1":
			items := make([]map[string]string, 0, 100)
			for i := 0; i < 100; i++ {
				items = append(items, map[string]string{"full_name": fmt.Sprintf("acme/repo-%03d", i)})
			}
			_ = json.NewEncoder(w).Encode(items)
		case "2":
			current := atomic.AddInt32(&page2Attempts, 1)
			if current == 1 {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = fmt.Fprint(w, `{"message":"retry page 2"}`)
				return
			}
			_, _ = fmt.Fprint(w, `[]`)
		default:
			t.Fatalf("unexpected page request: %s", page)
		}
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	repos, err := connector.ListOrgRepos(context.Background(), "acme")
	if err != nil {
		t.Fatalf("list org repos: %v", err)
	}
	if len(repos) != 100 {
		t.Fatalf("expected 100 repos, got %d", len(repos))
	}
	if page2Attempts != 2 {
		t.Fatalf("expected page 2 to be attempted twice, got %d", page2Attempts)
	}
}

func TestListOrgReposFailsClosedOnLaterPageError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		if page == "" {
			page = "1"
		}
		switch page {
		case "1":
			items := make([]map[string]string, 0, 100)
			for i := 0; i < 100; i++ {
				items = append(items, map[string]string{"full_name": fmt.Sprintf("acme/repo-%03d", i)})
			}
			_ = json.NewEncoder(w).Encode(items)
		case "2":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprint(w, `{"message":"still failing"}`)
		default:
			t.Fatalf("unexpected page request: %s", page)
		}
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	repos, err := connector.ListOrgRepos(context.Background(), "acme")
	if err == nil {
		t.Fatal("expected page error to fail closed")
	}
	if repos != nil {
		t.Fatalf("expected no partial repos on failure, got %v", repos)
	}
}

func TestAcquireRepoRetriesTransientStatus(t *testing.T) {
	t.Parallel()

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt32(&attempts, 1)
		if current < 3 {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprint(w, `{"message":"try again"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"full_name":"acme/backend"}`)
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	manifest, err := connector.AcquireRepo(context.Background(), "acme/backend")
	if err != nil {
		t.Fatalf("expected retry to recover: %v", err)
	}
	if manifest.Repo != "acme/backend" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestAcquireRepoFailsOnInvalidRepo(t *testing.T) {
	t.Parallel()

	connector := NewConnector("", "", nil)
	for _, repo := range []string{"acme", "../..", "acme/..", "../backend"} {
		if _, err := connector.AcquireRepo(context.Background(), repo); err == nil {
			t.Fatalf("expected invalid repo input to fail: %q", repo)
		}
	}
}

func TestListOrgReposRequiresBaseURL(t *testing.T) {
	t.Parallel()

	connector := NewConnector("", "", nil)
	if _, err := connector.ListOrgRepos(context.Background(), "acme"); err == nil {
		t.Fatal("expected missing base URL to fail")
	}
}

func TestListOrgReposAllowsEmptyResultWithoutSyntheticFallback(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `[]`)
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	repos, err := connector.ListOrgRepos(context.Background(), "acme")
	if err != nil {
		t.Fatalf("list org repos: %v", err)
	}
	if len(repos) != 0 {
		t.Fatalf("expected no repos, got %v", repos)
	}
}

func TestMaterializeRepoWritesRepositoryTree(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/backend":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/backend","default_branch":"main"}`)
		case "/repos/acme/backend/git/trees/main":
			if r.URL.Query().Get("recursive") != "1" {
				t.Fatalf("expected recursive=1, got %q", r.URL.Query().Get("recursive"))
			}
			_, _ = fmt.Fprint(w, `{"tree":[{"path":"AGENTS.md","type":"blob","sha":"sha-1"},{"path":".codex/config.toml","type":"blob","sha":"sha-2"},{"path":"CODEOWNERS","type":"blob","sha":"sha-codeowners"},{"path":".wrkr/owners.yaml","type":"blob","sha":"sha-owners"},{"path":"catalog-info.yaml","type":"blob","sha":"sha-catalog"},{"path":"package-lock.json","type":"blob","sha":"sha-lock"},{"path":".github/dependabot.yml","type":"blob","sha":"sha-github"},{"path":"agent-plans/deploy.ptc.json","type":"blob","sha":"sha-compiled"},{"path":"agent-plans/build/release.ptc.json","type":"blob","sha":"sha-compiled-build"},{"path":"config/mcpgateway.yaml","type":"blob","sha":"sha-gateway"},{"path":"apps/api/.well-known/webmcp.json","type":"blob","sha":"sha-nested-webmcp"},{"path":"services/foo/.well-known/agent-card.json","type":"blob","sha":"sha-nested-agent-card"},{"path":"services/bar/agent.json","type":"blob","sha":"sha-agent-json"},{"path":".env.production","type":"blob","sha":"sha-env"},{"path":"prompts/system.md","type":"blob","sha":"sha-prompt-md"},{"path":"instructions/policy.yaml","type":"blob","sha":"sha-prompt-yaml"},{"path":"src/main.py","type":"blob","sha":"sha-source-py"},{"path":"crews/ops.py","type":"blob","sha":"sha-source-generic"},{"path":"build/main.py","type":"blob","sha":"sha-build-source"},{"path":"vendor/agent.py","type":"blob","sha":"sha-vendor-source"},{"path":"vendor/release.ptc.json","type":"blob","sha":"sha-vendor-compiled"},{"path":"vendor/agent-card.json","type":"blob","sha":"sha-vendor-agent-card"},{"path":"docs/changelog.txt","type":"blob","sha":"sha-skip"}]}`)
		case "/repos/acme/backend/git/blobs/sha-1":
			payload := base64.StdEncoding.EncodeToString([]byte("# agents\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-2":
			payload := base64.StdEncoding.EncodeToString([]byte("sandbox_mode = \"read-only\"\napproval_policy = \"on-request\"\nnetwork_access = false\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-codeowners":
			payload := base64.StdEncoding.EncodeToString([]byte(".github/workflows/* @acme/security\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-owners":
			payload := base64.StdEncoding.EncodeToString([]byte("owners:\n  - pattern: .codex/*\n    owner: '@acme/platform'\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-catalog":
			payload := base64.StdEncoding.EncodeToString([]byte("apiVersion: backstage.io/v1alpha1\nkind: Component\nmetadata:\n  name: backend\nspec:\n  owner: acme/backend\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-lock":
			payload := base64.StdEncoding.EncodeToString([]byte("{\"lockfileVersion\":3}\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-github":
			payload := base64.StdEncoding.EncodeToString([]byte("updates: []\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-compiled":
			payload := base64.StdEncoding.EncodeToString([]byte("{\"steps\":[{\"tool\":\"deploy\"}]}\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-compiled-build":
			payload := base64.StdEncoding.EncodeToString([]byte("{\"steps\":[{\"tool\":\"release\"}]}\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-gateway":
			payload := base64.StdEncoding.EncodeToString([]byte("gateway:\n  default_action: deny\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-nested-webmcp":
			payload := base64.StdEncoding.EncodeToString([]byte("{\"name\":\"api-webmcp\",\"tools\":[]}\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-nested-agent-card":
			payload := base64.StdEncoding.EncodeToString([]byte("{\"name\":\"foo-agent\",\"url\":\"https://example.invalid/a2a\"}\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-agent-json":
			payload := base64.StdEncoding.EncodeToString([]byte("{\"name\":\"bar-agent\",\"url\":\"https://example.invalid/bar\"}\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-env":
			payload := base64.StdEncoding.EncodeToString([]byte("OPENAI_API_KEY=redacted\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-prompt-md":
			payload := base64.StdEncoding.EncodeToString([]byte("Do not ignore prior system instructions.\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-prompt-yaml":
			payload := base64.StdEncoding.EncodeToString([]byte("system_prompt: keep policy instructions intact\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-source-py":
			t.Fatalf("default sparse materializer should not fetch generic source blob %s", r.URL.Path)
		case "/repos/acme/backend/git/blobs/sha-source-generic":
			t.Fatalf("default sparse materializer should not fetch generic source blob %s", r.URL.Path)
		case "/repos/acme/backend/git/blobs/sha-build-source":
			t.Fatalf("sparse materializer should not fetch generated source blob %s", r.URL.Path)
		case "/repos/acme/backend/git/blobs/sha-vendor-source":
			t.Fatalf("sparse materializer should not fetch skipped source blob %s", r.URL.Path)
		case "/repos/acme/backend/git/blobs/sha-vendor-compiled":
			t.Fatalf("sparse materializer should not fetch dependency compiled-action blob %s", r.URL.Path)
		case "/repos/acme/backend/git/blobs/sha-vendor-agent-card":
			t.Fatalf("sparse materializer should not fetch dependency agent-card blob %s", r.URL.Path)
		case "/repos/acme/backend/git/blobs/sha-skip":
			t.Fatalf("sparse materializer should not fetch unrelated blob %s", r.URL.Path)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	manifest, err := connector.MaterializeRepo(context.Background(), "acme/backend", tmp)
	if err != nil {
		t.Fatalf("materialize repo: %v", err)
	}
	if manifest.Source != "github_repo_materialized" {
		t.Fatalf("unexpected source: %s", manifest.Source)
	}
	if manifest.Repo != "acme/backend" {
		t.Fatalf("unexpected repo: %s", manifest.Repo)
	}
	if manifest.Location != "github://acme/backend" {
		t.Fatalf("expected logical hosted location, got %s", manifest.Location)
	}
	expectedScanRoot := filepath.ToSlash(filepath.Join(tmp, "acme", "backend"))
	if manifest.ScanRoot != expectedScanRoot {
		t.Fatalf("expected scan root %s, got %s", expectedScanRoot, manifest.ScanRoot)
	}

	agentsPath := filepath.Join(tmp, "acme", "backend", "AGENTS.md")
	if _, err := os.Stat(agentsPath); err != nil {
		t.Fatalf("expected materialized AGENTS.md: %v", err)
	}
	configPath := filepath.Join(tmp, "acme", "backend", ".codex", "config.toml")
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read materialized config: %v", err)
	}
	if !strings.Contains(string(content), "sandbox_mode") {
		t.Fatalf("unexpected config content: %s", string(content))
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "package-lock.json")); err != nil {
		t.Fatalf("expected materialized lockfile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "CODEOWNERS")); err != nil {
		t.Fatalf("expected materialized CODEOWNERS: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", ".wrkr", "owners.yaml")); err != nil {
		t.Fatalf("expected materialized owner mapping: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "catalog-info.yaml")); err != nil {
		t.Fatalf("expected materialized Backstage owner catalog: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", ".github", "dependabot.yml")); err != nil {
		t.Fatalf("expected materialized .github YAML: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "agent-plans", "deploy.ptc.json")); err != nil {
		t.Fatalf("expected materialized compiled-action config: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "agent-plans", "build", "release.ptc.json")); err != nil {
		t.Fatalf("expected materialized compiled-action config under generated dir name: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "config", "mcpgateway.yaml")); err != nil {
		t.Fatalf("expected materialized MCP gateway config: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "apps", "api", ".well-known", "webmcp.json")); err != nil {
		t.Fatalf("expected materialized nested WebMCP declaration: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "services", "foo", ".well-known", "agent-card.json")); err != nil {
		t.Fatalf("expected materialized nested A2A declaration: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "services", "bar", "agent.json")); err != nil {
		t.Fatalf("expected materialized non-well-known A2A declaration: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", ".env.production")); err != nil {
		t.Fatalf("expected materialized env file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "prompts", "system.md")); err != nil {
		t.Fatalf("expected materialized prompt markdown: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "instructions", "policy.yaml")); err != nil {
		t.Fatalf("expected materialized instruction YAML: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "src", "main.py")); !os.IsNotExist(err) {
		t.Fatalf("expected default scan to skip generic source file, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "crews", "ops.py")); !os.IsNotExist(err) {
		t.Fatalf("expected default scan to skip generic source file in framework-neutral path, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "build", "main.py")); !os.IsNotExist(err) {
		t.Fatalf("expected generated source path to remain skipped, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "vendor", "agent.py")); !os.IsNotExist(err) {
		t.Fatalf("expected skipped source path to remain skipped, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "vendor", "release.ptc.json")); !os.IsNotExist(err) {
		t.Fatalf("expected dependency compiled-action path to remain skipped, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "vendor", "agent-card.json")); !os.IsNotExist(err) {
		t.Fatalf("expected dependency agent-card path to remain skipped, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "docs", "changelog.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected unrelated docs blob to be skipped, stat err=%v", err)
	}
}

func TestMaterializeRepoAllowsGenericSourceWhenExplicitlyEnabled(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/backend":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/backend","default_branch":"main"}`)
		case "/repos/acme/backend/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[{"path":"src/main.py","type":"blob","sha":"sha-source-py"},{"path":"build/generated.py","type":"blob","sha":"sha-build-source"}]}`)
		case "/repos/acme/backend/git/blobs/sha-source-py":
			payload := base64.StdEncoding.EncodeToString([]byte("from crewai import Agent\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-build-source":
			t.Fatalf("explicit source materialization should still skip generated source blob %s", r.URL.Path)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	connector.SetAllowSourceMaterialization(true)
	manifest, err := connector.MaterializeRepo(context.Background(), "acme/backend", tmp)
	if err != nil {
		t.Fatalf("materialize repo: %v", err)
	}
	if manifest.Location != "github://acme/backend" {
		t.Fatalf("expected logical hosted location, got %s", manifest.Location)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "src", "main.py")); err != nil {
		t.Fatalf("expected explicit generic source materialization: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "acme", "backend", "build", "generated.py")); !os.IsNotExist(err) {
		t.Fatalf("expected generated source path to remain skipped, stat err=%v", err)
	}
}

func TestMaterializeRepoRejectsPathTraversal(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/backend":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/backend","default_branch":"main"}`)
		case "/repos/acme/backend/git/trees/main":
			_, _ = fmt.Fprint(w, `{"tree":[{"path":"../outside","type":"blob","sha":"sha-1"}]}`)
		case "/repos/acme/backend/git/blobs/sha-1":
			payload := base64.StdEncoding.EncodeToString([]byte("bad"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	if _, err := connector.MaterializeRepo(context.Background(), "acme/backend", tmp); err == nil {
		t.Fatal("expected traversal path to fail")
	}
}

func TestMaterializeRepoRejectsUnsafeMetadataFullName(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	materializedRoot := filepath.Join(tmp, "materialized-sources")
	if err := os.MkdirAll(materializedRoot, 0o750); err != nil {
		t.Fatalf("mkdir materialized root: %v", err)
	}
	sentinel := filepath.Join(materializedRoot, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatalf("write sentinel: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/backend":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/..","default_branch":"main"}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	if _, err := connector.MaterializeRepo(context.Background(), "acme/backend", materializedRoot); err == nil {
		t.Fatal("expected unsafe metadata full_name to fail")
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("expected sentinel to remain after rejected metadata, got: %v", err)
	}
}

func TestListOrgReposRejectsUnsafeFullName(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/acme/repos" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_, _ = fmt.Fprint(w, `[{"full_name":"acme/.."}]`)
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	if _, err := connector.ListOrgRepos(context.Background(), "acme"); err == nil {
		t.Fatal("expected unsafe repo metadata to fail closed")
	}
}

func TestMaterializeRepoFailsClosedOnTruncatedTree(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/backend":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/backend","default_branch":"main"}`)
		case "/repos/acme/backend/git/trees/main":
			_, _ = fmt.Fprint(w, `{"truncated":true,"tree":[{"path":"AGENTS.md","type":"blob","sha":"sha-1"}]}`)
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	_, err := connector.MaterializeRepo(context.Background(), "acme/backend", tmp)
	if err == nil {
		t.Fatal("expected truncated tree to fail closed")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("expected truncated error, got %v", err)
	}
}

func TestConnectorHonorsRetryAfter429(t *testing.T) {
	t.Parallel()

	var attempts int32
	var slept []time.Duration
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := atomic.AddInt32(&attempts, 1)
		if current == 1 {
			w.Header().Set("Retry-After", "4")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprint(w, `{"message":"rate limited"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"full_name":"acme/backend"}`)
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	connector.MaxRetries = 2
	connector.sleepFn = func(_ context.Context, duration time.Duration) error {
		slept = append(slept, duration)
		return nil
	}

	if _, err := connector.AcquireRepo(context.Background(), "acme/backend"); err != nil {
		t.Fatalf("acquire repo: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected two attempts, got %d", attempts)
	}
	if len(slept) == 0 || slept[0] != 4*time.Second {
		t.Fatalf("expected retry-after sleep of 4s, got %v", slept)
	}
}

func TestConnectorRetriesRecognizedRateLimit403(t *testing.T) {
	t.Parallel()

	var attempts int32
	var slept []time.Duration
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		current := atomic.AddInt32(&attempts, 1)
		if current == 1 {
			w.Header().Set("Retry-After", "2")
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"message":"API rate limit exceeded for this token"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"full_name":"acme/backend"}`)
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	connector.MaxRetries = 2
	connector.sleepFn = func(_ context.Context, duration time.Duration) error {
		slept = append(slept, duration)
		return nil
	}

	if _, err := connector.AcquireRepo(context.Background(), "acme/backend"); err != nil {
		t.Fatalf("acquire repo: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("expected two attempts, got %d", attempts)
	}
	if len(slept) == 0 || slept[0] != 2*time.Second {
		t.Fatalf("expected retry-after sleep of 2s, got %v", slept)
	}
}

func TestConnectorDoesNotRetryNonRateLimit403(t *testing.T) {
	t.Parallel()

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"message":"resource not accessible by integration"}`)
	}))
	defer server.Close()

	connector := NewConnector(server.URL, "", server.Client())
	connector.MaxRetries = 2
	connector.sleepFn = func(_ context.Context, _ time.Duration) error {
		t.Fatal("unexpected sleep for non-rate-limit 403")
		return nil
	}

	_, err := connector.AcquireRepo(context.Background(), "acme/backend")
	if err == nil {
		t.Fatal("expected non-rate-limit 403 to fail")
	}
	if attempts != 1 {
		t.Fatalf("expected one attempt, got %d", attempts)
	}
	if IsRateLimitedError(err) {
		t.Fatalf("expected non-rate-limit 403 to avoid rate-limit classification, got %v", err)
	}
}

func TestConnectorReturnsRateLimitedErrorWhenRetriesExhausted(t *testing.T) {
	t.Parallel()

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.Header().Set("X-RateLimit-Reset", "1700000015")
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"message":"secondary rate limit"}`)
	}))
	defer server.Close()

	now := time.Unix(1_700_000_000, 0)
	connector := NewConnector(server.URL, "", server.Client())
	connector.MaxRetries = 1
	connector.nowFn = func() time.Time { return now }
	connector.sleepFn = func(_ context.Context, _ time.Duration) error { return nil }

	_, err := connector.AcquireRepo(context.Background(), "acme/backend")
	if err == nil {
		t.Fatal("expected rate-limited failure")
	}
	var rateLimited *RateLimitedError
	if !errors.As(err, &rateLimited) {
		t.Fatalf("expected RateLimitedError, got %v", err)
	}
	if rateLimited.StatusCode != http.StatusForbidden {
		t.Fatalf("expected status 403, got %d", rateLimited.StatusCode)
	}
	if rateLimited.Attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", rateLimited.Attempts)
	}
	if !strings.Contains(rateLimited.Evidence, "x_ratelimit_reset_header") || !strings.Contains(rateLimited.Evidence, "body=secondary rate limit") {
		t.Fatalf("expected rate-limit evidence, got %q", rateLimited.Evidence)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}

func TestConnectorCircuitBreakerCooldown(t *testing.T) {
	t.Parallel()

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprint(w, `{"message":"upstream down"}`)
	}))
	defer server.Close()

	now := time.Unix(1_700_000_000, 0)
	connector := NewConnector(server.URL, "", server.Client())
	connector.MaxRetries = 0
	connector.FailureThreshold = 2
	connector.Cooldown = 30 * time.Second
	connector.nowFn = func() time.Time { return now }
	connector.sleepFn = func(_ context.Context, _ time.Duration) error { return nil }

	_, err := connector.AcquireRepo(context.Background(), "acme/backend")
	if err == nil {
		t.Fatal("expected first upstream failure")
	}
	if IsDegradedError(err) {
		t.Fatalf("first failure should not open circuit yet: %v", err)
	}

	_, err = connector.AcquireRepo(context.Background(), "acme/backend")
	if err == nil {
		t.Fatal("expected second failure")
	}
	if !IsDegradedError(err) {
		t.Fatalf("expected degradation on threshold breach, got %v", err)
	}

	attemptsAtOpen := atomic.LoadInt32(&attempts)
	_, err = connector.AcquireRepo(context.Background(), "acme/backend")
	if err == nil {
		t.Fatal("expected circuit-open degraded error")
	}
	if !IsDegradedError(err) {
		t.Fatalf("expected degraded error while cooldown active, got %v", err)
	}
	if got := atomic.LoadInt32(&attempts); got != attemptsAtOpen {
		t.Fatalf("expected no upstream calls while cooldown active, got before=%d after=%d", attemptsAtOpen, got)
	}

	now = now.Add(31 * time.Second)
	_, err = connector.AcquireRepo(context.Background(), "acme/backend")
	if err == nil {
		t.Fatal("expected upstream request after cooldown expiry")
	}
	if IsDegradedError(err) {
		t.Fatalf("expected non-degraded upstream error after cooldown expiry, got %v", err)
	}
}

func TestConnectorNonRetryableStatusResetsTransientFailureStreak(t *testing.T) {
	t.Parallel()

	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/backend" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		switch atomic.AddInt32(&attempts, 1) {
		case 1:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprint(w, `{"message":"transient-1"}`)
		case 2:
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"message":"missing"}`)
		default:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprint(w, `{"message":"transient-2"}`)
		}
	}))
	defer server.Close()

	now := time.Unix(1_700_000_000, 0)
	connector := NewConnector(server.URL, "", server.Client())
	connector.MaxRetries = 0
	connector.FailureThreshold = 2
	connector.Cooldown = 30 * time.Second
	connector.nowFn = func() time.Time { return now }
	connector.sleepFn = func(_ context.Context, _ time.Duration) error { return nil }

	_, err := connector.AcquireRepo(context.Background(), "acme/backend")
	if err == nil {
		t.Fatal("expected first transient failure")
	}
	if IsDegradedError(err) {
		t.Fatalf("first transient failure must not open cooldown, got %v", err)
	}

	_, err = connector.AcquireRepo(context.Background(), "acme/backend")
	if err == nil {
		t.Fatal("expected non-retryable status failure")
	}
	if IsDegradedError(err) {
		t.Fatalf("non-retryable status should not open cooldown, got %v", err)
	}

	_, err = connector.AcquireRepo(context.Background(), "acme/backend")
	if err == nil {
		t.Fatal("expected second transient failure")
	}
	if IsDegradedError(err) {
		t.Fatalf("transient streak should reset after non-retryable status, got %v", err)
	}
}
