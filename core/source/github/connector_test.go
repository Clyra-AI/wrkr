package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
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
	if _, err := connector.AcquireRepo(context.Background(), "acme"); err == nil {
		t.Fatal("expected invalid repo input to fail")
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
			_, _ = fmt.Fprint(w, `{"tree":[{"path":"AGENTS.md","type":"blob","sha":"sha-1"},{"path":".codex/config.toml","type":"blob","sha":"sha-2"}]}`)
		case "/repos/acme/backend/git/blobs/sha-1":
			payload := base64.StdEncoding.EncodeToString([]byte("# agents\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
		case "/repos/acme/backend/git/blobs/sha-2":
			payload := base64.StdEncoding.EncodeToString([]byte("sandbox_mode = \"read-only\"\napproval_policy = \"on-request\"\nnetwork_access = false\n"))
			_, _ = fmt.Fprintf(w, `{"content":"%s","encoding":"base64"}`, payload)
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
