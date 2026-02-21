package pr

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestGitHubClientListCreateUpdateWithRetry(t *testing.T) {
	t.Parallel()

	var createAttempts int32
	var updateAttempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/pulls"):
			_, _ = w.Write([]byte(`[{"number":7,"html_url":"https://example/pr/7","title":"existing","body":"x","head":{"ref":"wrkr-bot/remediation/repo/adhoc/abc"},"base":{"ref":"main"}}]`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/pulls"):
			if atomic.AddInt32(&createAttempts, 1) == 1 {
				w.WriteHeader(http.StatusBadGateway)
				_, _ = w.Write([]byte(`{"message":"retry"}`))
				return
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"number":9,"html_url":"https://example/pr/9","title":"new","body":"b","head":{"ref":"h"},"base":{"ref":"main"}}`))
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/pulls/"):
			if atomic.AddInt32(&updateAttempts, 1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				_, _ = w.Write([]byte(`{"message":"retry"}`))
				return
			}
			_, _ = w.Write([]byte(`{"number":7,"html_url":"https://example/pr/7","title":"updated","body":"u","head":{"ref":"wrkr-bot/remediation/repo/adhoc/abc"},"base":{"ref":"main"}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(fmt.Sprintf("unknown route: %s %s", r.Method, r.URL.Path)))
		}
	}))
	defer server.Close()

	client := NewGitHubClient(server.URL, "token", server.Client())

	list, err := client.ListOpenByHead(context.Background(), "acme", "repo", "wrkr-bot/remediation/repo/adhoc/abc", "main")
	if err != nil {
		t.Fatalf("list prs: %v", err)
	}
	if len(list) != 1 || list[0].Number != 7 {
		t.Fatalf("unexpected list result: %#v", list)
	}

	created, err := client.Create(context.Background(), "acme", "repo", CreateRequest{Title: "new", Head: "h", Base: "main", Body: "b"})
	if err != nil {
		t.Fatalf("create pr: %v", err)
	}
	if created.Number != 9 {
		t.Fatalf("expected created pr #9, got %#v", created)
	}
	if atomic.LoadInt32(&createAttempts) != 2 {
		t.Fatalf("expected one retry on create, attempts=%d", createAttempts)
	}

	updated, err := client.Update(context.Background(), "acme", "repo", 7, UpdateRequest{Title: "updated", Body: "u"})
	if err != nil {
		t.Fatalf("update pr: %v", err)
	}
	if updated.Title != "updated" {
		t.Fatalf("expected updated title, got %#v", updated)
	}
	if atomic.LoadInt32(&updateAttempts) != 2 {
		t.Fatalf("expected one retry on update, attempts=%d", updateAttempts)
	}
}

func TestGitHubClientRepoURLPreservesBasePathPrefix(t *testing.T) {
	t.Parallel()

	var requestedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	client := NewGitHubClient(server.URL+"/api/v3", "token", server.Client())
	if _, err := client.ListOpenByHead(context.Background(), "acme", "repo", "branch", "main"); err != nil {
		t.Fatalf("list prs: %v", err)
	}
	if requestedPath != "/api/v3/repos/acme/repo/pulls" {
		t.Fatalf("expected API prefix preserved, got %q", requestedPath)
	}
}

func TestGitHubClientEnsureHeadRefCreatesMissingBranchFromBase(t *testing.T) {
	t.Parallel()

	var createRefCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/git/ref/heads/wrkr-bot/remediation/repo/weekly/abc"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
			_, _ = w.Write([]byte(`{"object":{"sha":"base-sha-123"}}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/git/refs"):
			createRefCalls++
			_, _ = w.Write([]byte(`{"ref":"refs/heads/wrkr-bot/remediation/repo/weekly/abc"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"unexpected route"}`))
		}
	}))
	defer server.Close()

	client := NewGitHubClient(server.URL, "token", server.Client())
	if err := client.EnsureHeadRef(context.Background(), "acme", "repo", "wrkr-bot/remediation/repo/weekly/abc", "main"); err != nil {
		t.Fatalf("ensure head ref: %v", err)
	}
	if createRefCalls != 1 {
		t.Fatalf("expected one branch-create call, got %d", createRefCalls)
	}
}
