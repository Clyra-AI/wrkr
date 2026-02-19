package github

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestAcquireRepoOfflineMode(t *testing.T) {
	t.Parallel()

	connector := NewConnector("", "", nil)
	manifest, err := connector.AcquireRepo(context.Background(), "acme/backend")
	if err != nil {
		t.Fatalf("acquire repo: %v", err)
	}
	if manifest.Repo != "acme/backend" {
		t.Fatalf("unexpected repo: %+v", manifest)
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
