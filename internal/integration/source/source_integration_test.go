package sourceintegration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Clyra-AI/wrkr/core/source/github"
	"github.com/Clyra-AI/wrkr/core/source/org"
)

func TestIntegrationOrgAcquireWithSimulatedGitHub(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			_, _ = fmt.Fprint(w, `[{"full_name":"acme/ok"},{"full_name":"acme/fail"}]`)
		case "/repos/acme/ok":
			_, _ = fmt.Fprint(w, `{"full_name":"acme/ok"}`)
		case "/repos/acme/fail":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprint(w, `{"message":"temporary"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	connector := github.NewConnector(server.URL, "token", server.Client())
	repos, failures, err := org.Acquire(context.Background(), "acme", connector, connector)
	if err != nil {
		t.Fatalf("acquire org: %v", err)
	}
	if len(repos) != 1 || repos[0].Repo != "acme/ok" {
		t.Fatalf("unexpected repos: %+v", repos)
	}
	if len(failures) != 1 || failures[0].Repo != "acme/fail" {
		t.Fatalf("unexpected failures: %+v", failures)
	}
}
