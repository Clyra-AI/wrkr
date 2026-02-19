package org

import (
	"context"
	"errors"
	"testing"

	"github.com/Clyra-AI/wrkr/core/source"
)

type fakeLister struct {
	repos []string
	err   error
}

func (f fakeLister) ListOrgRepos(_ context.Context, _ string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.repos, nil
}

type fakeAcquirer struct {
	failRepo string
}

func (f fakeAcquirer) AcquireRepo(_ context.Context, repo string) (source.RepoManifest, error) {
	if repo == f.failRepo {
		return source.RepoManifest{}, errors.New("boom")
	}
	return source.RepoManifest{Repo: repo, Location: repo, Source: "github_repo"}, nil
}

func TestAcquireContinuesOnRepoFailure(t *testing.T) {
	t.Parallel()

	repos, failures, err := Acquire(context.Background(), "acme", fakeLister{repos: []string{"acme/a", "acme/b"}}, fakeAcquirer{failRepo: "acme/b"})
	if err != nil {
		t.Fatalf("acquire org: %v", err)
	}
	if len(repos) != 1 || repos[0].Repo != "acme/a" {
		t.Fatalf("unexpected repos: %v", repos)
	}
	if len(failures) != 1 || failures[0].Repo != "acme/b" {
		t.Fatalf("unexpected failures: %v", failures)
	}
}
