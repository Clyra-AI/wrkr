package org

import (
	"context"
	"sort"

	"github.com/Clyra-AI/wrkr/core/source"
)

type RepoLister interface {
	ListOrgRepos(ctx context.Context, org string) ([]string, error)
}

type RepoAcquirer interface {
	AcquireRepo(ctx context.Context, repo string) (source.RepoManifest, error)
}

// Acquire gathers repo manifests for an org and continues on per-repo acquisition failures.
func Acquire(ctx context.Context, org string, lister RepoLister, acquirer RepoAcquirer) (repos []source.RepoManifest, failures []source.RepoFailure, err error) {
	repoNames, err := lister.ListOrgRepos(ctx, org)
	if err != nil {
		return nil, nil, err
	}

	repos = make([]source.RepoManifest, 0, len(repoNames))
	failures = make([]source.RepoFailure, 0)
	for _, repo := range repoNames {
		manifest, repoErr := acquirer.AcquireRepo(ctx, repo)
		if repoErr != nil {
			failures = append(failures, source.RepoFailure{Repo: repo, Reason: repoErr.Error()})
			continue
		}
		repos = append(repos, manifest)
	}

	sort.Slice(repos, func(i, j int) bool { return repos[i].Repo < repos[j].Repo })
	sort.Slice(failures, func(i, j int) bool { return failures[i].Repo < failures[j].Repo })
	return repos, failures, nil
}
