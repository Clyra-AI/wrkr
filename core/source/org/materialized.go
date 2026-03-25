package org

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Clyra-AI/wrkr/core/source"
)

type RepoMaterializer interface {
	MaterializeRepo(ctx context.Context, repo string, materializedRoot string) (source.RepoManifest, error)
}

type ProgressReporter interface {
	RepoDiscovery(total int)
	RepoMaterialize(index, total int, repo string)
	Resume(total, completed, pending int)
	Complete(total, completed, failed int)
}

type AcquireMaterializedOptions struct {
	StatePath        string
	MaterializedRoot string
	Resume           bool
	WorkerCount      int
	Progress         ProgressReporter
}

type materializeJob struct {
	repo  string
	index int
}

type materializeResult struct {
	manifest source.RepoManifest
	failure  source.RepoFailure
	fatalErr error
}

func AcquireMaterialized(
	ctx context.Context,
	org string,
	lister RepoLister,
	materializer RepoMaterializer,
	opts AcquireMaterializedOptions,
) (repos []source.RepoManifest, failures []source.RepoFailure, err error) {
	repoNames, err := lister.ListOrgRepos(ctx, org)
	if err != nil {
		return nil, nil, err
	}
	repoNames = uniqueSortedStrings(repoNames)
	totalRepos := len(repoNames)
	if opts.Progress != nil {
		opts.Progress.RepoDiscovery(totalRepos)
	}

	checkpointFile, err := checkpointPath(opts.StatePath, org)
	if err != nil {
		return nil, nil, err
	}

	manager := newCheckpointManager(checkpointFile, org, repoNames, opts.MaterializedRoot)
	if opts.Resume {
		manager, err = loadCheckpointManager(checkpointFile)
		if err != nil {
			return nil, nil, err
		}
		if err := manager.validate(org, repoNames, opts.MaterializedRoot); err != nil {
			return nil, nil, err
		}
	} else if err := manager.save(); err != nil {
		return nil, nil, err
	}

	completedSet := manager.completedSet()
	repos = make([]source.RepoManifest, 0, totalRepos)
	failures = make([]source.RepoFailure, 0)
	pendingJobs := make([]materializeJob, 0, totalRepos)
	for idx, repo := range repoNames {
		if _, ok := completedSet[repo]; ok {
			manifest, manifestErr := manifestFromCheckpoint(repo, opts.MaterializedRoot)
			if manifestErr != nil {
				return nil, nil, manifestErr
			}
			repos = append(repos, manifest)
			continue
		}
		pendingJobs = append(pendingJobs, materializeJob{repo: repo, index: idx + 1})
	}
	if opts.Resume && opts.Progress != nil {
		opts.Progress.Resume(totalRepos, len(repos), len(pendingJobs))
	}
	if len(pendingJobs) == 0 {
		if opts.Progress != nil {
			opts.Progress.Complete(totalRepos, len(repos), 0)
		}
		sortMaterialized(repos, failures)
		return repos, failures, nil
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	workerCount := opts.WorkerCount
	if workerCount <= 0 {
		workerCount = 4
	}
	if workerCount > len(pendingJobs) {
		workerCount = len(pendingJobs)
	}

	jobs := make(chan materializeJob)
	results := make(chan materializeResult, len(pendingJobs))
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				manifest, materializeErr := materializer.MaterializeRepo(ctx, job.repo, opts.MaterializedRoot)
				if materializeErr != nil {
					if errors.Is(materializeErr, context.Canceled) || errors.Is(materializeErr, context.DeadlineExceeded) {
						cancel()
						results <- materializeResult{fatalErr: materializeErr}
						continue
					}
					results <- materializeResult{
						failure: source.RepoFailure{Repo: job.repo, Reason: materializeErr.Error()},
					}
					continue
				}
				if checkpointErr := manager.markCompleted(job.repo); checkpointErr != nil {
					cancel()
					results <- materializeResult{fatalErr: checkpointErr}
					continue
				}
				results <- materializeResult{manifest: manifest}
			}
		}()
	}

	go func() {
		for _, job := range pendingJobs {
			if opts.Progress != nil {
				opts.Progress.RepoMaterialize(job.index, totalRepos, job.repo)
			}
			jobs <- job
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var fatalErr error
	for result := range results {
		if result.fatalErr != nil && fatalErr == nil {
			fatalErr = result.fatalErr
		}
		if result.failure.Repo != "" {
			failures = append(failures, result.failure)
		}
		if strings.TrimSpace(result.manifest.Repo) != "" {
			repos = append(repos, result.manifest)
		}
	}
	if fatalErr != nil {
		return nil, nil, fatalErr
	}
	if opts.Progress != nil {
		opts.Progress.Complete(totalRepos, len(repos), len(failures))
	}
	sortMaterialized(repos, failures)
	return repos, failures, nil
}

func manifestFromCheckpoint(repo string, materializedRoot string) (source.RepoManifest, error) {
	location := filepath.Join(materializedRoot, filepath.FromSlash(strings.TrimSpace(repo)))
	info, err := os.Stat(location)
	if err != nil {
		if os.IsNotExist(err) {
			return source.RepoManifest{}, newCheckpointInputError("resume checkpoint repo materialization missing: %s", repo)
		}
		return source.RepoManifest{}, fmt.Errorf("stat resumed repo materialization %s: %w", location, err)
	}
	if !info.IsDir() {
		return source.RepoManifest{}, newCheckpointInputError("resume checkpoint repo materialization is not a directory: %s", location)
	}
	return source.RepoManifest{
		Repo:     strings.TrimSpace(repo),
		Location: filepath.ToSlash(location),
		Source:   "github_repo_materialized",
	}, nil
}

func sortMaterialized(repos []source.RepoManifest, failures []source.RepoFailure) {
	sort.Slice(repos, func(i, j int) bool { return repos[i].Repo < repos[j].Repo })
	sort.Slice(failures, func(i, j int) bool { return failures[i].Repo < failures[j].Repo })
}
