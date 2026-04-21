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
	RepoDiscovery(org string, total int)
	RepoMaterialize(org string, index, total int, repo string)
	RepoMaterializeDone(org string, completed, total int, repo, status string)
	Resume(org string, total, completed, pending int)
	Complete(org string, total, completed, failed int)
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
	repo     string
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
		opts.Progress.RepoDiscovery(org, totalRepos)
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
		opts.Progress.Resume(org, totalRepos, len(repos), len(pendingJobs))
	}
	if len(pendingJobs) == 0 {
		if opts.Progress != nil {
			opts.Progress.Complete(org, totalRepos, len(repos), 0)
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
				if opts.Progress != nil {
					opts.Progress.RepoMaterialize(org, job.index, totalRepos, job.repo)
				}
				manifest, materializeErr := materializer.MaterializeRepo(ctx, job.repo, opts.MaterializedRoot)
				if materializeErr != nil {
					if errors.Is(materializeErr, context.Canceled) || errors.Is(materializeErr, context.DeadlineExceeded) {
						cancel()
						results <- materializeResult{fatalErr: materializeErr, repo: job.repo}
						continue
					}
					results <- materializeResult{
						failure: source.RepoFailure{Repo: job.repo, Reason: materializeErr.Error()},
						repo:    job.repo,
					}
					continue
				}
				if checkpointErr := manager.markCompleted(job.repo); checkpointErr != nil {
					cancel()
					results <- materializeResult{fatalErr: checkpointErr, repo: job.repo}
					continue
				}
				results <- materializeResult{manifest: manifest, repo: job.repo}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, job := range pendingJobs {
			if ctx.Err() != nil {
				return
			}
			select {
			case <-ctx.Done():
				return
			case jobs <- job:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var fatalErr error
	completedResults := len(repos)
	for result := range results {
		if result.fatalErr != nil && fatalErr == nil {
			fatalErr = result.fatalErr
		}
		if result.failure.Repo != "" {
			failures = append(failures, result.failure)
			completedResults++
			if opts.Progress != nil {
				opts.Progress.RepoMaterializeDone(org, completedResults, totalRepos, result.failure.Repo, "failed")
			}
		}
		if strings.TrimSpace(result.manifest.Repo) != "" {
			repos = append(repos, result.manifest)
			completedResults++
			if opts.Progress != nil {
				opts.Progress.RepoMaterializeDone(org, completedResults, totalRepos, result.manifest.Repo, "ok")
			}
		}
	}
	if fatalErr != nil {
		return nil, nil, fatalErr
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, nil, ctxErr
	}
	if opts.Progress != nil {
		opts.Progress.Complete(org, totalRepos, len(repos), len(failures))
	}
	sortMaterialized(repos, failures)
	return repos, failures, nil
}

func manifestFromCheckpoint(repo string, materializedRoot string) (source.RepoManifest, error) {
	location := filepath.Join(materializedRoot, filepath.FromSlash(strings.TrimSpace(repo)))
	info, err := os.Lstat(location)
	if err != nil {
		if os.IsNotExist(err) {
			return source.RepoManifest{}, newCheckpointInputError("resume checkpoint repo materialization missing: %s", repo)
		}
		return source.RepoManifest{}, fmt.Errorf("lstat resumed repo materialization %s: %w", location, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return source.RepoManifest{}, newCheckpointSafetyError("resume checkpoint repo materialization must not be a symlink: %s", location)
	}
	if !info.IsDir() {
		return source.RepoManifest{}, newCheckpointInputError("resume checkpoint repo materialization is not a directory: %s", location)
	}
	canonicalRoot, err := filepath.EvalSymlinks(materializedRoot)
	if err != nil {
		return source.RepoManifest{}, fmt.Errorf("resolve materialized root %s: %w", materializedRoot, err)
	}
	resolvedLocation, err := filepath.EvalSymlinks(location)
	if err != nil {
		return source.RepoManifest{}, fmt.Errorf("resolve resumed repo materialization %s: %w", location, err)
	}
	if !materializedLocationWithinRoot(canonicalRoot, resolvedLocation) {
		return source.RepoManifest{}, newCheckpointSafetyError("resume checkpoint repo materialization escapes managed root: %s", location)
	}
	return source.RepoManifest{
		Repo:     strings.TrimSpace(repo),
		Location: filepath.ToSlash(location),
		Source:   "github_repo_materialized",
	}, nil
}

func materializedLocationWithinRoot(root string, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func sortMaterialized(repos []source.RepoManifest, failures []source.RepoFailure) {
	sort.Slice(repos, func(i, j int) bool { return repos[i].Repo < repos[j].Repo })
	sort.Slice(failures, func(i, j int) bool { return failures[i].Repo < failures[j].Repo })
}
