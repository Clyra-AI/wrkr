package local

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/Clyra-AI/wrkr/core/source"
)

var repoRootSignals = []string{
	".agents",
	".claude",
	".codex",
	".cursor",
	".git",
	".github",
	".mcp.json",
	".vscode/mcp.json",
	".cursorrules",
	"AGENTS.md",
	"AGENTS.override.md",
	"CLAUDE.md",
	"Cargo.toml",
	"Gemfile",
	"Jenkinsfile",
	"build.gradle",
	"build.gradle.kts",
	"composer.json",
	"go.mod",
	"package.json",
	"pnpm-workspace.yaml",
	"pom.xml",
	"pyproject.toml",
	"requirements.txt",
}

const maxRepoDiscoveryDepth = 4

type ProgressReporter interface {
	PathDiscovery(root string, total int)
	PathRepo(root string, index, total int, repo string)
}

type AcquireOptions struct {
	Progress ProgressReporter
}

// Acquire discovers local repositories from a directory path.
func Acquire(root string) ([]source.RepoManifest, error) {
	return AcquireWithOptions(context.Background(), root, AcquireOptions{})
}

func AcquireWithOptions(ctx context.Context, root string, opts AcquireOptions) ([]source.RepoManifest, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("path target is required")
	}
	root = filepath.Clean(root)
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("read path target: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path target must be a directory: %s", root)
	}
	rootHasSignals, err := hasRepoRootSignals(root)
	if err != nil {
		return nil, fmt.Errorf("classify path target: %w", err)
	}
	if rootHasStrongSignal, err := pathExists(filepath.Join(root, ".git")); err != nil {
		return nil, fmt.Errorf("classify path target: %w", err)
	} else if rootHasStrongSignal {
		return []source.RepoManifest{repoManifestForRoot(root)}, nil
	}

	immediate, immediateSignalCount, err := immediateChildRepos(ctx, root)
	if err != nil {
		return nil, err
	}
	if len(immediate) > 0 && immediateSignalCount > 0 {
		if rootHasSignals && immediateSignalCount < 2 {
			return []source.RepoManifest{repoManifestForRoot(root)}, nil
		}
		emitPathProgress(opts.Progress, root, immediate)
		return immediate, nil
	}

	discovered, err := discoverRepoRoots(ctx, root)
	if err != nil {
		return nil, err
	}
	if rootHasSignals && len(discovered) < 2 {
		return []source.RepoManifest{repoManifestForRoot(root)}, nil
	}
	if len(discovered) > 0 {
		emitPathProgress(opts.Progress, root, discovered)
		return discovered, nil
	}
	emitPathProgress(opts.Progress, root, immediate)
	return immediate, nil
}

func immediateChildRepos(ctx context.Context, root string) ([]source.RepoManifest, int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, 0, fmt.Errorf("read path entries: %w", err)
	}

	manifests := make([]source.RepoManifest, 0)
	signalCount := 0
	for _, entry := range entries {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, 0, ctxErr
		}
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		repoPath := filepath.Join(root, name)
		if hasSignals, signalErr := hasRepoRootSignals(repoPath); signalErr == nil && hasSignals {
			signalCount++
		}
		manifests = append(manifests, source.RepoManifest{
			Repo:     name,
			Location: filepath.ToSlash(repoPath),
			Source:   "local_path",
		})
	}
	sort.Slice(manifests, func(i, j int) bool { return manifests[i].Repo < manifests[j].Repo })
	return manifests, signalCount, nil
}

func discoverRepoRoots(ctx context.Context, root string) ([]source.RepoManifest, error) {
	manifests := make([]source.RepoManifest, 0)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if walkErr != nil {
			if path != root {
				return nil
			}
			return walkErr
		}
		if d == nil || !d.IsDir() {
			return nil
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		relSlash := filepath.ToSlash(rel)
		if shouldSkipLocalTraversal(relSlash, d.Name()) {
			return filepath.SkipDir
		}
		if repoDiscoveryDepth(relSlash) > maxRepoDiscoveryDepth {
			return filepath.SkipDir
		}

		hasSignals, signalErr := hasRepoRootSignals(path)
		if signalErr != nil {
			return fmt.Errorf("classify path target %s: %w", path, signalErr)
		}
		if !hasSignals {
			return nil
		}
		manifests = append(manifests, repoManifestForDiscoveredRoot(root, path))
		return filepath.SkipDir
	})
	if err != nil {
		return nil, fmt.Errorf("discover path repos: %w", err)
	}
	sort.Slice(manifests, func(i, j int) bool {
		if manifests[i].Repo == manifests[j].Repo {
			return manifests[i].Location < manifests[j].Location
		}
		return manifests[i].Repo < manifests[j].Repo
	})
	return manifests, nil
}

func shouldSkipLocalTraversal(rel, name string) bool {
	lowerName := strings.ToLower(strings.TrimSpace(name))
	switch lowerName {
	case "", ".git", "node_modules", "vendor", "dist", "build", "target", ".venv", "venv", ".next", "coverage":
		return true
	}
	for _, part := range strings.Split(strings.Trim(filepath.ToSlash(strings.TrimSpace(rel)), "/"), "/") {
		if strings.HasPrefix(strings.TrimSpace(part), ".") {
			return true
		}
	}
	return false
}

func repoDiscoveryDepth(rel string) int {
	trimmed := strings.Trim(filepath.ToSlash(strings.TrimSpace(rel)), "/")
	if trimmed == "" {
		return 0
	}
	return strings.Count(trimmed, "/") + 1
}

func emitPathProgress(progress ProgressReporter, root string, manifests []source.RepoManifest) {
	if progress == nil {
		return
	}
	progress.PathDiscovery(root, len(manifests))
	for idx, manifest := range manifests {
		progress.PathRepo(root, idx+1, len(manifests), manifest.Repo)
	}
}

func hasRepoRootSignals(root string) (bool, error) {
	for _, rel := range repoRootSignals {
		exists, err := pathExists(filepath.Join(root, rel))
		if err != nil {
			if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.ENOTDIR) {
				continue
			}
			return false, err
		}
		if exists {
			return true, nil
		}
	}
	return false, nil
}

func pathExists(path string) (bool, error) {
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func repoManifestForRoot(root string) source.RepoManifest {
	return source.RepoManifest{
		Repo:     repoNameForRoot(root),
		Location: filepath.ToSlash(root),
		Source:   "local_path",
	}
}

func repoManifestForDiscoveredRoot(root, repoPath string) source.RepoManifest {
	repoName := repoNameForRoot(repoPath)
	if rel, err := filepath.Rel(root, repoPath); err == nil {
		rel = filepath.ToSlash(rel)
		if strings.TrimSpace(rel) != "" && rel != "." {
			repoName = rel
		}
	}
	return source.RepoManifest{
		Repo:     repoName,
		Location: filepath.ToSlash(repoPath),
		Source:   "local_path",
	}
}

func repoNameForRoot(root string) string {
	cleanRoot := filepath.Clean(root)
	name := filepath.Base(cleanRoot)
	if name != "" && name != "." && name != string(filepath.Separator) {
		return name
	}

	absRoot, err := filepath.Abs(cleanRoot)
	if err == nil {
		name = filepath.Base(absRoot)
		if name != "" && name != "." && name != string(filepath.Separator) {
			return name
		}
		if volume := filepath.VolumeName(absRoot); volume != "" {
			return volume
		}
	}
	return "local-root"
}
