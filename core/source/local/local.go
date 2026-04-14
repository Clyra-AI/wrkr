package local

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

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

// Acquire discovers local repositories from a directory path.
func Acquire(root string) ([]source.RepoManifest, error) {
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
	if hasSignals, err := hasRepoRootSignals(root); err != nil {
		return nil, fmt.Errorf("classify path target: %w", err)
	} else if hasSignals {
		return []source.RepoManifest{repoManifestForRoot(root)}, nil
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read path entries: %w", err)
	}

	manifests := make([]source.RepoManifest, 0)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}
		repoPath := filepath.Join(root, name)
		manifests = append(manifests, source.RepoManifest{
			Repo:     name,
			Location: filepath.ToSlash(repoPath),
			Source:   "local_path",
		})
	}
	sort.Slice(manifests, func(i, j int) bool { return manifests[i].Repo < manifests[j].Repo })
	return manifests, nil
}

func hasRepoRootSignals(root string) (bool, error) {
	for _, rel := range repoRootSignals {
		exists, err := pathExists(filepath.Join(root, rel))
		if err != nil {
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
