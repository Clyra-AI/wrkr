package local

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/source"
)

// Acquire discovers local repositories from a directory path.
func Acquire(root string) ([]source.RepoManifest, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("path target is required")
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("read path target: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("path target must be a directory: %s", root)
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
