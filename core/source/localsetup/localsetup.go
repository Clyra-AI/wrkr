package localsetup

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Clyra-AI/wrkr/core/source"
)

const (
	TargetValue = "local-machine"
	RepoName    = "local-machine"
)

// Acquire returns the deterministic local-machine scan root anchored at the user's home directory.
func Acquire() ([]source.RepoManifest, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve user home: %w", err)
	}
	info, err := os.Stat(home)
	if err != nil {
		return nil, fmt.Errorf("stat user home: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("user home is not a directory: %s", home)
	}
	return []source.RepoManifest{{
		Repo:     RepoName,
		Location: filepath.ToSlash(home),
		Source:   "local_machine",
	}}, nil
}
