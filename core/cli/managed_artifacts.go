package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

type managedArtifactSnapshot struct {
	path    string
	existed bool
	payload []byte
	perm    os.FileMode
}

func captureManagedArtifacts(paths ...string) ([]managedArtifactSnapshot, error) {
	snapshots := make([]managedArtifactSnapshot, 0, len(paths))
	seen := map[string]struct{}{}
	for _, rawPath := range paths {
		cleanPath := filepath.Clean(strings.TrimSpace(rawPath))
		if cleanPath == "" || cleanPath == "." {
			continue
		}
		if _, ok := seen[cleanPath]; ok {
			continue
		}
		seen[cleanPath] = struct{}{}

		snapshot, err := captureManagedArtifact(cleanPath)
		if err != nil {
			return nil, err
		}
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func captureManagedArtifact(path string) (managedArtifactSnapshot, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return managedArtifactSnapshot{path: path}, nil
		}
		return managedArtifactSnapshot{}, fmt.Errorf("stat managed artifact %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return managedArtifactSnapshot{}, fmt.Errorf("managed artifact is not a regular file: %s", path)
	}
	payload, err := os.ReadFile(path) // #nosec G304 -- managed artifact paths are deterministic local wrkr paths.
	if err != nil {
		return managedArtifactSnapshot{}, fmt.Errorf("read managed artifact %s: %w", path, err)
	}
	return managedArtifactSnapshot{
		path:    path,
		existed: true,
		payload: payload,
		perm:    info.Mode().Perm(),
	}, nil
}

func restoreManagedArtifacts(snapshots []managedArtifactSnapshot) error {
	issues := make([]string, 0)
	for _, snapshot := range snapshots {
		if err := snapshot.restore(); err != nil {
			issues = append(issues, err.Error())
		}
	}
	if len(issues) > 0 {
		return errors.New(strings.Join(issues, "; "))
	}
	return nil
}

func (s managedArtifactSnapshot) restore() error {
	if !s.existed {
		if err := os.Remove(filepath.Clean(s.path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove managed artifact %s: %w", s.path, err)
		}
		return nil
	}

	perm := s.perm
	if perm == 0 {
		perm = 0o600
	}
	if err := atomicwrite.WriteFile(s.path, s.payload, perm); err != nil {
		return fmt.Errorf("restore managed artifact %s: %w", s.path, err)
	}
	return nil
}

func emitRolledBackRuntimeFailure(stderr io.Writer, jsonOut bool, actionErr error, snapshots []managedArtifactSnapshot) int {
	if actionErr == nil {
		return exitSuccess
	}
	if restoreErr := restoreManagedArtifacts(snapshots); restoreErr != nil {
		return emitError(stderr, jsonOut, "runtime_failure", fmt.Sprintf("%v (rollback restore failed: %v)", actionErr, restoreErr), exitRuntime)
	}
	return emitError(stderr, jsonOut, "runtime_failure", actionErr.Error(), exitRuntime)
}
