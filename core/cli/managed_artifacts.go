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

type scanArtifactPathEntry struct {
	label string
	path  string
	key   string
}

type unsafeManagedArtifactPathError struct {
	err error
}

func (e unsafeManagedArtifactPathError) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e unsafeManagedArtifactPathError) Unwrap() error {
	return e.err
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

func normalizeManagedArtifactPath(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("scan artifact path must not be empty")
	}
	return filepath.Clean(trimmed), nil
}

func preflightTrustedStatePath(raw string) (string, error) {
	statePath, err := normalizeManagedArtifactPath(raw)
	if err != nil {
		return "", err
	}
	if err := rejectUnsafeExistingManagedFile(statePath, "--state"); err != nil {
		return "", unsafeManagedArtifactPathError{err: err}
	}
	return statePath, nil
}

func rejectUnsafeExistingManagedFile(path string, label string) error {
	cleanPath := filepath.Clean(strings.TrimSpace(path))
	info, err := os.Lstat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", cleanPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must be a regular file, not a symlink: %s", strings.TrimSpace(label), cleanPath)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file: %s", strings.TrimSpace(label), cleanPath)
	}
	return nil
}

func isUnsafeManagedArtifactPathError(err error) bool {
	var target unsafeManagedArtifactPathError
	return errors.As(err, &target)
}

func newScanArtifactPathEntry(label, path string) (scanArtifactPathEntry, error) {
	key, err := canonicalArtifactPath(path)
	if err != nil {
		return scanArtifactPathEntry{}, err
	}
	return scanArtifactPathEntry{
		label: label,
		path:  path,
		key:   key,
	}, nil
}

func canonicalArtifactPath(raw string) (string, error) {
	cleanPath := filepath.Clean(strings.TrimSpace(raw))
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("resolve artifact output path: %w", err)
	}
	return resolveArtifactPath(absPath)
}

func resolveArtifactPath(absPath string) (string, error) {
	missingTail := make([]string, 0, 4)
	candidate := absPath
	for {
		resolved, err := filepath.EvalSymlinks(candidate)
		if err == nil {
			for i := len(missingTail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missingTail[i])
			}
			return filepath.Clean(resolved), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("resolve artifact output path: %w", err)
		}

		parent := filepath.Dir(candidate)
		if parent == candidate {
			for i := len(missingTail) - 1; i >= 0; i-- {
				candidate = filepath.Join(candidate, missingTail[i])
			}
			return filepath.Clean(candidate), nil
		}

		missingTail = append(missingTail, filepath.Base(candidate))
		candidate = parent
	}
}

func detectScanArtifactPathCollisions(entries []scanArtifactPathEntry) error {
	byKey := make(map[string][]scanArtifactPathEntry, len(entries))
	keyOrder := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry.key) == "" {
			continue
		}
		if _, ok := byKey[entry.key]; !ok {
			keyOrder = append(keyOrder, entry.key)
		}
		byKey[entry.key] = append(byKey[entry.key], entry)
	}

	conflicts := make([]string, 0)
	for _, key := range keyOrder {
		group := byKey[key]
		if len(group) < 2 {
			continue
		}
		labels := make([]string, 0, len(group))
		for _, entry := range group {
			labels = append(labels, entry.label)
		}
		conflicts = append(conflicts, fmt.Sprintf("%s resolve to the same path %s", humanArtifactLabelList(labels), key))
	}
	if len(conflicts) == 0 {
		return nil
	}
	return fmt.Errorf("scan artifact path collision: %s", strings.Join(conflicts, "; "))
}

func humanArtifactLabelList(labels []string) string {
	switch len(labels) {
	case 0:
		return ""
	case 1:
		return labels[0]
	case 2:
		return labels[0] + " and " + labels[1]
	default:
		return strings.Join(labels[:len(labels)-1], ", ") + ", and " + labels[len(labels)-1]
	}
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
