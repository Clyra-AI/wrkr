package org

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

const (
	checkpointVersion       = "v1"
	checkpointRootName      = "org-checkpoints"
	checkpointMarkerFile    = ".wrkr-org-checkpoints-managed"
	checkpointMarkerContent = "managed by wrkr org checkpoints\n"
)

type checkpointInputError struct {
	message string
}

func (e *checkpointInputError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

type checkpointSafetyError struct {
	message string
}

func (e *checkpointSafetyError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func IsCheckpointInputError(err error) bool {
	var target *checkpointInputError
	return errors.As(err, &target)
}

func IsCheckpointSafetyError(err error) bool {
	var target *checkpointSafetyError
	return errors.As(err, &target)
}

func newCheckpointInputError(format string, args ...any) error {
	return &checkpointInputError{message: fmt.Sprintf(format, args...)}
}

func newCheckpointSafetyError(format string, args ...any) error {
	return &checkpointSafetyError{message: fmt.Sprintf(format, args...)}
}

type checkpointState struct {
	Version          string   `json:"version"`
	Org              string   `json:"org"`
	MaterializedRoot string   `json:"materialized_root"`
	Repos            []string `json:"repos"`
	CompletedRepos   []string `json:"completed_repos"`
}

type checkpointManager struct {
	path  string
	state checkpointState
	mu    sync.Mutex
}

func checkpointPath(statePath, org string) (string, error) {
	root, err := prepareCheckpointRoot(statePath)
	if err != nil {
		return "", err
	}
	return filepath.Join(root, checkpointFileName(org)+".json"), nil
}

func prepareCheckpointRoot(statePath string) (string, error) {
	cleanState := filepath.Clean(strings.TrimSpace(statePath))
	if cleanState == "" || cleanState == "." {
		return "", fmt.Errorf("state path is required for org scan checkpoints")
	}
	root := filepath.Join(filepath.Dir(cleanState), checkpointRootName)

	info, err := os.Lstat(root)
	if err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(root, 0o750); err != nil {
				return "", fmt.Errorf("create org checkpoint root: %w", err)
			}
			if err := writeCheckpointMarker(root); err != nil {
				return "", err
			}
			return root, nil
		}
		return "", fmt.Errorf("stat org checkpoint root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return "", newCheckpointSafetyError("org checkpoint root must not be a symlink: %s", root)
	}
	if !info.IsDir() {
		return "", newCheckpointSafetyError("org checkpoint root is not a directory: %s", root)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		return "", fmt.Errorf("read org checkpoint root: %w", err)
	}
	if len(entries) == 0 {
		if err := writeCheckpointMarker(root); err != nil {
			return "", err
		}
		return root, nil
	}

	markerPath := filepath.Join(root, checkpointMarkerFile)
	markerInfo, err := os.Lstat(markerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", newCheckpointSafetyError("org checkpoint root is not empty and not managed by wrkr scan: %s", root)
		}
		return "", fmt.Errorf("stat org checkpoint root marker: %w", err)
	}
	if !markerInfo.Mode().IsRegular() {
		return "", newCheckpointSafetyError("org checkpoint root marker is not a regular file: %s", markerPath)
	}
	payload, err := os.ReadFile(markerPath) // #nosec G304 -- marker path is deterministic under the selected state directory.
	if err != nil {
		return "", fmt.Errorf("read org checkpoint root marker: %w", err)
	}
	if string(payload) != checkpointMarkerContent {
		return "", newCheckpointSafetyError("org checkpoint root marker content is invalid: %s", markerPath)
	}
	return root, nil
}

func writeCheckpointMarker(root string) error {
	markerPath := filepath.Join(root, checkpointMarkerFile)
	if err := os.WriteFile(markerPath, []byte(checkpointMarkerContent), 0o600); err != nil {
		return fmt.Errorf("write org checkpoint root marker: %w", err)
	}
	return nil
}

func checkpointFileName(org string) string {
	trimmed := strings.TrimSpace(strings.ToLower(org))
	if trimmed == "" {
		return "org"
	}
	var b strings.Builder
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func newCheckpointManager(path string, org string, repos []string, materializedRoot string) *checkpointManager {
	sortedRepos := append([]string(nil), repos...)
	sort.Strings(sortedRepos)
	return &checkpointManager{
		path: path,
		state: checkpointState{
			Version:          checkpointVersion,
			Org:              strings.TrimSpace(org),
			MaterializedRoot: filepath.Clean(strings.TrimSpace(materializedRoot)),
			Repos:            sortedRepos,
			CompletedRepos:   []string{},
		},
	}
}

func loadCheckpointManager(path string) (*checkpointManager, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, newCheckpointInputError("resume checkpoint does not exist: %s", path)
		}
		return nil, fmt.Errorf("lstat org checkpoint: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, newCheckpointSafetyError("resume checkpoint file must not be a symlink: %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, newCheckpointSafetyError("resume checkpoint file is not a regular file: %s", path)
	}
	payload, err := os.ReadFile(path) // #nosec G304 -- checkpoint path is deterministic under the selected state directory.
	if err != nil {
		return nil, fmt.Errorf("read org checkpoint: %w", err)
	}
	var state checkpointState
	if err := json.Unmarshal(payload, &state); err != nil {
		return nil, newCheckpointInputError("parse resume checkpoint %s: %v", path, err)
	}
	state.MaterializedRoot = filepath.Clean(strings.TrimSpace(state.MaterializedRoot))
	state.Org = strings.TrimSpace(state.Org)
	state.Repos = uniqueSortedStrings(state.Repos)
	state.CompletedRepos = uniqueSortedStrings(state.CompletedRepos)
	if state.Version == "" {
		state.Version = checkpointVersion
	}
	return &checkpointManager{path: path, state: state}, nil
}

func (m *checkpointManager) validate(org string, repos []string, materializedRoot string) error {
	if m == nil {
		return newCheckpointInputError("resume checkpoint is not available")
	}
	if strings.TrimSpace(m.state.Org) != strings.TrimSpace(org) {
		return newCheckpointInputError("resume checkpoint target mismatch: have %s want %s", m.state.Org, org)
	}
	if m.state.Version != checkpointVersion {
		return newCheckpointInputError("resume checkpoint version mismatch: have %s want %s", m.state.Version, checkpointVersion)
	}
	cleanRoot := filepath.Clean(strings.TrimSpace(materializedRoot))
	if m.state.MaterializedRoot != cleanRoot {
		return newCheckpointInputError("resume checkpoint materialized root mismatch: have %s want %s", m.state.MaterializedRoot, cleanRoot)
	}
	wantRepos := uniqueSortedStrings(repos)
	if len(m.state.Repos) != len(wantRepos) {
		return newCheckpointInputError("resume checkpoint repo-set mismatch: have %d repos want %d", len(m.state.Repos), len(wantRepos))
	}
	for i := range wantRepos {
		if m.state.Repos[i] != wantRepos[i] {
			return newCheckpointInputError("resume checkpoint repo-set mismatch: repo list changed")
		}
	}
	return nil
}

func (m *checkpointManager) save() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.state.Repos = uniqueSortedStrings(m.state.Repos)
	m.state.CompletedRepos = uniqueSortedStrings(m.state.CompletedRepos)
	payload, err := json.MarshalIndent(m.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal org checkpoint: %w", err)
	}
	payload = append(payload, '\n')
	if err := atomicwrite.WriteFile(m.path, payload, 0o600); err != nil {
		return fmt.Errorf("write org checkpoint: %w", err)
	}
	return nil
}

func (m *checkpointManager) completedSet() map[string]struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make(map[string]struct{}, len(m.state.CompletedRepos))
	for _, repo := range m.state.CompletedRepos {
		out[repo] = struct{}{}
	}
	return out
}

func (m *checkpointManager) markCompleted(repo string) error {
	m.mu.Lock()
	for _, existing := range m.state.CompletedRepos {
		if existing == repo {
			m.mu.Unlock()
			return nil
		}
	}
	m.state.CompletedRepos = append(m.state.CompletedRepos, repo)
	m.mu.Unlock()
	return m.save()
}

func uniqueSortedStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
