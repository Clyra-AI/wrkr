package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	"github.com/Clyra-AI/wrkr/core/state"
	verifycore "github.com/Clyra-AI/wrkr/core/verify"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
	"github.com/Clyra-AI/wrkr/internal/statelock"
)

const (
	managedArtifactTransactionVersion = "v2"
	managedArtifactTransactionName    = ".wrkr-managed-transaction.json"
	managedArtifactTransactionDir     = "transactions"
)

type managedArtifactVerificationMode uint8

const (
	managedArtifactVerificationStructural managedArtifactVerificationMode = iota
	managedArtifactVerificationFull
)

type managedArtifactSnapshot struct {
	path    string
	existed bool
	payload []byte
	perm    os.FileMode
}

type managedArtifactFile struct {
	label string
	path  string
}

type managedArtifactTransaction struct {
	journalPath string
	snapshots   []managedArtifactSnapshot
	lease       *statelock.Lease
	completed   bool
}

type managedArtifactTransactionJournal struct {
	Version         string                               `json:"version"`
	StatePathSHA256 string                               `json:"state_path_sha256"`
	Operation       string                               `json:"operation"`
	Artifacts       []managedArtifactTransactionArtifact `json:"artifacts"`
}

type managedArtifactTransactionArtifact struct {
	Label   string      `json:"label"`
	Path    string      `json:"path"`
	Existed bool        `json:"existed"`
	Payload []byte      `json:"payload,omitempty"`
	Perm    os.FileMode `json:"perm,omitempty"`
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

func recoverManagedArtifactTransaction(statePath string) error {
	legacyPath := legacyManagedArtifactTransactionPath(statePath)
	if _, err := os.Lstat(legacyPath); err == nil {
		return unsafeManagedArtifactPathError{err: fmt.Errorf(
			"legacy repo-local managed artifact transaction is untrusted and will not be replayed: %s; remove it only after reviewing the affected state directory",
			legacyPath,
		)}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect legacy managed artifact transaction: %w", err)
	}

	journalPath, err := managedArtifactTransactionPath(statePath)
	if err != nil {
		return err
	}
	payload, err := readTrustedManagedArtifactJournal(journalPath)
	if err != nil {
		return err
	}
	if payload == nil {
		return nil
	}

	var journal managedArtifactTransactionJournal
	if err := json.Unmarshal(payload, &journal); err != nil {
		return fmt.Errorf("parse managed artifact transaction: %w", err)
	}
	if strings.TrimSpace(journal.Version) != managedArtifactTransactionVersion {
		return fmt.Errorf("managed artifact transaction has unsupported version %q", journal.Version)
	}
	expectedStatePathSHA, err := managedArtifactStatePathSHA256(statePath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(journal.StatePathSHA256) != expectedStatePathSHA {
		return unsafeManagedArtifactPathError{err: fmt.Errorf("managed artifact transaction state binding mismatch")}
	}
	if len(journal.Artifacts) == 0 {
		return fmt.Errorf("managed artifact transaction has no artifacts")
	}

	root := managedArtifactRoot(statePath)
	snapshots := make([]managedArtifactSnapshot, 0, len(journal.Artifacts))
	seen := make(map[string]struct{}, len(journal.Artifacts))
	for _, artifact := range journal.Artifacts {
		resolvedPath, resolveErr := managedArtifactPathFromJournal(root, artifact.Path)
		if resolveErr != nil {
			return resolveErr
		}
		canonicalPath, canonicalErr := canonicalArtifactPath(resolvedPath)
		if canonicalErr != nil {
			return unsafeManagedArtifactPathError{err: fmt.Errorf("resolve managed artifact recovery path: %w", canonicalErr)}
		}
		if _, ok := seen[canonicalPath]; ok {
			return unsafeManagedArtifactPathError{err: fmt.Errorf("managed artifact transaction contains duplicate recovery path %q", artifact.Path)}
		}
		seen[canonicalPath] = struct{}{}
		snapshots = append(snapshots, managedArtifactSnapshot{
			path:    resolvedPath,
			existed: artifact.Existed,
			payload: append([]byte(nil), artifact.Payload...),
			perm:    artifact.Perm,
		})
	}
	if err := restoreManagedArtifacts(snapshots); err != nil {
		return fmt.Errorf("recover managed artifact transaction: %w", err)
	}
	if err := os.Remove(journalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove recovered managed artifact transaction: %w", err)
	}
	return nil
}

func beginManagedArtifactTransaction(statePath string, operation string, files []managedArtifactFile) (*managedArtifactTransaction, error) {
	lease, err := statelock.Acquire(context.Background(), statePath)
	if err != nil {
		return nil, err
	}
	tx, err := beginManagedArtifactTransactionWithLease(statePath, operation, files, lease)
	if err != nil {
		if releaseErr := lease.Release(); releaseErr != nil {
			return nil, fmt.Errorf("%v (release managed artifact lock: %v)", err, releaseErr)
		}
		return nil, err
	}
	tx.lease = lease
	return tx, nil
}

// beginManagedArtifactTransactionWithLease starts a transaction while the caller
// holds the state-directory lease for the complete operation.
func beginManagedArtifactTransactionWithLease(statePath string, operation string, files []managedArtifactFile, lease *statelock.Lease) (*managedArtifactTransaction, error) {
	if lease == nil {
		return nil, fmt.Errorf("managed artifact transaction requires a state lease")
	}
	if err := recoverManagedArtifactTransaction(statePath); err != nil {
		return nil, err
	}
	normalizedFiles, err := normalizeManagedArtifactFiles(files)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(normalizedFiles))
	for _, file := range normalizedFiles {
		paths = append(paths, file.path)
	}
	snapshots, err := captureManagedArtifacts(paths...)
	if err != nil {
		return nil, err
	}
	journalPath, err := managedArtifactTransactionPath(statePath)
	if err != nil {
		return nil, err
	}
	journal, err := newManagedArtifactTransactionJournal(statePath, managedArtifactRoot(statePath), operation, normalizedFiles, snapshots)
	if err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal managed artifact transaction: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := atomicwrite.WriteFile(journalPath, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("write managed artifact transaction: %w", err)
	}
	return &managedArtifactTransaction{
		journalPath: journalPath,
		snapshots:   snapshots,
	}, nil
}

func (tx *managedArtifactTransaction) Rollback(actionErr error) error {
	if tx == nil {
		return actionErr
	}
	if tx.completed {
		return actionErr
	}
	restoreErr := restoreManagedArtifacts(tx.snapshots)
	removeErr := os.Remove(tx.journalPath)
	if errors.Is(removeErr, os.ErrNotExist) {
		removeErr = nil
	}
	tx.completed = true
	releaseErr := tx.releaseLease()

	if restoreErr != nil && removeErr != nil && releaseErr != nil {
		return fmt.Errorf("%v (rollback restore failed: %v; transaction cleanup failed: %v; lock release failed: %v)", actionErr, restoreErr, removeErr, releaseErr)
	}
	if restoreErr != nil && removeErr != nil {
		return fmt.Errorf("%v (rollback restore failed: %v; transaction cleanup failed: %v)", actionErr, restoreErr, removeErr)
	}
	if restoreErr != nil && releaseErr != nil {
		return fmt.Errorf("%v (rollback restore failed: %v; lock release failed: %v)", actionErr, restoreErr, releaseErr)
	}
	if restoreErr != nil {
		return fmt.Errorf("%v (rollback restore failed: %v)", actionErr, restoreErr)
	}
	if removeErr != nil && releaseErr != nil {
		return fmt.Errorf("%v (transaction cleanup failed: %v; lock release failed: %v)", actionErr, removeErr, releaseErr)
	}
	if removeErr != nil {
		return fmt.Errorf("%v (transaction cleanup failed: %v)", actionErr, removeErr)
	}
	if releaseErr != nil {
		return fmt.Errorf("%v (lock release failed: %v)", actionErr, releaseErr)
	}
	return actionErr
}

func (tx *managedArtifactTransaction) Complete() error {
	if tx == nil || tx.completed {
		return nil
	}
	if err := os.Remove(tx.journalPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove managed artifact transaction: %w", err)
	}
	tx.completed = true
	return tx.releaseLease()
}

func (tx *managedArtifactTransaction) releaseLease() error {
	if tx == nil || tx.lease == nil {
		return nil
	}
	lease := tx.lease
	tx.lease = nil
	return lease.Release()
}

func managedArtifactRoot(statePath string) string {
	cleanStatePath := filepath.Clean(strings.TrimSpace(statePath))
	if cleanStatePath == "" || cleanStatePath == "." {
		cleanStatePath = state.ResolvePath("")
	}
	dir := filepath.Dir(cleanStatePath)
	if strings.TrimSpace(dir) == "" {
		dir = "."
	}
	return dir
}

func legacyManagedArtifactTransactionPath(statePath string) string {
	return filepath.Join(managedArtifactRoot(statePath), managedArtifactTransactionName)
}

func managedArtifactTransactionPath(statePath string) (string, error) {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("resolve private managed artifact transaction directory: %w", err)
	}
	transactionDir := filepath.Join(cacheDir, "wrkr", managedArtifactTransactionDir)
	if err := os.MkdirAll(transactionDir, 0o700); err != nil {
		return "", fmt.Errorf("create private managed artifact transaction directory: %w", err)
	}
	info, err := os.Lstat(transactionDir)
	if err != nil {
		return "", fmt.Errorf("inspect private managed artifact transaction directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", unsafeManagedArtifactPathError{err: fmt.Errorf("private managed artifact transaction path must be a real directory: %s", transactionDir)}
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(transactionDir, 0o700); err != nil {
			return "", fmt.Errorf("secure private managed artifact transaction directory: %w", err)
		}
	}
	statePathSHA, err := managedArtifactStatePathSHA256(statePath)
	if err != nil {
		return "", err
	}
	return filepath.Join(transactionDir, statePathSHA+".json"), nil
}

func managedArtifactStatePathSHA256(statePath string) (string, error) {
	cleanStatePath := filepath.Clean(strings.TrimSpace(statePath))
	if cleanStatePath == "" || cleanStatePath == "." {
		cleanStatePath = state.ResolvePath("")
	}
	absStatePath, err := filepath.Abs(cleanStatePath)
	if err != nil {
		return "", fmt.Errorf("resolve managed artifact state path: %w", err)
	}
	sum := sha256.Sum256([]byte(filepath.Clean(absStatePath)))
	return fmt.Sprintf("%x", sum[:]), nil
}

func validateTrustedManagedArtifactJournal(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("inspect managed artifact transaction: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return unsafeManagedArtifactPathError{err: fmt.Errorf("managed artifact transaction must be a regular file, not a link or special file: %s", path)}
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return unsafeManagedArtifactPathError{err: fmt.Errorf("managed artifact transaction permissions are too broad: %s", path)}
	}
	return nil
}

func readTrustedManagedArtifactJournal(path string) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("inspect managed artifact transaction: %w", err)
	}
	if err := validateTrustedManagedArtifactJournal(path); err != nil {
		return nil, err
	}
	file, err := os.Open(path) // #nosec G304 -- path is state-derived inside Wrkr's private user cache and identity-checked below.
	if err != nil {
		return nil, fmt.Errorf("open managed artifact transaction: %w", err)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened managed artifact transaction: %w", err)
	}
	if !opened.Mode().IsRegular() {
		return nil, unsafeManagedArtifactPathError{err: fmt.Errorf("opened managed artifact transaction is not a regular file: %s", path)}
	}
	if runtime.GOOS != "windows" && opened.Mode().Perm()&0o077 != 0 {
		return nil, unsafeManagedArtifactPathError{err: fmt.Errorf("opened managed artifact transaction permissions are too broad: %s", path)}
	}
	after, err := os.Lstat(path)
	if err != nil {
		return nil, unsafeManagedArtifactPathError{err: fmt.Errorf("reinspect managed artifact transaction: %w", err)}
	}
	if !os.SameFile(before, opened) || !os.SameFile(after, opened) {
		return nil, unsafeManagedArtifactPathError{err: fmt.Errorf("managed artifact transaction changed while it was being opened: %s", path)}
	}
	payload, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("read managed artifact transaction: %w", err)
	}
	return payload, nil
}

func normalizeManagedArtifactFiles(files []managedArtifactFile) ([]managedArtifactFile, error) {
	out := make([]managedArtifactFile, 0, len(files))
	seen := map[string]struct{}{}
	for _, file := range files {
		path, err := normalizeManagedArtifactPath(file.path)
		if err != nil {
			if strings.TrimSpace(file.path) == "" {
				continue
			}
			return nil, err
		}
		if path == "" || path == "." {
			continue
		}
		key := filepath.Clean(path)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		label := strings.TrimSpace(file.label)
		if label == "" {
			label = filepath.Base(key)
		}
		out = append(out, managedArtifactFile{label: label, path: key})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("managed artifact transaction requires at least one artifact")
	}
	return out, nil
}

func newManagedArtifactTransactionJournal(statePath string, root string, operation string, files []managedArtifactFile, snapshots []managedArtifactSnapshot) (managedArtifactTransactionJournal, error) {
	statePathSHA, err := managedArtifactStatePathSHA256(statePath)
	if err != nil {
		return managedArtifactTransactionJournal{}, err
	}
	snapshotByPath := make(map[string]managedArtifactSnapshot, len(snapshots))
	for _, snapshot := range snapshots {
		snapshotByPath[filepath.Clean(snapshot.path)] = snapshot
	}

	artifacts := make([]managedArtifactTransactionArtifact, 0, len(files))
	for _, file := range files {
		snapshot, ok := snapshotByPath[filepath.Clean(file.path)]
		if !ok {
			return managedArtifactTransactionJournal{}, fmt.Errorf("missing managed artifact snapshot for %s", file.path)
		}
		portablePath, err := managedArtifactPathForJournal(root, file.path)
		if err != nil {
			return managedArtifactTransactionJournal{}, err
		}
		artifacts = append(artifacts, managedArtifactTransactionArtifact{
			Label:   strings.TrimSpace(file.label),
			Path:    portablePath,
			Existed: snapshot.existed,
			Payload: append([]byte(nil), snapshot.payload...),
			Perm:    snapshot.perm,
		})
	}
	return managedArtifactTransactionJournal{
		Version:         managedArtifactTransactionVersion,
		StatePathSHA256: statePathSHA,
		Operation:       strings.TrimSpace(operation),
		Artifacts:       artifacts,
	}, nil
}

func managedArtifactPathForJournal(root string, path string) (string, error) {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve managed artifact transaction root: %w", err)
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve managed artifact path: %w", err)
	}
	rel, err := filepath.Rel(absRoot, absPath)
	if err != nil {
		return "", fmt.Errorf("relativize managed artifact path: %w", err)
	}
	return filepath.ToSlash(filepath.Clean(rel)), nil
}

func managedArtifactPathFromJournal(root string, journalPath string) (string, error) {
	cleanPath := filepath.Clean(filepath.FromSlash(strings.TrimSpace(journalPath)))
	if cleanPath == "" || cleanPath == "." || filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("managed artifact transaction path must be relative: %q", journalPath)
	}
	return filepath.Clean(filepath.Join(root, cleanPath)), nil
}

func preflightManagedArtifactRead(statePath string) error {
	if err := recoverManagedArtifactTransaction(statePath); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Clean(strings.TrimSpace(statePath))); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat managed state artifact: %w", err)
	}
	return verifyManagedArtifactConsistency(statePath, managedArtifactVerificationStructural)
}

func preflightManagedArtifactScoreRead(statePath string) error {
	resolvedStatePath := filepath.Clean(strings.TrimSpace(statePath))
	if resolvedStatePath == "" || resolvedStatePath == "." {
		resolvedStatePath = state.ResolvePath("")
	}
	if err := recoverManagedArtifactTransaction(resolvedStatePath); err != nil {
		return err
	}
	if _, err := os.Stat(resolvedStatePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat managed state artifact: %w", err)
	}
	for _, path := range []string{
		manifest.ResolvePath(resolvedStatePath),
		lifecycle.ChainPath(resolvedStatePath),
	} {
		if _, err := os.Stat(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("managed artifact consistency %s: %w", filepath.Base(path), err)
		}
	}
	proofChainPath := proofemit.ChainPath(resolvedStatePath)
	proofChainInfo, err := os.Stat(proofChainPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("managed artifact consistency proof chain: %w", err)
	}
	if proofChainInfo.Size() == 0 {
		return nil
	}
	if _, err := os.Stat(proofemit.SigningKeyPath(resolvedStatePath)); err != nil {
		return fmt.Errorf("managed artifact consistency proof signing key: %w", err)
	}
	if _, err := os.Stat(proofemit.ChainAttestationPath(proofChainPath)); err != nil {
		return fmt.Errorf("managed artifact consistency proof attestation: %w", err)
	}
	return nil
}

func verifyManagedArtifactConsistency(statePath string, mode managedArtifactVerificationMode) error {
	resolvedStatePath := filepath.Clean(strings.TrimSpace(statePath))
	if resolvedStatePath == "" || resolvedStatePath == "." {
		resolvedStatePath = state.ResolvePath("")
	}
	snapshot, err := state.Load(resolvedStatePath)
	if err != nil {
		return fmt.Errorf("managed artifact consistency state: %w", err)
	}
	manifestPath := manifest.ResolvePath(resolvedStatePath)
	manifestExists := true
	if _, err := os.Stat(manifestPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			manifestExists = false
		} else {
			return fmt.Errorf("managed artifact consistency manifest: %w", err)
		}
	}
	if manifestExists {
		loadedManifest, err := manifest.Load(manifestPath)
		if err != nil {
			return fmt.Errorf("managed artifact consistency manifest: %w", err)
		}
		if !reflect.DeepEqual(normalizedManagedIdentities(snapshot.Identities), normalizedManagedIdentities(loadedManifest.Identities)) {
			return fmt.Errorf("managed artifact consistency mismatch: state and manifest identities differ")
		}
	}

	lifecyclePath := lifecycle.ChainPath(resolvedStatePath)
	lifecycleExists := true
	if _, err := os.Stat(lifecyclePath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			lifecycleExists = false
		} else {
			return fmt.Errorf("managed artifact consistency lifecycle chain: %w", err)
		}
	}
	if lifecycleExists {
		if _, err := lifecycle.LoadChain(lifecyclePath); err != nil {
			return fmt.Errorf("managed artifact consistency lifecycle chain: %w", err)
		}
	}

	proofChainPath := proofemit.ChainPath(resolvedStatePath)
	proofChainInfo, err := os.Stat(proofChainPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("managed artifact consistency proof chain: %w", err)
	}
	if mode == managedArtifactVerificationStructural {
		if proofChainInfo.Size() == 0 {
			return nil
		}
		if _, err := os.Stat(proofemit.SigningKeyPath(resolvedStatePath)); err != nil {
			return fmt.Errorf("managed artifact consistency proof signing key: %w", err)
		}
		if _, err := os.Stat(proofemit.ChainAttestationPath(proofChainPath)); err != nil {
			return fmt.Errorf("managed artifact consistency proof attestation: %w", err)
		}
		return nil
	}
	proofChain, err := proofemit.LoadChain(proofChainPath)
	if err != nil {
		return fmt.Errorf("managed artifact consistency proof chain: %w", err)
	}
	if proofChain != nil && len(proofChain.Records) > 0 {
		if _, err := os.Stat(proofemit.SigningKeyPath(resolvedStatePath)); err != nil {
			return fmt.Errorf("managed artifact consistency proof signing key: %w", err)
		}
		if _, err := os.Stat(proofemit.ChainAttestationPath(proofChainPath)); err != nil {
			return fmt.Errorf("managed artifact consistency proof attestation: %w", err)
		}
		if mode == managedArtifactVerificationFull {
			publicKey, keyErr := proofemit.LoadVerifierKey(resolvedStatePath)
			var result verifycore.Result
			if keyErr == nil {
				result, err = verifycore.ChainWithPublicKey(proofChainPath, publicKey)
			} else if errors.Is(keyErr, os.ErrNotExist) {
				result, err = verifycore.Chain(proofChainPath)
			} else {
				return fmt.Errorf("managed artifact consistency proof signing key: %w", keyErr)
			}
			if err != nil {
				return fmt.Errorf("managed artifact consistency proof verification: %w", err)
			}
			if !result.Intact {
				return fmt.Errorf("managed artifact consistency proof verification failed: %s", result.Reason)
			}
		}
	}
	return nil
}
func normalizedManagedIdentities(records []manifest.IdentityRecord) []manifest.IdentityRecord {
	out := append([]manifest.IdentityRecord(nil), model.FilterLegacyArtifactIdentityRecords(records)...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].AgentID != out[j].AgentID {
			return out[i].AgentID < out[j].AgentID
		}
		if out[i].Repo != out[j].Repo {
			return out[i].Repo < out[j].Repo
		}
		return out[i].Location < out[j].Location
	})
	return out
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

func emitManagedArtifactReadError(stderr io.Writer, jsonOut bool, err error) int {
	if isUnsafeManagedArtifactPathError(err) {
		return emitError(stderr, jsonOut, "unsafe_operation_blocked", err.Error(), exitUnsafeBlocked)
	}
	return emitError(stderr, jsonOut, "runtime_failure", err.Error(), exitRuntime)
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
