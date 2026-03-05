package atomicwrite

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Options struct {
	BeforeRename func(path string, tempPath string) error
}

var (
	pathLocksMu sync.Mutex
	pathLocks   = map[string]*sync.Mutex{}

	beforeRenameHookMu sync.Mutex
	beforeRenameHook   func(path string, tempPath string) error
)

func WriteFile(path string, payload []byte, perm os.FileMode) error {
	return WriteFileWithOptions(path, payload, perm, Options{})
}

func WriteFileWithOptions(path string, payload []byte, perm os.FileMode, opts Options) error {
	cleanPath, err := resolveCommitPath(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(cleanPath)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("mkdir atomic-write dir: %w", err)
	}

	lock := pathLock(cleanPath)
	lock.Lock()
	defer lock.Unlock()

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(cleanPath)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create atomic temp: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write atomic temp: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod atomic temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync atomic temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close atomic temp: %w", err)
	}

	if opts.BeforeRename != nil {
		if err := opts.BeforeRename(cleanPath, tmpPath); err != nil {
			return fmt.Errorf("before atomic rename: %w", err)
		}
	}
	if err := invokeBeforeRenameHook(cleanPath, tmpPath); err != nil {
		return fmt.Errorf("before atomic rename: %w", err)
	}

	if err := os.Rename(tmpPath, cleanPath); err != nil { // #nosec G703 -- caller-selected artifact path is intentional for deterministic local persistence.
		return fmt.Errorf("commit atomic write: %w", err)
	}
	committed = true
	syncDirBestEffort(dir)
	return nil
}

func resolveCommitPath(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	info, err := os.Lstat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return cleanPath, nil
		}
		return "", fmt.Errorf("stat atomic-write path: %w", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return cleanPath, nil
	}

	targetPath, err := os.Readlink(cleanPath)
	if err != nil {
		return "", fmt.Errorf("read atomic-write symlink target: %w", err)
	}
	if !filepath.IsAbs(targetPath) {
		parentDir, err := filepath.EvalSymlinks(filepath.Dir(cleanPath))
		if err != nil {
			return "", fmt.Errorf("resolve atomic-write symlink parent: %w", err)
		}
		targetPath = filepath.Join(parentDir, targetPath)
	}
	return filepath.Clean(targetPath), nil
}

// SetBeforeRenameHookForTest installs a process-wide hook used by tests to
// simulate interruptions between file sync and rename commit.
func SetBeforeRenameHookForTest(hook func(path string, tempPath string) error) (restore func()) {
	beforeRenameHookMu.Lock()
	previous := beforeRenameHook
	beforeRenameHook = hook
	beforeRenameHookMu.Unlock()
	return func() {
		beforeRenameHookMu.Lock()
		beforeRenameHook = previous
		beforeRenameHookMu.Unlock()
	}
}

func pathLock(path string) *sync.Mutex {
	pathLocksMu.Lock()
	defer pathLocksMu.Unlock()
	lock, ok := pathLocks[path]
	if ok {
		return lock
	}
	lock = &sync.Mutex{}
	pathLocks[path] = lock
	return lock
}

func invokeBeforeRenameHook(path string, tempPath string) error {
	beforeRenameHookMu.Lock()
	hook := beforeRenameHook
	beforeRenameHookMu.Unlock()
	if hook == nil {
		return nil
	}
	return hook(path, tempPath)
}

func syncDirBestEffort(dir string) {
	handle, err := os.Open(dir) // #nosec G304 -- dir derives from caller-selected local artifact path.
	if err != nil {
		return
	}
	defer func() {
		_ = handle.Close()
	}()
	_ = handle.Sync()
}
