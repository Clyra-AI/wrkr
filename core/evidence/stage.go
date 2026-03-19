package evidence

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	beforePublishHookMu sync.Mutex
	beforePublishHook   func(stageDir, targetDir, backupDir string) error
)

func validateOutputDirTarget(path string) error {
	cleanPath := filepath.Clean(path)
	info, err := os.Lstat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("lstat output dir: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return newOutputDirSafetyError("output dir must not be a symlink: %s", cleanPath)
	}
	if !info.IsDir() {
		return newOutputDirSafetyError("output dir is not a directory: %s", cleanPath)
	}
	entries, err := os.ReadDir(cleanPath)
	if err != nil {
		return fmt.Errorf("read output dir: %w", err)
	}
	if len(entries) == 0 {
		return nil
	}
	return validateManagedOutputDir(cleanPath)
}

func validateManagedOutputDir(path string) error {
	markerPath := filepath.Join(path, outputDirMarkerFile)
	markerInfo, err := os.Lstat(markerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return newOutputDirSafetyError("output dir is not empty and not managed by wrkr evidence: %s", path)
		}
		return fmt.Errorf("stat output dir marker: %w", err)
	}
	if !markerInfo.Mode().IsRegular() {
		return newOutputDirSafetyError("output dir marker is not a regular file: %s", markerPath)
	}
	markerPayload, err := os.ReadFile(markerPath) // #nosec G304 -- marker path is deterministic under the selected local output directory.
	if err != nil {
		return fmt.Errorf("read output dir marker: %w", err)
	}
	if string(markerPayload) != outputDirMarkerContent {
		return newOutputDirSafetyError("output dir marker content is invalid: %s", markerPath)
	}
	return nil
}

func createOutputStageDir(targetDir string) (string, error) {
	cleanTarget := filepath.Clean(targetDir)
	parentDir := filepath.Dir(cleanTarget)
	if err := os.MkdirAll(parentDir, 0o750); err != nil {
		return "", fmt.Errorf("mkdir output dir parent: %w", err)
	}
	stageDir, err := os.MkdirTemp(parentDir, "."+filepath.Base(cleanTarget)+".stage-*")
	if err != nil {
		return "", fmt.Errorf("create output stage dir: %w", err)
	}
	if err := writeOutputDirMarker(stageDir); err != nil {
		_ = os.RemoveAll(stageDir)
		return "", err
	}
	return stageDir, nil
}

func publishStagedOutput(stageDir string, targetDir string) error {
	cleanStage := filepath.Clean(stageDir)
	cleanTarget := filepath.Clean(targetDir)
	parentDir := filepath.Dir(cleanTarget)
	if filepath.Dir(cleanStage) != parentDir {
		return fmt.Errorf("stage dir must share parent with output dir")
	}

	backupDir := filepath.Join(parentDir, fmt.Sprintf(".%s.backup-%d", filepath.Base(cleanTarget), time.Now().UTC().UnixNano()))
	movedTarget := false

	if _, err := os.Lstat(cleanTarget); err == nil {
		if err := os.Rename(cleanTarget, backupDir); err != nil {
			return fmt.Errorf("move existing output dir aside: %w", err)
		}
		movedTarget = true
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("lstat output dir before publish: %w", err)
	}

	if err := invokeBeforePublishHook(cleanStage, cleanTarget, backupDir); err != nil {
		if restoreErr := restoreOutputDir(cleanTarget, backupDir, movedTarget); restoreErr != nil {
			return fmt.Errorf("before publish swap: %w (restore output dir: %v)", err, restoreErr)
		}
		return fmt.Errorf("before publish swap: %w", err)
	}

	if err := os.Rename(cleanStage, cleanTarget); err != nil {
		if restoreErr := restoreOutputDir(cleanTarget, backupDir, movedTarget); restoreErr != nil {
			return fmt.Errorf("publish staged output: %w (restore output dir: %v)", err, restoreErr)
		}
		return fmt.Errorf("publish staged output: %w", err)
	}

	if movedTarget {
		_ = os.RemoveAll(backupDir)
	}
	return nil
}

func restoreOutputDir(targetDir string, backupDir string, movedTarget bool) error {
	if !movedTarget {
		return nil
	}
	if _, err := os.Lstat(targetDir); err == nil {
		if removeErr := os.RemoveAll(targetDir); removeErr != nil {
			return fmt.Errorf("remove incomplete published dir: %w", removeErr)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("lstat incomplete published dir: %w", err)
	}
	if err := os.Rename(backupDir, targetDir); err != nil {
		return err
	}
	return nil
}

func invokeBeforePublishHook(stageDir string, targetDir string, backupDir string) error {
	beforePublishHookMu.Lock()
	hook := beforePublishHook
	beforePublishHookMu.Unlock()
	if hook == nil {
		return nil
	}
	return hook(stageDir, targetDir, backupDir)
}

func setBeforePublishHookForTest(hook func(stageDir, targetDir, backupDir string) error) func() {
	beforePublishHookMu.Lock()
	previous := beforePublishHook
	beforePublishHook = hook
	beforePublishHookMu.Unlock()
	return func() {
		beforePublishHookMu.Lock()
		beforePublishHook = previous
		beforePublishHookMu.Unlock()
	}
}

func stageDirGlob(targetDir string) string {
	cleanTarget := filepath.Clean(targetDir)
	return filepath.Join(filepath.Dir(cleanTarget), "."+filepath.Base(cleanTarget)+".stage-*")
}

func backupDirPrefix(targetDir string) string {
	cleanTarget := filepath.Clean(targetDir)
	return filepath.Join(filepath.Dir(cleanTarget), "."+filepath.Base(cleanTarget)+".backup-")
}
