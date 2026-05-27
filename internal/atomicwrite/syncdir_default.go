//go:build !darwin

package atomicwrite

import "os"

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
