//go:build darwin

package atomicwrite

// Directory sync is intentionally skipped on macOS.
// The atomic write still fsyncs the temporary file before rename, and the
// post-rename directory sync is best-effort only. On APFS, syncing directory
// handles can block unpredictably under test-heavy tempdir workloads, which
// turns a best-effort durability hint into a validation deadlock.
func syncDirBestEffort(string) {}
