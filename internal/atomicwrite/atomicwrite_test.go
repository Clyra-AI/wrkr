package atomicwrite

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWriteFilePreservesSymlinkAndUpdatesTarget(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	targetDir := filepath.Join(root, "target")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("mkdir target dir: %v", err)
	}
	targetPath := filepath.Join(targetDir, "state.json")
	if err := os.WriteFile(targetPath, []byte("old\n"), 0o600); err != nil {
		t.Fatalf("seed target file: %v", err)
	}

	linkPath := filepath.Join(root, "state-link.json")
	relativeTarget, err := filepath.Rel(filepath.Dir(linkPath), targetPath)
	if err != nil {
		t.Fatalf("relative target: %v", err)
	}
	if err := os.Symlink(relativeTarget, linkPath); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}

	expected := []byte("{\"status\":\"ok\"}\n")
	if err := WriteFile(linkPath, expected, 0o600); err != nil {
		t.Fatalf("write through symlink: %v", err)
	}

	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("lstat symlink: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink to remain in place, mode=%v", info.Mode())
	}

	got, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read target file: %v", err)
	}
	if string(got) != string(expected) {
		t.Fatalf("unexpected target content:\n got=%q\nwant=%q", string(got), string(expected))
	}
}

func TestWriteFileCreatesMissingSymlinkTarget(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	targetDir := filepath.Join(root, "target")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("mkdir target dir: %v", err)
	}

	targetPath := filepath.Join(targetDir, "missing.json")
	linkPath := filepath.Join(root, "state-link.json")
	relativeTarget, err := filepath.Rel(filepath.Dir(linkPath), targetPath)
	if err != nil {
		t.Fatalf("relative target: %v", err)
	}
	if err := os.Symlink(relativeTarget, linkPath); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}

	expected := []byte("{\"created\":true}\n")
	if err := WriteFile(linkPath, expected, 0o600); err != nil {
		t.Fatalf("write through symlink: %v", err)
	}

	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("lstat symlink: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected symlink to remain in place, mode=%v", info.Mode())
	}

	got, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("read created target file: %v", err)
	}
	if string(got) != string(expected) {
		t.Fatalf("unexpected target content:\n got=%q\nwant=%q", string(got), string(expected))
	}
}
