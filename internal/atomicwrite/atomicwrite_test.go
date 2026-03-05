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

func TestWriteFileResolvesRelativeTargetFromRealSymlinkParent(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	realParent := filepath.Join(root, "real", "nested")
	if err := os.MkdirAll(realParent, 0o755); err != nil {
		t.Fatalf("mkdir real parent: %v", err)
	}

	aliasParent := filepath.Join(root, "alias")
	if err := os.Symlink(realParent, aliasParent); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}

	linkPath := filepath.Join(aliasParent, "state-link.json")
	if err := os.Symlink("../target.json", linkPath); err != nil {
		t.Fatalf("create link file: %v", err)
	}

	correctTarget := filepath.Join(root, "real", "target.json")
	if err := os.WriteFile(correctTarget, []byte("old\n"), 0o600); err != nil {
		t.Fatalf("seed expected target file: %v", err)
	}
	wrongTarget := filepath.Join(root, "target.json")
	if err := os.WriteFile(wrongTarget, []byte("untouched\n"), 0o600); err != nil {
		t.Fatalf("seed wrong target file: %v", err)
	}

	expected := []byte("{\"resolved\":true}\n")
	if err := WriteFile(linkPath, expected, 0o600); err != nil {
		t.Fatalf("write through symlink: %v", err)
	}

	got, err := os.ReadFile(correctTarget)
	if err != nil {
		t.Fatalf("read expected target file: %v", err)
	}
	if string(got) != string(expected) {
		t.Fatalf("unexpected resolved target content:\n got=%q\nwant=%q", string(got), string(expected))
	}

	wrongGot, err := os.ReadFile(wrongTarget)
	if err != nil {
		t.Fatalf("read wrong target file: %v", err)
	}
	if string(wrongGot) != "untouched\n" {
		t.Fatalf("unexpected write to lexical parent target: %q", string(wrongGot))
	}
}
