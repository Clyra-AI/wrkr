package owners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveOwnerFromCodeowners(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	content := "* @acme/platform\n.github/workflows/* @acme/security\n"
	if err := os.WriteFile(filepath.Join(root, "CODEOWNERS"), []byte(content), 0o600); err != nil {
		t.Fatalf("write CODEOWNERS: %v", err)
	}
	owner := ResolveOwner(root, "acme/repo", "acme", ".github/workflows/scan.yml")
	if owner != "@acme/security" {
		t.Fatalf("unexpected owner: %s", owner)
	}
}

func TestResolveOwnerFallback(t *testing.T) {
	t.Parallel()
	owner := ResolveOwner(t.TempDir(), "acme/payments-service", "acme", ".cursor/mcp.json")
	if owner != "@acme/payments" {
		t.Fatalf("unexpected fallback owner: %s", owner)
	}
}
