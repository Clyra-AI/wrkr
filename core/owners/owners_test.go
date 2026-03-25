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

func TestResolveReturnsOwnershipMetadata(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	content := "* @acme/platform\n.github/workflows/* @acme/security\n"
	if err := os.WriteFile(filepath.Join(root, "CODEOWNERS"), []byte(content), 0o600); err != nil {
		t.Fatalf("write CODEOWNERS: %v", err)
	}
	resolution := Resolve(root, "acme/repo", "acme", ".github/workflows/scan.yml")
	if resolution.Owner != "@acme/security" {
		t.Fatalf("unexpected owner: %+v", resolution)
	}
	if resolution.OwnerSource != OwnerSourceCodeowners || resolution.OwnershipStatus != OwnershipStatusExplicit {
		t.Fatalf("expected explicit CODEOWNERS resolution, got %+v", resolution)
	}
}

func TestResolveOwnerFallback(t *testing.T) {
	t.Parallel()
	owner := ResolveOwner(t.TempDir(), "acme/payments-service", "acme", ".cursor/mcp.json")
	if owner != "@acme/payments" {
		t.Fatalf("unexpected fallback owner: %s", owner)
	}
}

func TestResolveFallbackMetadataTracksInferredAndUnresolvedStates(t *testing.T) {
	t.Parallel()

	inferred := Resolve(t.TempDir(), "acme/payments-service", "acme", ".cursor/mcp.json")
	if inferred.OwnerSource != OwnerSourceRepoFallback || inferred.OwnershipStatus != OwnershipStatusInferred {
		t.Fatalf("expected inferred fallback, got %+v", inferred)
	}

	unresolved := Resolve(t.TempDir(), "", "acme", ".cursor/mcp.json")
	if unresolved.OwnerSource != OwnerSourceRepoFallback || unresolved.OwnershipStatus != OwnershipStatusUnresolved {
		t.Fatalf("expected unresolved fallback, got %+v", unresolved)
	}
}
