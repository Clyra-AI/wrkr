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
	if resolution.OwnershipState != OwnershipStateExplicit || resolution.OwnershipConfidence < 0.9 || len(resolution.EvidenceBasis) == 0 {
		t.Fatalf("expected explicit ownership quality metadata, got %+v", resolution)
	}
}

func TestResolveOwnershipFromCustomMappingBeforeFallback(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".wrkr"), 0o750); err != nil {
		t.Fatalf("create .wrkr: %v", err)
	}
	content := []byte("owners:\n  - pattern: .github/workflows/*.yml\n    owner: '@acme/platform'\n")
	if err := os.WriteFile(filepath.Join(root, ".wrkr", "owners.yaml"), content, 0o600); err != nil {
		t.Fatalf("write owners mapping: %v", err)
	}

	resolution := Resolve(root, "acme/payments-service", "acme", ".github/workflows/deploy.yml")
	if resolution.Owner != "@acme/platform" {
		t.Fatalf("expected custom owner mapping, got %+v", resolution)
	}
	if resolution.OwnerSource != OwnerSourceCustomMap || resolution.OwnershipState != OwnershipStateExplicit {
		t.Fatalf("expected explicit custom mapping metadata, got %+v", resolution)
	}
	if resolution.OwnershipConfidence < 0.9 {
		t.Fatalf("expected high confidence custom mapping, got %+v", resolution)
	}
}

func TestResolveParsesServiceCatalogAndBackstageOwners(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	serviceCatalog := []byte("services:\n  - name: payments\n    owner: '@acme/payments'\n    path: .github/workflows/*\n")
	if err := os.WriteFile(filepath.Join(root, "service-catalog.yaml"), serviceCatalog, 0o600); err != nil {
		t.Fatalf("write service catalog: %v", err)
	}
	service := Resolve(root, "acme/payments", "acme", ".github/workflows/release.yml")
	if service.Owner != "@acme/payments" || service.OwnerSource != OwnerSourceService {
		t.Fatalf("expected service catalog owner, got %+v", service)
	}

	backstageRoot := t.TempDir()
	backstage := []byte("apiVersion: backstage.io/v1alpha1\nkind: Component\nmetadata:\n  name: billing\nspec:\n  owner: acme/billing\n")
	if err := os.WriteFile(filepath.Join(backstageRoot, "catalog-info.yaml"), backstage, 0o600); err != nil {
		t.Fatalf("write backstage catalog: %v", err)
	}
	backstageResolution := Resolve(backstageRoot, "acme/billing", "acme", "AGENTS.md")
	if backstageResolution.Owner != "@acme/billing" || backstageResolution.OwnerSource != OwnerSourceBackstage {
		t.Fatalf("expected Backstage owner, got %+v", backstageResolution)
	}
}

func TestResolveSurfacesConflictingOwnersDeterministically(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "CODEOWNERS"), []byte("* @acme/platform\n"), 0o600); err != nil {
		t.Fatalf("write CODEOWNERS: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "service-catalog.yaml"), []byte("services:\n  - owner: '@acme/security'\n"), 0o600); err != nil {
		t.Fatalf("write service catalog: %v", err)
	}

	resolution := Resolve(root, "acme/app", "acme", "AGENTS.md")
	if resolution.OwnerSource != OwnerSourceConflict || resolution.OwnershipState != OwnershipStateConflicting {
		t.Fatalf("expected conflict state, got %+v", resolution)
	}
	want := []string{"@acme/platform", "@acme/security"}
	if len(resolution.ConflictOwners) != len(want) {
		t.Fatalf("expected conflict owners %v, got %+v", want, resolution)
	}
	for idx := range want {
		if resolution.ConflictOwners[idx] != want[idx] {
			t.Fatalf("expected deterministic conflict owners %v, got %+v", want, resolution.ConflictOwners)
		}
	}
	if resolution.OwnershipConfidence >= 0.5 {
		t.Fatalf("expected low confidence for conflict, got %+v", resolution)
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
	if inferred.OwnershipState != OwnershipStateInferred || inferred.OwnershipConfidence == 0 {
		t.Fatalf("expected inferred ownership quality metadata, got %+v", inferred)
	}

	unresolved := Resolve(t.TempDir(), "", "acme", ".cursor/mcp.json")
	if unresolved.OwnerSource != OwnerSourceMissing || unresolved.OwnershipStatus != OwnershipStatusUnresolved || unresolved.OwnershipState != OwnershipStateMissing {
		t.Fatalf("expected missing owner fallback, got %+v", unresolved)
	}
}
