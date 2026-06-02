package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWave31SiteAssetsContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustRepoRootForWaveAssets(t)
	assetDir := filepath.Join(repoRoot, "docs", "examples", "site-assets")
	required := []string{
		"architecture-boundary.json",
		"interactive-lab-data.json",
		"local-private-posture.md",
		"sample-agent-action-bom.json",
		"sample-control-path-graph.json",
		"sample-redacted-report.md",
		"site-asset-manifest.json",
	}
	for _, name := range required {
		if _, err := os.Stat(filepath.Join(assetDir, name)); err != nil {
			t.Fatalf("missing site asset %s: %v", name, err)
		}
	}

	manifestPayload, err := os.ReadFile(filepath.Join(assetDir, "site-asset-manifest.json"))
	if err != nil {
		t.Fatalf("read site asset manifest: %v", err)
	}
	var manifest struct {
		ScenarioPath string `json:"scenario_path"`
		Files        []struct {
			Path string `json:"path"`
		} `json:"files"`
	}
	if err := json.Unmarshal(manifestPayload, &manifest); err != nil {
		t.Fatalf("parse site asset manifest: %v", err)
	}
	if manifest.ScenarioPath != "scenarios/wrkr/scan-mixed-org/repos" {
		t.Fatalf("unexpected site asset scenario path: %s", manifest.ScenarioPath)
	}
	if len(manifest.Files) != 6 {
		t.Fatalf("expected six published files in manifest, got %d", len(manifest.Files))
	}

	siteAssetsDoc := mustReadFile(t, filepath.Join(repoRoot, "docs", "examples", "site-assets.md"))
	for _, needle := range []string{
		"go run ./scripts/generate_site_assets",
		"docs/examples/site-assets/sample-agent-action-bom.json",
		"docs/examples/site-assets/site-asset-manifest.json",
	} {
		if !strings.Contains(siteAssetsDoc, needle) {
			t.Fatalf("site-assets doc missing %q", needle)
		}
	}

	navigation := mustReadFile(t, filepath.Join(repoRoot, "docs-site", "src", "lib", "navigation.ts"))
	if !strings.Contains(navigation, "/docs/examples/site-assets") {
		t.Fatalf("navigation missing site-assets route")
	}
	docsHome := mustReadFile(t, filepath.Join(repoRoot, "docs-site", "src", "app", "docs", "page.tsx"))
	if !strings.Contains(docsHome, "/docs/examples/site-assets") {
		t.Fatalf("docs home missing site-assets route")
	}
	llms := mustReadFile(t, filepath.Join(repoRoot, "docs-site", "public", "llms.txt"))
	if !strings.Contains(llms, "/docs/examples/site-assets/") {
		t.Fatalf("llms.txt missing site-assets route")
	}
	productLLM := mustReadFile(t, filepath.Join(repoRoot, "docs-site", "public", "llm", "product.md"))
	if !strings.Contains(productLLM, "Website Demo Assets") {
		t.Fatalf("product llm summary missing website demo assets reference")
	}
}

func mustRepoRootForWaveAssets(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(wd, "go.mod")); statErr == nil {
			return wd
		}
		next := filepath.Dir(wd)
		if next == wd {
			t.Fatal("could not locate repo root")
		}
		wd = next
	}
}
