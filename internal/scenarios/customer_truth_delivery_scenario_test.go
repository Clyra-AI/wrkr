//go:build scenario

package scenarios

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScenarioCustomerTruthAssessmentDelivery(t *testing.T) {
	repoRoot := mustFindRepoRoot(t)
	tmp := t.TempDir()
	outputDir := filepath.Join(tmp, "assessment")
	scanRoot := filepath.Join(repoRoot, "scenarios", "wrkr", "first-offer-mixed-governance", "repos")

	payload := runScenarioCommandJSONRaw(t, []string{
		"assess", "--path", scanRoot, "--output-dir", outputDir, "--json",
	})
	artifacts := requireScenarioObject(t, payload, "artifacts")
	lead := mustReadScenarioRelativeArtifact(t, outputDir, artifacts, "report_markdown_path")
	appendix := mustReadScenarioRelativeArtifact(t, outputDir, artifacts, "report_appendix_path")
	if strings.Contains(lead, "## Report Context Appendix") || !strings.Contains(lead, "companion appendix artifact") {
		t.Fatalf("expected buyer lead to exclude diagnostic appendix, got %q", lead)
	}
	if !strings.Contains(appendix, "# Wrkr Diagnostic Appendix") {
		t.Fatalf("expected complete diagnostic appendix, got %q", appendix)
	}
	if len(lead) > 16*1024 || strings.Count(lead, "\n")+1 > 80 {
		t.Fatalf("buyer lead exceeded readability budget: bytes=%d lines=%d", len(lead), strings.Count(lead, "\n")+1)
	}
	if len(appendix) > 64*1024 {
		t.Fatalf("diagnostic appendix exceeded size budget: bytes=%d", len(appendix))
	}

	shareDirValue, _ := artifacts["customer_share_dir"].(string)
	shareManifestValue, _ := artifacts["customer_share_manifest"].(string)
	if shareDirValue == "" || shareManifestValue == "" {
		t.Fatalf("expected customer share paths, got %+v", artifacts)
	}
	shareDir := filepath.Join(outputDir, filepath.FromSlash(shareDirValue))
	for _, name := range []string{"wrkr-report.md", "wrkr-report-appendix.md", "wrkr-report-evidence.json", "wrkr-control-backlog.csv", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(shareDir, name)); err != nil {
			t.Fatalf("expected customer-share artifact %s: %v", name, err)
		}
	}
	for _, forbidden := range []string{"scan-state.json", "last-scan.json", "private-join-map.json", "signing-key.json"} {
		if _, err := os.Stat(filepath.Join(shareDir, forbidden)); !os.IsNotExist(err) {
			t.Fatalf("customer-share unexpectedly contains %s", forbidden)
		}
	}
	sharedEvidence, err := os.ReadFile(filepath.Join(shareDir, "wrkr-report-evidence.json"))
	if err != nil {
		t.Fatalf("read customer-share evidence: %v", err)
	}
	if len(sharedEvidence) > 2*1024*1024 {
		t.Fatalf("customer-share evidence exceeded size budget: bytes=%d", len(sharedEvidence))
	}
	for _, sensitive := range []string{"control-plane", "first-offer-mixed-governance", repoRoot} {
		if strings.Contains(lead+appendix+string(sharedEvidence), sensitive) {
			t.Fatalf("customer-share artifacts exposed private source identity %q", sensitive)
		}
	}
	manifestBytes, err := os.ReadFile(filepath.Join(outputDir, filepath.FromSlash(shareManifestValue)))
	if err != nil {
		t.Fatalf("read customer-share manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("parse customer-share manifest: %v", err)
	}
	if manifest["share_profile"] != "customer-redacted" {
		t.Fatalf("expected customer-redacted share profile, got %+v", manifest)
	}
}

func mustReadScenarioRelativeArtifact(t *testing.T, root string, artifacts map[string]any, key string) string {
	t.Helper()
	value, _ := artifacts[key].(string)
	if strings.TrimSpace(value) == "" {
		t.Fatalf("expected artifact %s in %+v", key, artifacts)
	}
	payload, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(value)))
	if err != nil {
		t.Fatalf("read artifact %s: %v", key, err)
	}
	return string(payload)
}
