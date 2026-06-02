package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWave42EnterprisePressureContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustRepoRootForWaveAssets(t)
	for _, rel := range []string{
		"internal/enterprisepressure/fixture.go",
		"scenarios/wrkr/enterprise-pressure/README.md",
		"scenarios/wrkr/enterprise-pressure/expected/contract.json",
		"docs/decisions/wave29-enterprise-pressure-gates.md",
	} {
		if _, err := os.Stat(filepath.Join(repoRoot, rel)); err != nil {
			t.Fatalf("missing enterprise-pressure contract file %s: %v", rel, err)
		}
	}

	payload := mustReadFile(t, filepath.Join(repoRoot, "scenarios", "wrkr", "enterprise-pressure", "expected", "contract.json"))
	var contract struct {
		RepoCount               int      `json:"repo_count"`
		RequiredDriftCategories []string `json:"required_drift_categories"`
		RequiredShareProfiles   []string `json:"required_share_profiles"`
	}
	if err := json.Unmarshal([]byte(payload), &contract); err != nil {
		t.Fatalf("parse enterprise-pressure contract: %v", err)
	}
	if contract.RepoCount < 300 {
		t.Fatalf("enterprise-pressure contract must cover 300+ repos, got %d", contract.RepoCount)
	}
	if len(contract.RequiredDriftCategories) < 2 {
		t.Fatalf("expected at least two required drift categories, got %v", contract.RequiredDriftCategories)
	}
	if len(contract.RequiredShareProfiles) != 5 {
		t.Fatalf("expected five redaction/public share profiles, got %v", contract.RequiredShareProfiles)
	}

	waveGates := mustReadFile(t, filepath.Join(repoRoot, "docs", "trust", "wave-gates.md"))
	if !strings.Contains(waveGates, "enterprise-pressure-scorecard") {
		t.Fatalf("wave-gates doc missing enterprise pressure scorecard guidance")
	}
	coverage := mustReadFile(t, filepath.Join(repoRoot, "docs", "trust", "detection-coverage-matrix.md"))
	if !strings.Contains(coverage, "enterprise-pressure") {
		t.Fatalf("detection coverage matrix missing enterprise-pressure coverage note")
	}
}
