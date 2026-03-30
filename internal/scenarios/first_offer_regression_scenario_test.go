//go:build scenario

package scenarios

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
)

func TestScenarioFirstOfferNoisePackAssessmentSharpening(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "first-offer-noise-pack", "repos")
	standard := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "standard-state.json"), "--profile", "standard", "--json"})
	assessment := runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", filepath.Join(t.TempDir(), "assessment-state.json"), "--profile", "assessment", "--json"})

	standardFindings, ok := standard["findings"].([]any)
	if !ok {
		t.Fatalf("expected standard findings, got %T", standard["findings"])
	}
	assessmentFindings, ok := assessment["findings"].([]any)
	if !ok {
		t.Fatalf("expected assessment findings, got %T", assessment["findings"])
	}
	if len(standardFindings) != len(assessmentFindings) {
		t.Fatalf("expected raw findings to stay unchanged between profiles, standard=%d assessment=%d", len(standardFindings), len(assessmentFindings))
	}

	standardPaths, ok := standard["action_paths"].([]any)
	if !ok {
		t.Fatalf("expected standard action_paths, got %T", standard["action_paths"])
	}
	assessmentPaths, _ := assessment["action_paths"].([]any)
	if len(assessmentPaths) >= len(standardPaths) {
		t.Fatalf("expected assessment profile to sharpen noisy action paths, standard=%d assessment=%d", len(standardPaths), len(assessmentPaths))
	}
}

func TestScenarioFirstOfferMixedGovernanceReportUsefulness(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "first-offer-mixed-governance", "repos")
	_ = runScenarioCommandJSON(t, []string{"scan", "--path", scanPath, "--state", statePath, "--profile", "assessment", "--json"})
	reportPayload := runScenarioCommandJSON(t, []string{"report", "--state", statePath, "--json"})

	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected report summary, got %T", reportPayload["summary"])
	}
	topRisks, ok := summary["top_risks"].([]any)
	if !ok || len(topRisks) == 0 {
		t.Fatalf("expected top_risks, got %v", summary["top_risks"])
	}
	first, ok := topRisks[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected top risk type: %T", topRisks[0])
	}
	if first["finding_type"] != "action_path" {
		t.Fatalf("expected action_path-first report output, got %v", first)
	}
	exposureGroups, ok := reportPayload["exposure_groups"].([]any)
	if !ok || len(exposureGroups) == 0 {
		t.Fatalf("expected exposure_groups payload, got %v", reportPayload["exposure_groups"])
	}
}

func TestScenarioFirstOfferDuplicatePathFixture(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	fixturePath := filepath.Join(repoRoot, "scenarios", "wrkr", "first-offer-duplicate-paths", "action_path_fixture.json")
	payload, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read duplicate path fixture: %v", err)
	}

	var fixture struct {
		AttackPaths []riskattack.ScoredPath `json:"attack_paths"`
		Inventory   agginventory.Inventory  `json:"inventory"`
	}
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatalf("parse duplicate path fixture: %v", err)
	}

	paths, choice := risk.BuildActionPaths(fixture.AttackPaths, &fixture.Inventory)
	if len(paths) != 1 || choice == nil {
		t.Fatalf("expected deduped duplicate-path fixture, got paths=%+v choice=%+v", paths, choice)
	}
}
