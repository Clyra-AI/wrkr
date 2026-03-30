package contracts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
)

func TestStory24NoisePackAssessmentContracts(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	standardState := filepath.Join(t.TempDir(), "standard-state.json")
	assessmentState := filepath.Join(t.TempDir(), "assessment-state.json")
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "first-offer-noise-pack", "repos")

	standard := runJSONCommand(t, []string{"scan", "--path", scanPath, "--state", standardState, "--profile", "standard", "--json"})
	assessment := runJSONCommand(t, []string{"scan", "--path", scanPath, "--state", assessmentState, "--profile", "assessment", "--json"})

	standardPaths, ok := standard["action_paths"].([]any)
	if !ok {
		t.Fatalf("expected standard action_paths, got %T", standard["action_paths"])
	}
	assessmentPaths, _ := assessment["action_paths"].([]any)
	if len(assessmentPaths) >= len(standardPaths) {
		t.Fatalf("expected assessment action_paths to be strictly narrower, standard=%d assessment=%d", len(standardPaths), len(assessmentPaths))
	}
}

func TestStory24DuplicatePathFixtureContracts(t *testing.T) {
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
		t.Fatalf("expected duplicate path fixture to remain deduped, got paths=%+v choice=%+v", paths, choice)
	}
}

func TestStory24ReportUsefulnessContract(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	statePath := filepath.Join(t.TempDir(), "state.json")
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "first-offer-mixed-governance", "repos")
	_ = runJSONCommand(t, []string{"scan", "--path", scanPath, "--state", statePath, "--profile", "assessment", "--json"})
	reportPayload := runReportJSON(t, statePath, []string{"--template", "operator", "--share-profile", "internal", "--top", "5"})

	summary, ok := reportPayload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected report summary, got %T", reportPayload["summary"])
	}
	topRisks, ok := summary["top_risks"].([]any)
	if !ok || len(topRisks) == 0 {
		t.Fatalf("expected top_risks payload, got %v", summary["top_risks"])
	}
	first, ok := topRisks[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected top risk type: %T", topRisks[0])
	}
	if first["finding_type"] != "action_path" {
		t.Fatalf("expected action_path usefulness contract, got %v", first)
	}

	controlFirst, ok := reportPayload["action_path_to_control_first"].(map[string]any)
	if !ok {
		t.Fatalf("expected action_path_to_control_first, got %v", reportPayload["action_path_to_control_first"])
	}
	if _, present := controlFirst["path"]; !present {
		t.Fatalf("expected control-first path payload, got %v", controlFirst)
	}
}
