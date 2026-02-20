package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestBuildEvidenceBundle(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	findings := []model.Finding{
		{
			FindingType: "skill_policy_conflict",
			Severity:    model.SeverityHigh,
			ToolType:    "skill",
			Location:    ".claude/skills/deploy/SKILL.md",
			Repo:        "repo",
			Org:         "acme",
		},
	}
	report := risk.Score(findings, 5, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC))
	profile := profileeval.Result{ProfileName: "standard", CompliancePercent: 88.2, Status: "pass"}
	posture := score.Result{Score: 81.0, Grade: "B", Weights: scoremodel.DefaultWeights()}
	snapshot := state.Snapshot{
		Version:      state.SnapshotVersion,
		Target:       source.Target{Mode: "repo", Value: "acme/repo"},
		Findings:     findings,
		RiskReport:   &report,
		Profile:      &profile,
		PostureScore: &posture,
	}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if _, err := proofemit.EmitScan(statePath, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC), findings, report, profile, posture, nil); err != nil {
		t.Fatalf("emit scan records: %v", err)
	}

	outputDir := filepath.Join(tmp, "wrkr-evidence")
	result, err := Build(BuildInput{StatePath: statePath, Frameworks: []string{"soc2"}, OutputDir: outputDir, GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("build evidence bundle: %v", err)
	}
	if result.OutputDir != outputDir {
		t.Fatalf("unexpected output dir %q", result.OutputDir)
	}
	required := []string{
		"inventory.json",
		"risk-report.json",
		"profile-compliance.json",
		"posture-score.json",
		"proof-records/chain.json",
		"mappings/soc2.json",
		"gaps/soc2.json",
		"manifest.json",
	}
	for _, relative := range required {
		path := filepath.Join(outputDir, relative)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected bundle file %s: %v", relative, err)
		}
	}
}

func TestBuildEvidenceFailsWithoutFrameworks(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	snapshot := state.Snapshot{Version: state.SnapshotVersion, Target: source.Target{Mode: "repo", Value: "acme/repo"}}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if _, err := Build(BuildInput{StatePath: statePath, Frameworks: nil, OutputDir: filepath.Join(tmp, "bundle")}); err == nil {
		t.Fatal("expected error when frameworks are missing")
	}
}

func TestBuildEvidenceFailsWhenProofChainMissing(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	snapshot := state.Snapshot{
		Version: state.SnapshotVersion,
		Target:  source.Target{Mode: "repo", Value: "acme/repo"},
	}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}
	_, err := Build(BuildInput{
		StatePath:  statePath,
		Frameworks: []string{"soc2"},
		OutputDir:  filepath.Join(tmp, "wrkr-evidence"),
	})
	if err == nil {
		t.Fatal("expected error when proof chain file is missing")
	}
	if !strings.Contains(err.Error(), "proof chain file does not exist") {
		t.Fatalf("expected missing proof chain error, got: %v", err)
	}
}

func TestBuildEvidenceRejectsNonManagedNonEmptyOutputDir(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	findings := []model.Finding{
		{
			FindingType: "skill_policy_conflict",
			Severity:    model.SeverityHigh,
			ToolType:    "skill",
			Location:    ".claude/skills/deploy/SKILL.md",
			Repo:        "repo",
			Org:         "acme",
		},
	}
	report := risk.Score(findings, 5, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC))
	profile := profileeval.Result{ProfileName: "standard", CompliancePercent: 88.2, Status: "pass"}
	posture := score.Result{Score: 81.0, Grade: "B", Weights: scoremodel.DefaultWeights()}
	snapshot := state.Snapshot{
		Version:      state.SnapshotVersion,
		Target:       source.Target{Mode: "repo", Value: "acme/repo"},
		Findings:     findings,
		RiskReport:   &report,
		Profile:      &profile,
		PostureScore: &posture,
	}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if _, err := proofemit.EmitScan(statePath, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC), findings, report, profile, posture, nil); err != nil {
		t.Fatalf("emit scan records: %v", err)
	}

	outputDir := filepath.Join(tmp, "wrkr-evidence")
	if err := os.MkdirAll(filepath.Join(outputDir, "old"), 0o750); err != nil {
		t.Fatalf("mkdir stale dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "stale.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale root file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "old", "legacy.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write stale nested file: %v", err)
	}

	_, err := Build(BuildInput{StatePath: statePath, Frameworks: []string{"soc2"}, OutputDir: outputDir, GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC)})
	if err == nil {
		t.Fatal("expected build to fail when output dir is non-empty and not wrkr-managed")
	}
	if !strings.Contains(err.Error(), "not managed by wrkr evidence") {
		t.Fatalf("expected non-managed output dir error, got: %v", err)
	}
}

func TestBuildEvidenceClearsManagedOutputDirBeforeManifestHashing(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	findings := []model.Finding{
		{
			FindingType: "skill_policy_conflict",
			Severity:    model.SeverityHigh,
			ToolType:    "skill",
			Location:    ".claude/skills/deploy/SKILL.md",
			Repo:        "repo",
			Org:         "acme",
		},
	}
	report := risk.Score(findings, 5, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC))
	profile := profileeval.Result{ProfileName: "standard", CompliancePercent: 88.2, Status: "pass"}
	posture := score.Result{Score: 81.0, Grade: "B", Weights: scoremodel.DefaultWeights()}
	snapshot := state.Snapshot{
		Version:      state.SnapshotVersion,
		Target:       source.Target{Mode: "repo", Value: "acme/repo"},
		Findings:     findings,
		RiskReport:   &report,
		Profile:      &profile,
		PostureScore: &posture,
	}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if _, err := proofemit.EmitScan(statePath, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC), findings, report, profile, posture, nil); err != nil {
		t.Fatalf("emit scan records: %v", err)
	}

	outputDir := filepath.Join(tmp, "wrkr-evidence")
	if _, err := Build(BuildInput{StatePath: statePath, Frameworks: []string{"soc2"}, OutputDir: outputDir, GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatalf("initial build evidence bundle: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(outputDir, "old"), 0o750); err != nil {
		t.Fatalf("mkdir stale dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "stale.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale root file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "old", "legacy.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write stale nested file: %v", err)
	}

	if _, err := Build(BuildInput{StatePath: statePath, Frameworks: []string{"soc2"}, OutputDir: outputDir, GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatalf("second build evidence bundle: %v", err)
	}

	if _, err := os.Stat(filepath.Join(outputDir, "stale.txt")); !os.IsNotExist(err) {
		t.Fatalf("expected stale.txt to be removed, got err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "old", "legacy.json")); !os.IsNotExist(err) {
		t.Fatalf("expected old/legacy.json to be removed, got err=%v", err)
	}

	payload, err := os.ReadFile(filepath.Join(outputDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest proof.BundleManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	for _, entry := range manifest.Files {
		if entry.Path == "stale.txt" || strings.HasPrefix(entry.Path, "old/") || entry.Path == outputDirMarkerFile {
			t.Fatalf("manifest should not include stale file path %q", entry.Path)
		}
	}
}
