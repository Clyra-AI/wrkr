package evidence

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
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
		Inventory:    &agginventory.Inventory{InventoryVersion: "v1", GeneratedAt: "2026-02-20T12:00:00Z"},
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

func TestBuildEvidenceFailsWhenProofChainHasNoScanEvidenceRecords(t *testing.T) {
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
	chainPath := proofemit.ChainPath(statePath)
	chain := proof.NewChain("wrkr-proof")
	if err := proofemit.SaveChain(chainPath, chain); err != nil {
		t.Fatalf("save empty chain: %v", err)
	}

	_, err := Build(BuildInput{
		StatePath:  statePath,
		Frameworks: []string{"soc2"},
		OutputDir:  filepath.Join(tmp, "wrkr-evidence"),
	})
	if err == nil {
		t.Fatal("expected error when proof chain has no scan evidence records")
	}
	if !strings.Contains(err.Error(), "proof chain has no scan evidence records") {
		t.Fatalf("expected no-scan-evidence error, got: %v", err)
	}
}

func TestBuildEvidenceFailsWhenSigningKeyMissing(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	statePath := createEvidenceStateWithProof(t, tmp)
	signingKeyPath := proofemit.SigningKeyPath(statePath)
	if err := os.Remove(signingKeyPath); err != nil {
		t.Fatalf("remove signing key: %v", err)
	}

	_, err := Build(BuildInput{
		StatePath:  statePath,
		Frameworks: []string{"soc2"},
		OutputDir:  filepath.Join(tmp, "wrkr-evidence"),
	})
	if err == nil {
		t.Fatal("expected error when signing key file is missing")
	}
	if !strings.Contains(err.Error(), "signing key file does not exist") {
		t.Fatalf("expected missing signing key error, got: %v", err)
	}
}

func TestBuildEvidenceUsesEnvSigningKeyWhenFileMissing(t *testing.T) {
	tmp := t.TempDir()
	statePath := createEvidenceStateWithProof(t, tmp)
	signingMaterial, err := proofemit.LoadSigningMaterial(statePath)
	if err != nil {
		t.Fatalf("load signing material: %v", err)
	}
	signingKeyPath := proofemit.SigningKeyPath(statePath)
	if err := os.Remove(signingKeyPath); err != nil {
		t.Fatalf("remove signing key: %v", err)
	}
	t.Setenv("WRKR_PROOF_PRIVATE_KEY_B64", base64.StdEncoding.EncodeToString(signingMaterial.Private))
	t.Setenv("WRKR_PROOF_KEY_ID", strings.TrimSpace(signingMaterial.KeyID))

	outputDir := filepath.Join(tmp, "wrkr-evidence")
	result, err := Build(BuildInput{
		StatePath:  statePath,
		Frameworks: []string{"soc2"},
		OutputDir:  outputDir,
	})
	if err != nil {
		t.Fatalf("expected env signing key to be accepted when file is missing, got: %v", err)
	}
	if _, err := os.Stat(result.ManifestPath); err != nil {
		t.Fatalf("expected manifest to be written: %v", err)
	}
	keyIDPayload, err := os.ReadFile(filepath.Join(outputDir, "signatures", "key-id.txt"))
	if err != nil {
		t.Fatalf("read key id output: %v", err)
	}
	if strings.TrimSpace(string(keyIDPayload)) != strings.TrimSpace(signingMaterial.KeyID) {
		t.Fatalf("expected key id %q, got %q", strings.TrimSpace(signingMaterial.KeyID), strings.TrimSpace(string(keyIDPayload)))
	}
}

func TestBuildEvidenceFailsWhenStateSnapshotMissingRequiredSections(t *testing.T) {
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
	if _, err := proofemit.EmitScan(statePath, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC), findings, report, profile, posture, nil); err != nil {
		t.Fatalf("emit scan records: %v", err)
	}

	_, err := Build(BuildInput{
		StatePath:  statePath,
		Frameworks: []string{"soc2"},
		OutputDir:  filepath.Join(tmp, "wrkr-evidence"),
	})
	if err == nil {
		t.Fatal("expected error when state snapshot is missing required sections")
	}
	if !strings.Contains(err.Error(), "missing required sections") {
		t.Fatalf("expected missing snapshot section error, got: %v", err)
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
		Inventory:    &agginventory.Inventory{InventoryVersion: "v1", GeneratedAt: "2026-02-20T12:00:00Z"},
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
		Inventory:    &agginventory.Inventory{InventoryVersion: "v1", GeneratedAt: "2026-02-20T12:00:00Z"},
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

func TestBuildEvidenceRejectsMarkerDirectory(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	statePath := createEvidenceStateWithProof(t, tmp)

	outputDir := filepath.Join(tmp, "wrkr-evidence")
	if err := os.MkdirAll(filepath.Join(outputDir, outputDirMarkerFile), 0o750); err != nil {
		t.Fatalf("mkdir marker directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "stale.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	_, err := Build(BuildInput{StatePath: statePath, Frameworks: []string{"soc2"}, OutputDir: outputDir, GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC)})
	if err == nil {
		t.Fatal("expected error when marker is a directory")
	}
	if !strings.Contains(err.Error(), "marker is not a regular file") {
		t.Fatalf("expected marker regular file error, got: %v", err)
	}
}

func TestBuildEvidenceRejectsMarkerSymlink(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	statePath := createEvidenceStateWithProof(t, tmp)

	outputDir := filepath.Join(tmp, "wrkr-evidence")
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		t.Fatalf("mkdir output dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "marker-target.txt"), []byte(outputDirMarkerContent), 0o600); err != nil {
		t.Fatalf("write marker target: %v", err)
	}
	if err := os.Symlink("marker-target.txt", filepath.Join(outputDir, outputDirMarkerFile)); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "stale.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	_, err := Build(BuildInput{StatePath: statePath, Frameworks: []string{"soc2"}, OutputDir: outputDir, GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC)})
	if err == nil {
		t.Fatal("expected error when marker is a symlink")
	}
	if !strings.Contains(err.Error(), "marker is not a regular file") {
		t.Fatalf("expected marker regular file error, got: %v", err)
	}
}

func TestBuildEvidenceRejectsMarkerWithInvalidContent(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	statePath := createEvidenceStateWithProof(t, tmp)

	outputDir := filepath.Join(tmp, "wrkr-evidence")
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		t.Fatalf("mkdir output dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, outputDirMarkerFile), []byte("invalid marker\n"), 0o600); err != nil {
		t.Fatalf("write invalid marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "stale.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}

	_, err := Build(BuildInput{StatePath: statePath, Frameworks: []string{"soc2"}, OutputDir: outputDir, GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC)})
	if err == nil {
		t.Fatal("expected error when marker content is invalid")
	}
	if !strings.Contains(err.Error(), "marker content is invalid") {
		t.Fatalf("expected marker content error, got: %v", err)
	}
}

func TestBuildEvidenceRejectsSymlinkOutputDir(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	statePath := createEvidenceStateWithProof(t, tmp)

	managedDir := filepath.Join(tmp, "managed-dir")
	if err := os.MkdirAll(managedDir, 0o750); err != nil {
		t.Fatalf("mkdir managed dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(managedDir, outputDirMarkerFile), []byte(outputDirMarkerContent), 0o600); err != nil {
		t.Fatalf("write managed marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(managedDir, "stale.txt"), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale file: %v", err)
	}
	outputDir := filepath.Join(tmp, "wrkr-evidence-symlink")
	if err := os.Symlink(managedDir, outputDir); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}

	_, err := Build(BuildInput{
		StatePath:   statePath,
		Frameworks:  []string{"soc2"},
		OutputDir:   outputDir,
		GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("expected error when output dir is a symlink")
	}
	if !strings.Contains(err.Error(), "output dir must not be a symlink") {
		t.Fatalf("expected symlink output dir error, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(managedDir, "stale.txt")); err != nil {
		t.Fatalf("expected symlink target to remain untouched, got: %v", err)
	}
}

func TestBuildManifestEntriesRejectsSymlinkFile(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	outputDir := filepath.Join(tmp, "wrkr-evidence")
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		t.Fatalf("mkdir output dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "inventory.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	outside := filepath.Join(tmp, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(outputDir, "linked.txt")); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}

	_, err := buildManifestEntries(outputDir)
	if err == nil {
		t.Fatal("expected error when manifest input contains symlink")
	}
	if !strings.Contains(err.Error(), "manifest entry is not a regular file") {
		t.Fatalf("expected non-regular manifest entry error, got: %v", err)
	}
}

func createEvidenceStateWithProof(t *testing.T, tmp string) string {
	t.Helper()

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
		Inventory:    &agginventory.Inventory{InventoryVersion: "v1", GeneratedAt: "2026-02-20T12:00:00Z"},
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
	return statePath
}
