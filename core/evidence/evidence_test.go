package evidence

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
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
	verifycore "github.com/Clyra-AI/wrkr/core/verify"
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
	if _, err := proofemit.EmitScan(statePath, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC), findings, nil, report, profile, posture, nil); err != nil {
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
		"inventory.yaml",
		"compliance-summary.json",
		"risk-report.json",
		"profile-compliance.json",
		"posture-score.json",
		"reports/audit-summary.md",
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
	if len(result.ReportArtifacts) == 0 {
		t.Fatal("expected report artifacts to be recorded in build result")
	}
}

func TestBuildEvidenceBundleIncludesPersonalInventoryAndMCPCatalogWhenPresent(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	findings := []model.Finding{
		{
			FindingType: "policy_violation",
			RuleID:      "WRKR-A001",
			Severity:    model.SeverityHigh,
			ToolType:    "codex",
			Location:    ".codex/config.toml",
			Org:         "local",
		},
		{
			FindingType: "mcp_server",
			Severity:    model.SeverityHigh,
			ToolType:    "mcp",
			Location:    ".mcp.json",
			Org:         "local",
			Evidence: []model.Evidence{
				{Key: "server", Value: "filesystem"},
				{Key: "transport", Value: "stdio"},
			},
			Permissions: []string{"filesystem.read"},
		},
	}
	report := risk.Score(findings, 5, time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC))
	profile := profileeval.Result{ProfileName: "standard", CompliancePercent: 88.2, Status: "pass"}
	posture := score.Result{Score: 81.0, Grade: "B", Weights: scoremodel.DefaultWeights()}
	snapshot := state.Snapshot{
		Version:  state.SnapshotVersion,
		Target:   source.Target{Mode: "my_setup", Value: ""},
		Findings: findings,
		Inventory: &agginventory.Inventory{
			InventoryVersion: "v1",
			GeneratedAt:      "2026-03-09T12:00:00Z",
			Tools: []agginventory.Tool{
				{
					ToolID:          "wrkr:mcp:.mcp.json",
					AgentID:         "wrkr:mcp:local",
					DiscoveryMethod: "static",
					ToolType:        "mcp",
					ToolCategory:    "mcp_integration",
					Org:             "local",
					Locations: []agginventory.ToolLocation{
						{Location: ".mcp.json"},
					},
					Permissions: []string{"filesystem.read"},
				},
			},
		},
		RiskReport:   &report,
		Profile:      &profile,
		PostureScore: &posture,
	}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if _, err := proofemit.EmitScan(statePath, time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC), findings, nil, report, profile, posture, nil); err != nil {
		t.Fatalf("emit scan records: %v", err)
	}

	outputDir := filepath.Join(tmp, "wrkr-evidence")
	if _, err := Build(BuildInput{StatePath: statePath, Frameworks: []string{"soc2"}, OutputDir: outputDir, GeneratedAt: time.Date(2026, 3, 9, 13, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatalf("build evidence bundle: %v", err)
	}

	for _, relative := range []string{"personal-inventory-snapshot.json", "mcp-catalog.json", "compliance-summary.json"} {
		if _, err := os.Stat(filepath.Join(outputDir, relative)); err != nil {
			t.Fatalf("expected %s in bundle: %v", relative, err)
		}
	}
}

func TestVerifyChainPersonalSetupBundleRemainsCompatible(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	findings := []model.Finding{
		{
			FindingType: "policy_violation",
			RuleID:      "WRKR-A001",
			Severity:    model.SeverityHigh,
			ToolType:    "codex",
			Location:    ".codex/config.toml",
			Org:         "local",
		},
	}
	report := risk.Score(findings, 5, time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC))
	profile := profileeval.Result{ProfileName: "standard", CompliancePercent: 88.2, Status: "pass"}
	posture := score.Result{Score: 81.0, Grade: "B", Weights: scoremodel.DefaultWeights()}
	snapshot := state.Snapshot{
		Version:      state.SnapshotVersion,
		Target:       source.Target{Mode: "my_setup"},
		Findings:     findings,
		Inventory:    &agginventory.Inventory{InventoryVersion: "v1", GeneratedAt: "2026-03-09T12:00:00Z"},
		RiskReport:   &report,
		Profile:      &profile,
		PostureScore: &posture,
	}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if _, err := proofemit.EmitScan(statePath, time.Date(2026, 3, 9, 12, 0, 0, 0, time.UTC), findings, nil, report, profile, posture, nil); err != nil {
		t.Fatalf("emit scan records: %v", err)
	}
	if _, err := Build(BuildInput{StatePath: statePath, Frameworks: []string{"soc2"}, OutputDir: filepath.Join(tmp, "wrkr-evidence"), GeneratedAt: time.Date(2026, 3, 9, 13, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatalf("build evidence bundle: %v", err)
	}

	verified, err := verifycore.Chain(proofemit.ChainPath(statePath))
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if !verified.Intact {
		t.Fatalf("expected intact chain, got %+v", verified)
	}
}

func TestEvidenceBundle_VerifiesWithAgentContextFields(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	findings := []model.Finding{
		{
			FindingType: "agent_framework",
			Severity:    model.SeverityHigh,
			ToolType:    "langchain",
			Location:    "agents/release.py",
			Repo:        "repo",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "release_agent"},
				{Key: "bound_tools", Value: "deploy.write"},
				{Key: "deployment_artifacts", Value: ".github/workflows/release.yml"},
				{Key: "deployment_status", Value: "deployed"},
				{Key: "approval_status", Value: "missing"},
				{Key: "kill_switch", Value: "false"},
			},
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
	if _, err := proofemit.EmitScan(statePath, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC), findings, nil, report, profile, posture, nil); err != nil {
		t.Fatalf("emit scan records: %v", err)
	}

	outputDir := filepath.Join(tmp, "wrkr-evidence")
	if _, err := Build(BuildInput{StatePath: statePath, Frameworks: []string{"soc2"}, OutputDir: outputDir, GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatalf("build evidence bundle: %v", err)
	}

	payload, err := os.ReadFile(filepath.Join(outputDir, "proof-records", "scan-findings.jsonl"))
	if err != nil {
		t.Fatalf("read scan findings jsonl: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(payload)), "\n")
	if len(lines) == 0 {
		t.Fatal("expected scan findings records in evidence bundle")
	}
	record := map[string]any{}
	if err := json.Unmarshal([]byte(lines[0]), &record); err != nil {
		t.Fatalf("parse scan finding jsonl: %v", err)
	}
	event, ok := record["event"].(map[string]any)
	if !ok {
		t.Fatalf("expected event map in proof record, got %T", record["event"])
	}
	if event["agent_id"] == "" {
		t.Fatalf("expected additive agent_id in proof record event, got %v", event)
	}
	if _, ok := event["agent_context"].(map[string]any); !ok {
		t.Fatalf("expected additive agent_context map in proof record event, got %T", event["agent_context"])
	}
}

func TestEvidenceFrameworkCoverage_DeterministicForAgentFindings(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := createEvidenceStateWithProof(t, tmp)
	firstDir := filepath.Join(tmp, "evidence-first")
	secondDir := filepath.Join(tmp, "evidence-second")
	input := BuildInput{
		StatePath:   statePath,
		Frameworks:  []string{"eu_ai_act", "soc2", "pci_dss"},
		GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC),
	}

	first, err := Build(BuildInput{
		StatePath:   input.StatePath,
		Frameworks:  input.Frameworks,
		OutputDir:   firstDir,
		GeneratedAt: input.GeneratedAt,
	})
	if err != nil {
		t.Fatalf("first evidence build: %v", err)
	}
	second, err := Build(BuildInput{
		StatePath:   input.StatePath,
		Frameworks:  input.Frameworks,
		OutputDir:   secondDir,
		GeneratedAt: input.GeneratedAt,
	})
	if err != nil {
		t.Fatalf("second evidence build: %v", err)
	}

	if !reflect.DeepEqual(first.FrameworkCoverage, second.FrameworkCoverage) {
		t.Fatalf("expected deterministic framework coverage\nfirst=%v\nsecond=%v", first.FrameworkCoverage, second.FrameworkCoverage)
	}
	expectedFrameworks := []string{"eu-ai-act", "pci-dss", "soc2"}
	if !reflect.DeepEqual(first.Frameworks, expectedFrameworks) {
		t.Fatalf("expected normalized framework IDs %v, got %v", expectedFrameworks, first.Frameworks)
	}
}

func TestBuildEvidenceInventoryYAMLByteStableAcrossRuns(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	statePath := createEvidenceStateWithProof(t, tmp)
	outputDir := filepath.Join(tmp, "wrkr-evidence")
	buildInput := BuildInput{
		StatePath:   statePath,
		Frameworks:  []string{"soc2"},
		OutputDir:   outputDir,
		GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC),
	}

	if _, err := Build(buildInput); err != nil {
		t.Fatalf("initial build evidence bundle: %v", err)
	}
	firstPayload, err := os.ReadFile(filepath.Join(outputDir, "inventory.yaml"))
	if err != nil {
		t.Fatalf("read first inventory.yaml: %v", err)
	}

	if _, err := Build(buildInput); err != nil {
		t.Fatalf("second build evidence bundle: %v", err)
	}
	secondPayload, err := os.ReadFile(filepath.Join(outputDir, "inventory.yaml"))
	if err != nil {
		t.Fatalf("read second inventory.yaml: %v", err)
	}

	if string(firstPayload) != string(secondPayload) {
		t.Fatalf("expected inventory.yaml to be byte-stable across runs")
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

func TestBuildEvidenceFailsWhenSigningKeyInvalid(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	statePath := createEvidenceStateWithProof(t, tmp)
	signingKeyPath := proofemit.SigningKeyPath(statePath)
	if err := os.WriteFile(signingKeyPath, []byte("{\"not\":\"a valid key file\"}\n"), 0o600); err != nil {
		t.Fatalf("write invalid signing key: %v", err)
	}

	_, err := Build(BuildInput{
		StatePath:  statePath,
		Frameworks: []string{"soc2"},
		OutputDir:  filepath.Join(tmp, "wrkr-evidence"),
	})
	if err == nil {
		t.Fatal("expected error when signing key file is invalid")
	}
	if !strings.Contains(err.Error(), "load signing material") {
		t.Fatalf("expected signing-material load error, got: %v", err)
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
	if _, err := proofemit.EmitScan(statePath, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC), findings, nil, report, profile, posture, nil); err != nil {
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
	if _, err := proofemit.EmitScan(statePath, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC), findings, nil, report, profile, posture, nil); err != nil {
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
	if _, err := proofemit.EmitScan(statePath, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC), findings, nil, report, profile, posture, nil); err != nil {
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

func TestBuildDoesNotLeavePartialBundleOnInvalidFramework(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := createEvidenceStateWithProof(t, tmp)
	outputDir := filepath.Join(tmp, "wrkr-evidence")

	_, err := Build(BuildInput{
		StatePath:   statePath,
		Frameworks:  []string{"not-a-framework"},
		OutputDir:   outputDir,
		GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("expected build to fail for unknown framework")
	}
	if _, statErr := os.Stat(outputDir); !os.IsNotExist(statErr) {
		t.Fatalf("expected output dir to remain absent, got %v", statErr)
	}
	if matches, globErr := filepath.Glob(stageDirGlob(outputDir)); globErr != nil {
		t.Fatalf("glob stage dirs: %v", globErr)
	} else if len(matches) != 0 {
		t.Fatalf("expected no leftover stage dirs, got %v", matches)
	}
	if matches, globErr := filepath.Glob(backupDirPrefix(outputDir) + "*"); globErr != nil {
		t.Fatalf("glob backup dirs: %v", globErr)
	} else if len(matches) != 0 {
		t.Fatalf("expected no leftover backup dirs, got %v", matches)
	}
}

func TestBuildPreservesPreviousManagedBundleWhenLateFailureOccurs(t *testing.T) {
	tmp := t.TempDir()
	statePath := createEvidenceStateWithProof(t, tmp)
	outputDir := filepath.Join(tmp, "wrkr-evidence")

	if _, err := Build(BuildInput{
		StatePath:   statePath,
		Frameworks:  []string{"soc2"},
		OutputDir:   outputDir,
		GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("initial build evidence bundle: %v", err)
	}
	before := snapshotBundleTree(t, outputDir)

	restore := setBeforePublishHookForTest(func(_, _, _ string) error {
		return errors.New("synthetic publish failure")
	})
	t.Cleanup(restore)

	_, err := Build(BuildInput{
		StatePath:   statePath,
		Frameworks:  []string{"soc2"},
		OutputDir:   outputDir,
		GeneratedAt: time.Date(2026, 2, 20, 15, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("expected build to fail when publish hook aborts the swap")
	}
	if !strings.Contains(err.Error(), "before publish swap") {
		t.Fatalf("expected publish swap failure, got: %v", err)
	}

	after := snapshotBundleTree(t, outputDir)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("expected previous managed bundle to remain intact\nbefore=%v\nafter=%v", before, after)
	}
	if matches, globErr := filepath.Glob(stageDirGlob(outputDir)); globErr != nil {
		t.Fatalf("glob stage dirs: %v", globErr)
	} else if len(matches) != 0 {
		t.Fatalf("expected no leftover stage dirs, got %v", matches)
	}
	if matches, globErr := filepath.Glob(backupDirPrefix(outputDir) + "*"); globErr != nil {
		t.Fatalf("glob backup dirs: %v", globErr)
	} else if len(matches) != 0 {
		t.Fatalf("expected no leftover backup dirs, got %v", matches)
	}
}

func TestBuildFailsClosedWhenBackupCleanupFails(t *testing.T) {
	tmp := t.TempDir()
	statePath := createEvidenceStateWithProof(t, tmp)
	outputDir := filepath.Join(tmp, "wrkr-evidence")

	if _, err := Build(BuildInput{
		StatePath:   statePath,
		Frameworks:  []string{"soc2"},
		OutputDir:   outputDir,
		GeneratedAt: time.Date(2026, 2, 20, 14, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatalf("initial build evidence bundle: %v", err)
	}

	restore := setRemoveAllHookForTest(func(path string) error {
		if strings.HasPrefix(filepath.Base(path), "."+filepath.Base(outputDir)+".backup-") {
			return errors.New("synthetic backup cleanup failure")
		}
		return os.RemoveAll(path)
	})
	t.Cleanup(restore)

	_, err := Build(BuildInput{
		StatePath:   statePath,
		Frameworks:  []string{"soc2"},
		OutputDir:   outputDir,
		GeneratedAt: time.Date(2026, 2, 20, 15, 0, 0, 0, time.UTC),
	})
	if err == nil {
		t.Fatal("expected build to fail when backup cleanup fails")
	}
	if !strings.Contains(err.Error(), "remove backup output dir") {
		t.Fatalf("expected backup cleanup failure, got: %v", err)
	}
	if _, verifyErr := proof.VerifyBundle(outputDir, proof.BundleVerifyOpts{}); verifyErr != nil {
		t.Fatalf("expected published bundle to remain valid when backup cleanup fails: %v", verifyErr)
	}
	if matches, globErr := filepath.Glob(backupDirPrefix(outputDir) + "*"); globErr != nil {
		t.Fatalf("glob backup dirs: %v", globErr)
	} else if len(matches) == 0 {
		t.Fatal("expected backup dir to remain when cleanup fails")
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
	if _, err := proofemit.EmitScan(statePath, time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC), findings, nil, report, profile, posture, nil); err != nil {
		t.Fatalf("emit scan records: %v", err)
	}
	return statePath
}

func snapshotBundleTree(t *testing.T, root string) map[string]string {
	t.Helper()

	snapshot := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		snapshot[filepath.ToSlash(rel)] = string(payload)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot bundle tree: %v", err)
	}
	return snapshot
}
