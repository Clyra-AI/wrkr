package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/sourceprivacy"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestBuildEvidenceBundlePreservesDeploymentModeInArtifacts(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	now := time.Date(2026, 5, 31, 18, 0, 0, 0, time.UTC)
	findings := []model.Finding{{
		FindingType: "source_discovery",
		Severity:    model.SeverityLow,
		ToolType:    "source_repo",
		Location:    ".",
		Repo:        "repo",
		Org:         "acme",
	}}
	report := risk.Score(findings, 5, now)
	profile := profileeval.Result{ProfileName: "standard", CompliancePercent: 88.2, Status: "pass"}
	posture := score.Result{Score: 81.0, Grade: "B", Weights: scoremodel.DefaultWeights()}
	snapshot := state.Snapshot{
		Version:  state.SnapshotVersion,
		Target:   source.Target{Mode: "path", Value: "repo"},
		Findings: findings,
		Inventory: &agginventory.Inventory{
			InventoryVersion: "v1",
			GeneratedAt:      now.Format(time.RFC3339),
		},
		RiskReport:   &report,
		Profile:      &profile,
		PostureScore: &posture,
		SourcePrivacy: &sourceprivacy.Contract{
			RetentionMode:       sourceprivacy.RetentionEphemeral,
			DeploymentMode:      sourceprivacy.DeploymentModeManagedPlatform,
			CleanupStatus:       sourceprivacy.CleanupNotApplicable,
			SerializedLocations: sourceprivacy.SerializedLocationsFilesystem,
		},
	}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}
	if _, err := proofemit.EmitScan(statePath, now, findings, nil, report, profile, posture, nil); err != nil {
		t.Fatalf("emit scan records: %v", err)
	}

	outputDir := filepath.Join(tmp, "wrkr-evidence")
	result, err := Build(BuildInput{
		StatePath:   statePath,
		Frameworks:  []string{"soc2"},
		OutputDir:   outputDir,
		GeneratedAt: now,
	})
	if err != nil {
		t.Fatalf("build evidence bundle: %v", err)
	}
	if result.DeploymentMode != sourceprivacy.DeploymentModeManagedPlatform {
		t.Fatalf("expected build result deployment mode, got %q", result.DeploymentMode)
	}

	payload, err := os.ReadFile(filepath.Join(outputDir, "scan-metadata.json"))
	if err != nil {
		t.Fatalf("read scan metadata: %v", err)
	}
	var metadata map[string]any
	if err := json.Unmarshal(payload, &metadata); err != nil {
		t.Fatalf("parse scan metadata: %v", err)
	}
	if metadata["deployment_mode"] != sourceprivacy.DeploymentModeManagedPlatform {
		t.Fatalf("expected scan metadata deployment_mode, got %v", metadata["deployment_mode"])
	}

	payload, err = os.ReadFile(filepath.Join(outputDir, "artifact-manifest.json"))
	if err != nil {
		t.Fatalf("read artifact manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatalf("parse artifact manifest: %v", err)
	}
	if manifest["deployment_mode"] != sourceprivacy.DeploymentModeManagedPlatform {
		t.Fatalf("expected artifact manifest deployment_mode, got %v", manifest["deployment_mode"])
	}
}
