package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestStory3SchemasPresent(t *testing.T) {
	t.Parallel()
	repoRoot := mustFindRepoRoot(t)
	required := []string{
		"schemas/v1/inventory/inventory.schema.json",
		"schemas/v1/export/inventory-export.schema.json",
		"schemas/v1/identity/identity-manifest.schema.json",
		"schemas/v1/risk/risk-report.schema.json",
		"schemas/v1/profile/profile-result.schema.json",
		"schemas/v1/score/score.schema.json",
	}
	for _, rel := range required {
		if _, err := os.Stat(filepath.Join(repoRoot, rel)); err != nil {
			t.Fatalf("expected schema %s: %v", rel, err)
		}
	}
}

func TestScanProfileAndScoreContracts(t *testing.T) {
	t.Parallel()
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"scan", "--path", scanPath, "--state", statePath, "--profile", "standard", "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	profilePayload, ok := payload["profile"].(map[string]any)
	if !ok {
		t.Fatalf("expected profile payload, got %T", payload["profile"])
	}
	if _, present := profilePayload["compliance_percent"]; !present {
		t.Fatalf("missing profile.compliance_percent in %v", profilePayload)
	}
	scorePayload, ok := payload["posture_score"].(map[string]any)
	if !ok {
		t.Fatalf("expected posture_score payload, got %T", payload["posture_score"])
	}
	for _, key := range []string{"score", "grade", "breakdown", "weighted_breakdown", "weights", "trend_delta"} {
		if _, present := scorePayload[key]; !present {
			t.Fatalf("missing posture_score.%s in %v", key, scorePayload)
		}
	}
}

func TestExportInventoryContract(t *testing.T) {
	t.Parallel()
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"export", "--format", "inventory", "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("export failed: %d (%s)", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse export payload: %v", err)
	}
	for _, key := range []string{"export_version", "exported_at", "org", "tools"} {
		if _, present := payload[key]; !present {
			t.Fatalf("missing export key %q in %v", key, payload)
		}
	}
}
