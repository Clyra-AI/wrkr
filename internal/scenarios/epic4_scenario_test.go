//go:build scenario

package scenarios

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestScenarioEvidenceBundleIncludesProfileAndPosture(t *testing.T) {
	t.Parallel()
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")
	outputDir := filepath.Join(t.TempDir(), "wrkr-evidence")

	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	if code := cli.Run([]string{"scan", "--path", scanPath, "--state", statePath, "--profile", "standard", "--json"}, &scanOut, &scanErr); code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, scanErr.String())
	}

	var evidenceOut bytes.Buffer
	var evidenceErr bytes.Buffer
	if code := cli.Run([]string{"evidence", "--frameworks", "eu-ai-act,soc2", "--state", statePath, "--output", outputDir, "--json"}, &evidenceOut, &evidenceErr); code != 0 {
		t.Fatalf("evidence failed: %d (%s)", code, evidenceErr.String())
	}

	profilePayload, err := os.ReadFile(filepath.Join(outputDir, "profile-compliance.json"))
	if err != nil {
		t.Fatalf("read profile output: %v", err)
	}
	var profile map[string]any
	if err := json.Unmarshal(profilePayload, &profile); err != nil {
		t.Fatalf("parse profile output: %v", err)
	}
	if _, ok := profile["compliance_percent"]; !ok {
		t.Fatalf("expected compliance_percent in profile output: %v", profile)
	}

	posturePayload, err := os.ReadFile(filepath.Join(outputDir, "posture-score.json"))
	if err != nil {
		t.Fatalf("read posture output: %v", err)
	}
	var posture map[string]any
	if err := json.Unmarshal(posturePayload, &posture); err != nil {
		t.Fatalf("parse posture output: %v", err)
	}
	for _, key := range []string{"score", "grade", "weighted_breakdown"} {
		if _, ok := posture[key]; !ok {
			t.Fatalf("expected %s in posture output: %v", key, posture)
		}
	}
}
