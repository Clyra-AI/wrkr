//go:build scenario

package scenarios

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/cli"
)

func TestScenarioAggregateExposureIncludesSkillFields(t *testing.T) {
	t.Parallel()
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := cli.Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("scan failed: %d (%s)", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	summaries, ok := payload["repo_exposure_summaries"].([]any)
	if !ok || len(summaries) == 0 {
		t.Fatalf("expected repo exposure summaries, got %T", payload["repo_exposure_summaries"])
	}
	summary, ok := summaries[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected summary shape %T", summaries[0])
	}
	for _, key := range []string{"skill_privilege_ceiling", "skill_privilege_concentration", "skill_sprawl"} {
		if _, present := summary[key]; !present {
			t.Fatalf("missing %s in %v", key, summary)
		}
	}
}

func TestScenarioProfileComplianceAndScoreDeterminism(t *testing.T) {
	t.Parallel()
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "policy-check", "repos")
	statePath := filepath.Join(t.TempDir(), "state.json")

	run := func() map[string]any {
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
		return payload
	}

	first := run()
	second := run()

	profileA, ok := first["profile"].(map[string]any)
	if !ok {
		t.Fatalf("expected profile payload, got %T", first["profile"])
	}
	profileB, ok := second["profile"].(map[string]any)
	if !ok {
		t.Fatalf("expected profile payload, got %T", second["profile"])
	}
	if profileA["compliance_percent"] != profileB["compliance_percent"] {
		t.Fatalf("expected deterministic profile compliance, got %v and %v", profileA["compliance_percent"], profileB["compliance_percent"])
	}
	scoreA, ok := first["posture_score"].(map[string]any)
	if !ok {
		t.Fatalf("expected posture_score payload, got %T", first["posture_score"])
	}
	scoreB, ok := second["posture_score"].(map[string]any)
	if !ok {
		t.Fatalf("expected posture_score payload, got %T", second["posture_score"])
	}
	if scoreA["score"] != scoreB["score"] {
		t.Fatalf("expected deterministic score, got %v and %v", scoreA["score"], scoreB["score"])
	}
}
