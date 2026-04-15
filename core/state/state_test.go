package state

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
	"github.com/Clyra-AI/wrkr/core/score"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

func TestResolvePath(t *testing.T) {
	if got := ResolvePath("/tmp/custom.json"); got != "/tmp/custom.json" {
		t.Fatalf("unexpected explicit path: %q", got)
	}

	t.Setenv("WRKR_STATE_PATH", "/tmp/from-env.json")
	if got := ResolvePath(""); got != "/tmp/from-env.json" {
		t.Fatalf("unexpected env path: %q", got)
	}
}

func TestStateIntegrationRoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "state.json")

	snapshot := Snapshot{
		Target: source.Target{Mode: "repo", Value: "acme/backend"},
		Targets: []source.Target{
			{Mode: "org", Value: "acme"},
			{Mode: "path", Value: "./repos"},
		},
		Findings: []source.Finding{
			{ToolType: "source_repo", Location: "acme/backend", Org: "acme", Permissions: []string{"repo.contents.read"}},
		},
	}
	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if loaded.Target.Value != "acme/backend" {
		t.Fatalf("unexpected target: %+v", loaded.Target)
	}
	if len(loaded.Targets) != 2 || loaded.Targets[0].Mode != "org" || loaded.Targets[1].Mode != "path" {
		t.Fatalf("unexpected additive targets: %+v", loaded.Targets)
	}

	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read first state: %v", err)
	}
	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot second time: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read second state: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("state file must be byte-stable\nfirst: %s\nsecond: %s", first, second)
	}
}

func TestLoadRawMatchesLoadForCanonicalSnapshot(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "state.json")

	snapshot := Snapshot{
		Target: source.Target{Mode: "repo", Value: "acme/backend"},
		Targets: []source.Target{
			{Mode: "path", Value: "./repos"},
			{Mode: "org", Value: "acme"},
		},
		Findings: []source.Finding{
			{
				ToolType:    "source_repo",
				Location:    "acme/backend",
				Org:         "acme",
				Severity:    "high",
				Permissions: []string{"repo.contents.read", "repo.contents.read"},
			},
		},
	}
	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	rawLoaded, err := LoadRaw(path)
	if err != nil {
		t.Fatalf("load raw snapshot: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load snapshot: %v", err)
	}
	if !reflect.DeepEqual(rawLoaded, loaded) {
		t.Fatalf("expected raw load to match canonical load for saved snapshot\nraw=%+v\nload=%+v", rawLoaded, loaded)
	}
}

func TestStateSaveIsAtomicUnderInterruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	initial := Snapshot{
		Target: source.Target{Mode: "repo", Value: "acme/backend"},
		Findings: []source.Finding{
			{ToolType: "source_repo", Location: "acme/backend", Org: "acme", Permissions: []string{"repo.contents.read"}},
		},
	}
	if err := Save(path, initial); err != nil {
		t.Fatalf("save initial snapshot: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read initial snapshot bytes: %v", err)
	}

	var injected atomic.Bool
	restore := atomicwrite.SetBeforeRenameHookForTest(func(targetPath string, _ string) error {
		if filepath.Clean(targetPath) != filepath.Clean(path) {
			return nil
		}
		if injected.CompareAndSwap(false, true) {
			return errors.New("simulated interruption before rename")
		}
		return nil
	})
	defer restore()

	updated := Snapshot{
		Target: source.Target{Mode: "repo", Value: "acme/updated"},
		Findings: []source.Finding{
			{ToolType: "source_repo", Location: "acme/updated", Org: "acme", Permissions: []string{"repo.contents.read"}},
		},
	}
	if err := Save(path, updated); err == nil {
		t.Fatal("expected save interruption failure")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot after interruption: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("expected snapshot bytes to remain unchanged after interruption\nbefore: %s\nafter: %s", before, after)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("expected state file to remain parseable after interruption: %v", err)
	}
}

func TestLoadScoreViewPreservesStoredScoreAndAttackPaths(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	snapshot := Snapshot{
		Findings: []source.Finding{
			{ToolType: "source_repo", Location: "acme/backend", Org: "acme", Repo: "backend"},
		},
		PostureScore: &score.Result{
			Score: 81.4,
			Grade: "B",
		},
		RiskReport: &risk.Report{
			AttackPaths: []riskattack.ScoredPath{
				{
					PathID:          "path-a",
					Org:             "acme",
					Repo:            "backend",
					PathScore:       9.1,
					EntryNodeID:     "entry-a",
					TargetNodeID:    "target-a",
					EntryExposure:   3.0,
					PivotPrivilege:  2.5,
					TargetImpact:    3.6,
					EdgeRationale:   []string{"agent_to_auth_surface"},
					Explain:         []string{"entry_exposure=3.00"},
					SourceFindings:  []string{"finding-a"},
					GenerationModel: "wrkr_attack_path_v1",
				},
			},
			TopAttackPaths: []riskattack.ScoredPath{
				{
					PathID:          "path-b",
					Org:             "acme",
					Repo:            "backend",
					PathScore:       8.4,
					EntryNodeID:     "entry-b",
					TargetNodeID:    "target-b",
					EntryExposure:   2.8,
					PivotPrivilege:  2.2,
					TargetImpact:    3.4,
					EdgeRationale:   []string{"tool_to_auth_surface"},
					Explain:         []string{"entry_exposure=2.80"},
					SourceFindings:  []string{"finding-b"},
					GenerationModel: "wrkr_attack_path_v1",
				},
			},
		},
	}
	if err := Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot: %v", err)
	}

	view, err := LoadScoreView(path)
	if err != nil {
		t.Fatalf("load score view: %v", err)
	}
	if view.PostureScore == nil || view.PostureScore.Score != 81.4 {
		t.Fatalf("unexpected stored score view: %+v", view.PostureScore)
	}
	if len(view.AttackPaths) != 1 || view.AttackPaths[0].PathID != "path-a" {
		t.Fatalf("unexpected attack paths: %+v", view.AttackPaths)
	}
	if len(view.TopAttackPaths) != 1 || view.TopAttackPaths[0].PathID != "path-b" {
		t.Fatalf("unexpected top attack paths: %+v", view.TopAttackPaths)
	}
}

func TestLoadScoreViewRejectsMalformedFindings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		payload string
	}{
		{
			name: "string",
			payload: `{
  "version": "v1",
  "findings": "bad",
  "posture_score": {
    "score": 82.5,
    "grade": "B"
  }
}`,
		},
		{
			name: "number",
			payload: `{
  "version": "v1",
  "findings": 42,
  "posture_score": {
    "score": 82.5,
    "grade": "B"
  }
}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(tc.payload), 0o600); err != nil {
				t.Fatalf("write malformed snapshot: %v", err)
			}

			if _, err := LoadScoreView(path); err == nil {
				t.Fatal("expected malformed findings to fail score view load")
			}
		})
	}
}

func TestLoadScoreViewRejectsMalformedIdentitiesPrimitive(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "state.json")
	payload := []byte(`{
  "version": "v1",
  "identities": true,
  "posture_score": {
    "score": 82.5,
    "grade": "B"
  }
}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write malformed snapshot: %v", err)
	}

	if _, err := LoadScoreView(path); err == nil {
		t.Fatal("expected malformed identities to fail score view load")
	}
}
