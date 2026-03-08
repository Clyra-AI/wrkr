package regress

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
	"github.com/Clyra-AI/wrkr/core/state"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

func TestBuildBaselineAndLoadRoundTrip(t *testing.T) {
	t.Parallel()

	snapshot := state.Snapshot{
		Findings: []model.Finding{
			{
				FindingType: "source_discovery",
				ToolType:    "source_repo",
				Location:    "acme/backend",
				Org:         "acme",
				Permissions: []string{"repo.contents.read"},
			},
		},
		Identities: []manifest.IdentityRecord{
			{
				AgentID:       identity.AgentID(identity.ToolID("source_repo", "acme/backend"), "acme"),
				ToolID:        identity.ToolID("source_repo", "acme/backend"),
				Org:           "acme",
				Status:        identity.StateActive,
				ApprovalState: "valid",
				Present:       true,
			},
		},
	}

	baseline := BuildBaseline(snapshot, time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC))
	if baseline.Version != BaselineVersion {
		t.Fatalf("unexpected baseline version %q", baseline.Version)
	}
	if len(baseline.Tools) != 1 {
		t.Fatalf("expected one tool in baseline, got %d", len(baseline.Tools))
	}
	if baseline.Tools[0].Permissions[0] != "repo.contents.read" {
		t.Fatalf("unexpected permissions: %v", baseline.Tools[0].Permissions)
	}

	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := SaveBaseline(path, baseline); err != nil {
		t.Fatalf("save baseline: %v", err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read first baseline write: %v", err)
	}
	if err := SaveBaseline(path, baseline); err != nil {
		t.Fatalf("save baseline second write: %v", err)
	}
	second, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read second baseline write: %v", err)
	}
	if string(first) != string(second) {
		t.Fatalf("baseline output must be byte stable")
	}

	loaded, err := LoadBaseline(path)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	if len(loaded.Tools) != 1 {
		t.Fatalf("expected one loaded tool, got %d", len(loaded.Tools))
	}
}

func TestSaveBaselineIsAtomicUnderInterruption(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "baseline.json")
	initial := Baseline{Version: BaselineVersion, Tools: []ToolState{{AgentID: "wrkr:source-repo-old:acme", ToolID: "source-repo-old"}}}
	if err := SaveBaseline(path, initial); err != nil {
		t.Fatalf("save initial baseline: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read initial baseline: %v", err)
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

	updated := Baseline{Version: BaselineVersion, Tools: []ToolState{{AgentID: "wrkr:source-repo-new:acme", ToolID: "source-repo-new"}}}
	if err := SaveBaseline(path, updated); err == nil {
		t.Fatal("expected interrupted baseline save to fail")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read baseline after interruption: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("expected baseline bytes to remain unchanged after interruption")
	}
	if _, err := LoadBaseline(path); err != nil {
		t.Fatalf("expected baseline to remain parseable after interruption: %v", err)
	}
}

func TestCompareFlagsNewUnapprovedTool(t *testing.T) {
	t.Parallel()

	current := state.Snapshot{
		Findings: []model.Finding{
			{
				FindingType: "source_discovery",
				ToolType:    "source_repo",
				Location:    "acme/new-repo",
				Org:         "acme",
				Permissions: []string{"repo.contents.read"},
			},
		},
	}
	result := Compare(Baseline{Version: BaselineVersion, Tools: []ToolState{}}, current)
	if !result.Drift {
		t.Fatal("expected drift for new unapproved tool")
	}
	if result.ReasonCount != 1 {
		t.Fatalf("expected one reason, got %d", result.ReasonCount)
	}
	if result.Reasons[0].Code != ReasonNewUnapprovedTool {
		t.Fatalf("unexpected reason code %q", result.Reasons[0].Code)
	}
}

func TestCompareFlagsRevokedToolReappearance(t *testing.T) {
	t.Parallel()

	toolID := identity.ToolID("source_repo", "acme/backend")
	agentID := identity.AgentID(toolID, "acme")
	baseline := Baseline{
		Version: BaselineVersion,
		Tools: []ToolState{
			{
				AgentID:        agentID,
				ToolID:         toolID,
				Org:            "acme",
				Status:         identity.StateRevoked,
				ApprovalStatus: "revoked",
				Present:        false,
			},
		},
	}
	current := state.Snapshot{
		Findings: []model.Finding{
			{
				FindingType: "source_discovery",
				ToolType:    "source_repo",
				Location:    "acme/backend",
				Org:         "acme",
				Permissions: []string{"repo.contents.read"},
			},
		},
	}
	result := Compare(baseline, current)
	if !result.Drift {
		t.Fatal("expected drift for revoked tool reappearance")
	}
	found := false
	for _, reason := range result.Reasons {
		if reason.Code == ReasonRevokedToolReappeared {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected revoked reappearance reason, got %v", result.Reasons)
	}
}

func TestCompareFlagsUnapprovedPermissionExpansion(t *testing.T) {
	t.Parallel()

	toolID := identity.ToolID("source_repo", "acme/backend")
	agentID := identity.AgentID(toolID, "acme")
	baseline := Baseline{
		Version: BaselineVersion,
		Tools: []ToolState{
			{
				AgentID:        agentID,
				ToolID:         toolID,
				Org:            "acme",
				Status:         identity.StateUnderReview,
				ApprovalStatus: "missing",
				Present:        true,
				Permissions:    []string{"repo.contents.read"},
			},
		},
	}
	current := state.Snapshot{
		Findings: []model.Finding{
			{
				FindingType: "source_discovery",
				ToolType:    "source_repo",
				Location:    "acme/backend",
				Org:         "acme",
				Permissions: []string{"repo.contents.read", "repo.actions.write"},
			},
		},
		Identities: []manifest.IdentityRecord{
			{
				AgentID:       agentID,
				ToolID:        toolID,
				Org:           "acme",
				Status:        identity.StateUnderReview,
				ApprovalState: "missing",
				Present:       true,
			},
		},
	}
	result := Compare(baseline, current)
	if !result.Drift {
		t.Fatal("expected drift for unapproved permission expansion")
	}
	found := false
	for _, reason := range result.Reasons {
		if reason.Code == ReasonPermissionExpansion {
			found = true
			if len(reason.AddedPermissions) != 1 || reason.AddedPermissions[0] != "repo.actions.write" {
				t.Fatalf("unexpected added permissions: %v", reason.AddedPermissions)
			}
		}
	}
	if !found {
		t.Fatalf("expected permission expansion reason, got %v", result.Reasons)
	}
}

func TestCompareAllowsApprovedPermissionExpansion(t *testing.T) {
	t.Parallel()

	toolID := identity.ToolID("source_repo", "acme/backend")
	agentID := identity.AgentID(toolID, "acme")
	baseline := Baseline{
		Version: BaselineVersion,
		Tools: []ToolState{
			{
				AgentID:        agentID,
				ToolID:         toolID,
				Org:            "acme",
				Status:         identity.StateActive,
				ApprovalStatus: "valid",
				Present:        true,
				Permissions:    []string{"repo.contents.read"},
			},
		},
	}
	current := state.Snapshot{
		Findings: []model.Finding{
			{
				FindingType: "source_discovery",
				ToolType:    "source_repo",
				Location:    "acme/backend",
				Org:         "acme",
				Permissions: []string{"repo.contents.read", "repo.actions.write"},
			},
		},
		Identities: []manifest.IdentityRecord{
			{
				AgentID:       agentID,
				ToolID:        toolID,
				Org:           "acme",
				Status:        identity.StateActive,
				ApprovalState: "valid",
				Present:       true,
			},
		},
	}
	result := Compare(baseline, current)
	if result.Drift {
		t.Fatalf("expected no drift for approved permission expansion, got %v", result.Reasons)
	}
}

func TestCompareDeterministicForSameInput(t *testing.T) {
	t.Parallel()

	current := state.Snapshot{
		Findings: []model.Finding{
			{
				FindingType: "source_discovery",
				ToolType:    "source_repo",
				Location:    "acme/backend",
				Org:         "acme",
				Permissions: []string{"repo.contents.read"},
			},
		},
	}
	baseline := BuildBaseline(current, time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC))
	first := Compare(baseline, current)
	second := Compare(baseline, current)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("compare must be deterministic\nfirst=%+v\nsecond=%+v", first, second)
	}
}

func TestSnapshotToolsExcludesPolicyAndParseFindingTypes(t *testing.T) {
	t.Parallel()

	snapshot := state.Snapshot{
		Findings: []model.Finding{
			{
				FindingType: "source_discovery",
				ToolType:    "source_repo",
				Location:    "acme/backend",
				Org:         "acme",
				Permissions: []string{"repo.contents.read"},
			},
			{
				FindingType: "policy_check",
				ToolType:    "policy",
				Location:    ".wrkr/policy.yaml",
				Org:         "acme",
			},
			{
				FindingType: "parse_error",
				ToolType:    "yaml",
				Location:    ".github/workflows/ci.yml",
				Org:         "acme",
			},
		},
	}

	tools := SnapshotTools(snapshot)
	if len(tools) != 1 {
		t.Fatalf("expected one tool after filtering policy/meta findings, got %d (%+v)", len(tools), tools)
	}
	if tools[0].ToolID != identity.ToolID("source_repo", "acme/backend") {
		t.Fatalf("unexpected remaining tool: %+v", tools[0])
	}
}

func TestCompareIgnoresPolicyOnlyBaselineDelta(t *testing.T) {
	t.Parallel()

	baselineSnapshot := state.Snapshot{
		Findings: []model.Finding{
			{
				FindingType: "source_discovery",
				ToolType:    "source_repo",
				Location:    "acme/backend",
				Org:         "acme",
				Permissions: []string{"repo.contents.read"},
			},
			{
				FindingType: "policy_violation",
				ToolType:    "policy",
				Location:    "WRKR-001",
				Org:         "acme",
			},
		},
	}
	currentSnapshot := state.Snapshot{
		Findings: []model.Finding{
			{
				FindingType: "source_discovery",
				ToolType:    "source_repo",
				Location:    "acme/backend",
				Org:         "acme",
				Permissions: []string{"repo.contents.read"},
			},
		},
	}

	baseline := BuildBaseline(baselineSnapshot, time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC))
	result := Compare(baseline, currentSnapshot)
	if result.Drift {
		t.Fatalf("expected no drift for policy-only baseline delta, got %v", result.Reasons)
	}
}

func TestCompareSummarizesCriticalAttackPathDrift(t *testing.T) {
	t.Parallel()

	baseline := Baseline{
		Version: BaselineVersion,
		AttackPaths: []AttackPathState{
			{PathID: "path-a", Org: "acme", Repo: "repo", Score: 8.2},
			{PathID: "path-b", Org: "acme", Repo: "repo", Score: 8.1},
			{PathID: "path-c", Org: "acme", Repo: "repo", Score: 8.5},
			{PathID: "path-d", Org: "acme", Repo: "repo", Score: 7.4},
		},
	}

	current := state.Snapshot{
		RiskReport: &risk.Report{
			AttackPaths: []riskattack.ScoredPath{
				{PathID: "path-a", Org: "acme", Repo: "repo", PathScore: 9.7},
				{PathID: "path-c", Org: "acme", Repo: "repo", PathScore: 8.5},
				{PathID: "path-x", Org: "acme", Repo: "repo", PathScore: 9.0},
				{PathID: "path-y", Org: "acme", Repo: "repo", PathScore: 8.6},
			},
		},
	}

	result := Compare(baseline, current)
	second := Compare(baseline, current)
	if !result.Drift {
		t.Fatal("expected drift for significant attack path divergence")
	}
	if !reflect.DeepEqual(result, second) {
		t.Fatalf("expected deterministic summarized drift output\nfirst=%+v\nsecond=%+v", result, second)
	}
	if result.ReasonCount != 1 {
		t.Fatalf("expected a single summarized reason, got %d (%v)", result.ReasonCount, result.Reasons)
	}
	reason := result.Reasons[0]
	if reason.Code != ReasonCriticalAttackPath {
		t.Fatalf("unexpected reason code %q", reason.Code)
	}
	if reason.AttackPathDrift == nil {
		t.Fatal("expected attack_path_drift details")
	}
	detail := reason.AttackPathDrift
	if detail.DriftCount != 4 {
		t.Fatalf("expected drift_count=4, got %d", detail.DriftCount)
	}
	if len(detail.Added) != 2 || len(detail.Removed) != 1 || len(detail.ScoreChanged) != 1 {
		t.Fatalf("unexpected detail counts added=%d removed=%d score_changed=%d", len(detail.Added), len(detail.Removed), len(detail.ScoreChanged))
	}
	if reason.ToolID != "attack_paths" {
		t.Fatalf("unexpected summarized tool_id %q", reason.ToolID)
	}
}

func TestCompareSuppressesAttackPathDriftBelowThreshold(t *testing.T) {
	t.Parallel()

	baseline := Baseline{
		Version: BaselineVersion,
		AttackPaths: []AttackPathState{
			{PathID: "path-a", Org: "acme", Repo: "repo", Score: 8.2},
			{PathID: "path-b", Org: "acme", Repo: "repo", Score: 8.1},
		},
	}

	current := state.Snapshot{
		RiskReport: &risk.Report{
			AttackPaths: []riskattack.ScoredPath{
				{PathID: "path-a", Org: "acme", Repo: "repo", PathScore: 9.3},
				{PathID: "path-b", Org: "acme", Repo: "repo", PathScore: 8.1},
			},
		},
	}

	result := Compare(baseline, current)
	if result.Drift {
		t.Fatalf("expected no drift below summary threshold, got %v", result.Reasons)
	}
}
