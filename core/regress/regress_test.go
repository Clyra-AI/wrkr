package regress

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/state"
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
