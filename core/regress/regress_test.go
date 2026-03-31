package regress

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
				FindingType: "tool_config",
				ToolType:    "codex",
				Location:    "AGENTS.md",
				Org:         "acme",
				Permissions: []string{"repo.contents.read"},
			},
		},
		Identities: []manifest.IdentityRecord{
			{
				AgentID:       identity.AgentID(identity.ToolID("codex", "AGENTS.md"), "acme"),
				ToolID:        identity.ToolID("codex", "AGENTS.md"),
				ToolType:      "codex",
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

func TestLoadComparableBaselineAcceptsScanSnapshot(t *testing.T) {
	t.Parallel()

	snapshot := state.Snapshot{
		Version: state.SnapshotVersion,
		Findings: []model.Finding{
			{
				FindingType: "tool_config",
				ToolType:    "codex",
				Location:    "AGENTS.md",
				Org:         "acme",
				Permissions: []string{"repo.contents.read"},
			},
		},
		Identities: []manifest.IdentityRecord{
			{
				AgentID:       identity.AgentID(identity.ToolID("codex", "AGENTS.md"), "acme"),
				ToolID:        identity.ToolID("codex", "AGENTS.md"),
				ToolType:      "codex",
				Org:           "acme",
				Status:        identity.StateActive,
				ApprovalState: "valid",
				Present:       true,
			},
		},
	}
	path := filepath.Join(t.TempDir(), "inventory-baseline.json")
	if err := state.Save(path, snapshot); err != nil {
		t.Fatalf("save snapshot baseline: %v", err)
	}

	loaded, err := LoadComparableBaseline(path)
	if err != nil {
		t.Fatalf("load comparable baseline: %v", err)
	}
	expected := BuildBaselineFromSnapshot(snapshot)
	if !reflect.DeepEqual(expected, loaded) {
		t.Fatalf("unexpected snapshot baseline conversion\nwant=%+v\ngot=%+v", expected, loaded)
	}
}

func TestLoadComparableBaselinePrefersSnapshotMarkersOverAttackPaths(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "scan-json-baseline.json")
	payload := []byte(`{
  "status": "ok",
  "target": {"mode": "path", "value": "repos"},
  "findings": [
    {
      "finding_type": "tool_config",
      "tool_type": "agentframework",
      "location": ".wrkr/agents/research.yaml",
      "org": "acme",
      "repo": "backend",
      "permissions": ["repo.contents.read"]
    }
  ],
  "attack_paths": [
    {"path_id": "ap-1", "org": "acme", "repo": "backend", "path_score": 9.1}
  ]
}
`)
	if err := os.WriteFile(path, append(payload, '\n'), 0o600); err != nil {
		t.Fatalf("write scan json baseline: %v", err)
	}

	loaded, err := LoadComparableBaseline(path)
	if err != nil {
		t.Fatalf("load comparable baseline: %v", err)
	}
	if len(loaded.Tools) != 1 {
		t.Fatalf("expected one tool from snapshot payload, got %+v", loaded)
	}
	if loaded.Tools[0].ToolID == "" {
		t.Fatalf("expected normalized tool id from snapshot payload, got %+v", loaded.Tools[0])
	}
}

func TestLoadComparableBaselineRejectsUnknownPayload(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte("{\"version\":\"v1\",\"foo\":\"bar\"}\n"), 0o600); err != nil {
		t.Fatalf("write unknown payload: %v", err)
	}

	_, err := LoadComparableBaseline(path)
	if err == nil {
		t.Fatal("expected unknown payload to fail")
	}
	if got := err.Error(); !strings.Contains(got, "expected regress baseline artifact or scan snapshot") {
		t.Fatalf("unexpected error: %v", err)
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
				FindingType: "tool_config",
				ToolType:    "codex",
				Location:    "AGENTS.md",
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

func TestCompareIgnoresExtensionFindingsByDefault(t *testing.T) {
	t.Parallel()

	current := state.Snapshot{
		Findings: []model.Finding{
			{
				FindingType: "custom_extension_finding",
				ToolType:    "custom_detector",
				Detector:    "extension",
				Location:    "README.md",
				Org:         "acme",
				Repo:        "repo",
			},
		},
	}

	if tools := SnapshotTools(current); len(tools) != 0 {
		t.Fatalf("expected extension finding to stay out of baseline tools, got %+v", tools)
	}
	result := Compare(Baseline{Version: BaselineVersion, Tools: []ToolState{}}, current)
	if result.Drift {
		t.Fatalf("expected no drift for extension-only finding, got %+v", result)
	}
}

func TestCompareFlagsRevokedToolReappearance(t *testing.T) {
	t.Parallel()

	toolID := identity.ToolID("codex", "AGENTS.md")
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
				FindingType: "tool_config",
				ToolType:    "codex",
				Location:    "AGENTS.md",
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

	toolID := identity.ToolID("codex", "AGENTS.md")
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
				FindingType: "tool_config",
				ToolType:    "codex",
				Location:    "AGENTS.md",
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

	toolID := identity.ToolID("codex", "AGENTS.md")
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
				FindingType: "tool_config",
				ToolType:    "codex",
				Location:    "AGENTS.md",
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

func TestCompareScopesInstanceMatchingToOrg(t *testing.T) {
	t.Parallel()

	baseline := Baseline{
		Version: BaselineVersion,
		Tools: []ToolState{
			{
				AgentID:         "wrkr:shared-instance:beta",
				AgentInstanceID: "shared-instance",
				ToolID:          "shared-instance",
				Org:             "beta",
				Status:          identity.StateRevoked,
				ApprovalStatus:  "revoked",
				Present:         false,
			},
			{
				AgentID:         "wrkr:shared-instance:acme",
				AgentInstanceID: "shared-instance",
				ToolID:          "shared-instance",
				Org:             "acme",
				Status:          identity.StateActive,
				ApprovalStatus:  "valid",
				Present:         true,
			},
		},
	}
	current := state.Snapshot{
		Identities: []manifest.IdentityRecord{{
			AgentID:       "wrkr:shared-instance:beta",
			ToolID:        "shared-instance",
			Org:           "beta",
			Status:        identity.StateRevoked,
			ApprovalState: "revoked",
			Present:       true,
		}},
	}

	result := Compare(baseline, current)
	if !result.Drift {
		t.Fatalf("expected revoked beta instance to match its org-scoped baseline, got %v", result.Reasons)
	}
	if len(result.Reasons) != 1 || result.Reasons[0].Code != ReasonRevokedToolReappeared {
		t.Fatalf("expected revoked reappearance reason, got %v", result.Reasons)
	}
	if result.Reasons[0].Org != "beta" {
		t.Fatalf("expected beta org attribution, got %+v", result.Reasons[0])
	}
}

func TestCompareDeterministicForSameInput(t *testing.T) {
	t.Parallel()

	current := state.Snapshot{
		Findings: []model.Finding{
			{
				FindingType: "tool_config",
				ToolType:    "codex",
				Location:    "AGENTS.md",
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
				FindingType: "tool_config",
				ToolType:    "codex",
				Location:    "AGENTS.md",
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
			{
				FindingType: "secret_presence",
				ToolType:    "secret",
				Location:    ".env",
				Org:         "acme",
			},
		},
	}

	tools := SnapshotTools(snapshot)
	if len(tools) != 1 {
		t.Fatalf("expected one tool after filtering policy/meta findings, got %d (%+v)", len(tools), tools)
	}
	if tools[0].ToolID != identity.ToolID("codex", "AGENTS.md") {
		t.Fatalf("unexpected remaining tool: %+v", tools[0])
	}
}

func TestCompareIgnoresPolicyOnlyBaselineDelta(t *testing.T) {
	t.Parallel()

	baselineSnapshot := state.Snapshot{
		Findings: []model.Finding{
			{
				FindingType: "tool_config",
				ToolType:    "codex",
				Location:    "AGENTS.md",
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
				FindingType: "tool_config",
				ToolType:    "codex",
				Location:    "AGENTS.md",
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

func TestCompareAllowsLegacyBaselineForEquivalentInstanceIdentity(t *testing.T) {
	t.Parallel()

	finding := model.Finding{
		FindingType:   "tool_config",
		ToolType:      "agentframework",
		Location:      ".wrkr/agents/research.yaml",
		LocationRange: &model.LocationRange{StartLine: 12, EndLine: 24},
		Org:           "acme",
		Repo:          "backend",
		Evidence:      []model.Evidence{{Key: "symbol", Value: "research_agent"}},
	}
	legacySnapshot := state.Snapshot{Findings: []model.Finding{finding}}
	baseline := BuildBaseline(legacySnapshot, time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC))

	instanceToolID := identity.AgentInstanceID(finding.ToolType, finding.Location, "research_agent", 12, 24)
	current := state.Snapshot{
		Findings: []model.Finding{finding},
		Identities: []manifest.IdentityRecord{{
			AgentID:       identity.AgentID(instanceToolID, "acme"),
			ToolID:        instanceToolID,
			Org:           "acme",
			Status:        identity.StateUnderReview,
			ApprovalState: "missing",
			Present:       true,
		}},
	}

	result := Compare(baseline, current)
	if result.Drift {
		t.Fatalf("expected no drift for equivalent legacy baseline and instance identity, got %v", result.Reasons)
	}
}

func TestCompareFlagsAdditionalInstanceBeyondLegacyBaseline(t *testing.T) {
	t.Parallel()

	baseFinding := model.Finding{
		FindingType: "tool_config",
		ToolType:    "agentframework",
		Location:    ".wrkr/agents/research.yaml",
		Org:         "acme",
		Repo:        "backend",
	}
	baseline := BuildBaseline(state.Snapshot{Findings: []model.Finding{baseFinding}}, time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC))

	currentFindings := []model.Finding{
		{
			FindingType:   "tool_config",
			ToolType:      "agentframework",
			Location:      ".wrkr/agents/research.yaml",
			LocationRange: &model.LocationRange{StartLine: 12, EndLine: 24},
			Org:           "acme",
			Repo:          "backend",
			Evidence:      []model.Evidence{{Key: "symbol", Value: "research_agent"}},
		},
		{
			FindingType:   "tool_config",
			ToolType:      "agentframework",
			Location:      ".wrkr/agents/research.yaml",
			LocationRange: &model.LocationRange{StartLine: 30, EndLine: 42},
			Org:           "acme",
			Repo:          "backend",
			Evidence:      []model.Evidence{{Key: "symbol", Value: "ops_agent"}},
		},
	}
	current := state.Snapshot{
		Findings: currentFindings,
		Identities: []manifest.IdentityRecord{
			{
				AgentID:       identity.AgentID(identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "research_agent", 12, 24), "acme"),
				ToolID:        identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "research_agent", 12, 24),
				Org:           "acme",
				Status:        identity.StateUnderReview,
				ApprovalState: "missing",
				Present:       true,
			},
			{
				AgentID:       identity.AgentID(identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "ops_agent", 30, 42), "acme"),
				ToolID:        identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "ops_agent", 30, 42),
				Org:           "acme",
				Status:        identity.StateUnderReview,
				ApprovalState: "missing",
				Present:       true,
			},
		},
	}

	result := Compare(baseline, current)
	if !result.Drift {
		t.Fatal("expected drift when current state contains an additional instance beyond the legacy baseline")
	}
	found := false
	for _, reason := range result.Reasons {
		if reason.Code == ReasonNewUnapprovedTool {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected new_unapproved_tool reason, got %v", result.Reasons)
	}
}

func TestCompareIgnoresLegacyNonToolBaselineEntries(t *testing.T) {
	t.Parallel()

	realToolID := identity.ToolID("codex", "AGENTS.md")
	legacySourceToolID := identity.ToolID("source_repo", "acme/backend")
	legacySecretToolID := identity.ToolID("secret", "process:env")
	baseline := Baseline{
		Version: BaselineVersion,
		Tools: []ToolState{
			{
				AgentID:        identity.AgentID(realToolID, "acme"),
				ToolID:         realToolID,
				Org:            "acme",
				Status:         identity.StateUnderReview,
				ApprovalStatus: "missing",
				Present:        true,
				Permissions:    []string{"repo.contents.read"},
			},
			{
				AgentID:        identity.AgentID(legacySourceToolID, "acme"),
				ToolID:         legacySourceToolID,
				Org:            "acme",
				Status:         identity.StateRevoked,
				ApprovalStatus: "revoked",
				Present:        false,
			},
			{
				AgentID:        identity.AgentID(legacySecretToolID, "acme"),
				ToolID:         legacySecretToolID,
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
				FindingType: "tool_config",
				ToolType:    "codex",
				Location:    "AGENTS.md",
				Org:         "acme",
				Permissions: []string{"repo.contents.read"},
			},
			{
				FindingType: "source_discovery",
				ToolType:    "source_repo",
				Location:    "acme/backend",
				Org:         "acme",
				Permissions: []string{"repo.contents.read"},
			},
			{
				FindingType: "secret_presence",
				ToolType:    "secret",
				Location:    "process:env",
				Org:         "acme",
				Permissions: []string{"env.read"},
			},
		},
		Identities: []manifest.IdentityRecord{
			{
				AgentID:       identity.AgentID(realToolID, "acme"),
				ToolID:        realToolID,
				ToolType:      "codex",
				Org:           "acme",
				Status:        identity.StateUnderReview,
				ApprovalState: "missing",
				Present:       true,
			},
			{
				AgentID:       identity.AgentID(legacySourceToolID, "acme"),
				ToolID:        legacySourceToolID,
				ToolType:      "source_repo",
				Org:           "acme",
				Status:        identity.StateRevoked,
				ApprovalState: "revoked",
				Present:       true,
			},
		},
	}

	result := Compare(baseline, current)
	if result.Drift {
		t.Fatalf("expected no drift from legacy non-tool baseline entries, got %v", result.Reasons)
	}
}

func TestBuildBaselineCarriesAgentInstanceIDAdditively(t *testing.T) {
	t.Parallel()

	snapshot := state.Snapshot{
		Findings: []model.Finding{{
			FindingType:   "tool_config",
			ToolType:      "agentframework",
			Location:      ".wrkr/agents/research.yaml",
			LocationRange: &model.LocationRange{StartLine: 12, EndLine: 24},
			Org:           "acme",
			Repo:          "backend",
			Evidence:      []model.Evidence{{Key: "symbol", Value: "research_agent"}},
		}},
		Identities: []manifest.IdentityRecord{{
			AgentID:       identity.AgentID(identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "research_agent", 12, 24), "acme"),
			ToolID:        identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "research_agent", 12, 24),
			Org:           "acme",
			Status:        identity.StateUnderReview,
			ApprovalState: "missing",
			Present:       true,
		}},
	}

	baseline := BuildBaseline(snapshot, time.Date(2026, 2, 21, 12, 0, 0, 0, time.UTC))
	if len(baseline.Tools) != 1 {
		t.Fatalf("expected one baseline tool, got %d", len(baseline.Tools))
	}
	if baseline.Tools[0].AgentInstanceID == "" {
		t.Fatalf("expected additive agent_instance_id in baseline tool state, got %+v", baseline.Tools[0])
	}
}

func TestCompareDriftReasonCarriesAgentInstanceID(t *testing.T) {
	t.Parallel()

	current := state.Snapshot{
		Findings: []model.Finding{{
			FindingType:   "tool_config",
			ToolType:      "agentframework",
			Location:      ".wrkr/agents/research.yaml",
			LocationRange: &model.LocationRange{StartLine: 30, EndLine: 42},
			Org:           "acme",
			Repo:          "backend",
			Evidence:      []model.Evidence{{Key: "symbol", Value: "ops_agent"}},
		}},
		Identities: []manifest.IdentityRecord{{
			AgentID:       identity.AgentID(identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "ops_agent", 30, 42), "acme"),
			ToolID:        identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "ops_agent", 30, 42),
			Org:           "acme",
			Status:        identity.StateUnderReview,
			ApprovalState: "missing",
			Present:       true,
		}},
	}

	result := Compare(Baseline{Version: BaselineVersion, Tools: []ToolState{}}, current)
	if !result.Drift || len(result.Reasons) != 1 {
		t.Fatalf("expected a single drift reason, got %+v", result)
	}
	if result.Reasons[0].AgentInstanceID == "" {
		t.Fatalf("expected drift reason to carry additive agent_instance_id, got %+v", result.Reasons[0])
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
