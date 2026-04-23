package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestInventoryApproveWritesApprovalProofRecordAtomically(t *testing.T) {
	tmp := t.TempDir()
	statePath, agentID := writeInventoryMutationFixture(t, tmp)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"inventory", "approve", agentID,
		"--owner", "platform-security",
		"--evidence", "https://tickets.example/SEC-123",
		"--expires", time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339),
		"--state", statePath,
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("inventory approve failed: code=%d stderr=%s", code, errOut.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("expected clean stderr, got %q", errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse approve payload: %v", err)
	}
	if payload["approval_inventory_version"] != manifest.ApprovalInventoryVersion {
		t.Fatalf("expected approval_inventory_version, got %v", payload)
	}

	loadedManifest, err := manifest.Load(manifest.ResolvePath(statePath))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	if loadedManifest.Identities[0].Approval.Owner != "platform-security" {
		t.Fatalf("expected approval owner, got %+v", loadedManifest.Identities[0].Approval)
	}
	if loadedManifest.Identities[0].ApprovalState != "valid" {
		t.Fatalf("expected valid approval, got %+v", loadedManifest.Identities[0])
	}
	loadedState, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if loadedState.ApprovalInventoryVersion != state.ApprovalInventoryVersion {
		t.Fatalf("expected state approval inventory version, got %q", loadedState.ApprovalInventoryVersion)
	}
	if loadedState.ControlBacklog == nil || len(loadedState.ControlBacklog.Items) != 1 {
		t.Fatalf("expected retained backlog item after approval, got %+v", loadedState.ControlBacklog)
	}
	if loadedState.ControlBacklog.Items[0].RecommendedAction != controlbacklog.ActionMonitor {
		t.Fatalf("expected approved item to move to monitor, got %+v", loadedState.ControlBacklog.Items[0])
	}

	chain, err := proofemit.LoadChain(proofemit.ChainPath(statePath))
	if err != nil {
		t.Fatalf("load proof chain: %v", err)
	}
	found := false
	for _, record := range chain.Records {
		eventType, _ := record.Event["event_type"].(string)
		if record.RecordType == "approval" && eventType == "approval_recorded" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected approval_recorded proof record, got %+v", chain.Records)
	}
}

func TestInventoryAcceptRiskRequiresExpiry(t *testing.T) {
	tmp := t.TempDir()
	statePath, agentID := writeInventoryMutationFixture(t, tmp)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"inventory", "accept-risk", agentID, "--state", statePath, "--json"}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit 6, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if out.Len() != 0 {
		t.Fatalf("expected no stdout on invalid input, got %q", out.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(errOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse error payload: %v", err)
	}
	errObj, _ := payload["error"].(map[string]any)
	if errObj["code"] != "invalid_input" {
		t.Fatalf("expected invalid_input, got %v", payload)
	}
}

func TestInventoryMutationRejectsUnsafeManagedMarker(t *testing.T) {
	tmp := t.TempDir()
	realStatePath, agentID := writeInventoryMutationFixture(t, tmp)
	stateLink := filepath.Join(tmp, "state-link.json")
	if err := os.Symlink(filepath.Base(realStatePath), stateLink); err != nil {
		t.Fatalf("create state symlink: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"inventory", "deprecate", agentID,
		"--reason", "retired",
		"--state", stateLink,
		"--json",
	}, &out, &errOut)
	if code != exitUnsafeBlocked {
		t.Fatalf("expected unsafe exit 8, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "regular file") {
		t.Fatalf("expected regular-file safety error, got %q", errOut.String())
	}
}

func TestInventoryApproveUpdatesOnlyResolvedAgentID(t *testing.T) {
	tmp := t.TempDir()
	statePath, agentID := writeInventoryMutationFixture(t, tmp)
	loadedState, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	loadedManifest, err := manifest.Load(manifest.ResolvePath(statePath))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	sharedToolID := loadedManifest.Identities[0].ToolID
	other := loadedManifest.Identities[0]
	other.AgentID = identity.AgentID(sharedToolID, "beta")
	other.Org = "beta"
	other.Repo = "beta/repo"
	other.ApprovalState = "missing"
	other.Status = identity.StateUnderReview
	loadedManifest.Identities = append(loadedManifest.Identities, other)
	if err := manifest.Save(manifest.ResolvePath(statePath), loadedManifest); err != nil {
		t.Fatalf("save expanded manifest: %v", err)
	}
	loadedState.Identities = append(loadedState.Identities, other)
	loadedState.Inventory.Tools = append(loadedState.Inventory.Tools, agginventory.Tool{
		ToolID:         sharedToolID,
		AgentID:        other.AgentID,
		ToolType:       "codex",
		Org:            "beta",
		Repos:          []string{"beta/repo"},
		Locations:      []agginventory.ToolLocation{{Repo: "beta/repo", Location: "AGENTS.md"}},
		ApprovalStatus: "missing",
		ApprovalClass:  "unapproved",
		LifecycleState: identity.StateUnderReview,
	})
	if err := state.Save(statePath, loadedState); err != nil {
		t.Fatalf("save expanded state: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"inventory", "approve", agentID,
		"--owner", "platform-security",
		"--evidence", "SEC-123",
		"--expires", "90d",
		"--state", statePath,
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("inventory approve failed: code=%d stderr=%s", code, errOut.String())
	}
	next, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load mutated state: %v", err)
	}
	byAgent := map[string]agginventory.Tool{}
	for _, tool := range next.Inventory.Tools {
		byAgent[tool.AgentID] = tool
	}
	if byAgent[agentID].ApprovalStatus != "valid" {
		t.Fatalf("expected targeted agent approved, got %+v", byAgent[agentID])
	}
	if byAgent[other.AgentID].ApprovalStatus != "missing" {
		t.Fatalf("expected non-target agent unchanged, got %+v", byAgent[other.AgentID])
	}
}

func TestInventoryMutationRejectsAmbiguousToolID(t *testing.T) {
	tmp := t.TempDir()
	statePath, _ := writeInventoryMutationFixture(t, tmp)
	loadedState, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	loadedManifest, err := manifest.Load(manifest.ResolvePath(statePath))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	sharedToolID := loadedManifest.Identities[0].ToolID
	other := loadedManifest.Identities[0]
	other.AgentID = identity.AgentID(sharedToolID, "beta")
	other.Org = "beta"
	other.Repo = "beta/repo"
	loadedManifest.Identities = append(loadedManifest.Identities, other)
	if err := manifest.Save(manifest.ResolvePath(statePath), loadedManifest); err != nil {
		t.Fatalf("save expanded manifest: %v", err)
	}
	loadedState.Identities = append(loadedState.Identities, other)
	if err := state.Save(statePath, loadedState); err != nil {
		t.Fatalf("save expanded state: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"inventory", "approve", sharedToolID,
		"--owner", "platform-security",
		"--evidence", "SEC-123",
		"--expires", "90d",
		"--state", statePath,
		"--json",
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit 6, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	if !strings.Contains(errOut.String(), "ambiguous") {
		t.Fatalf("expected ambiguous tool_id error, got %q", errOut.String())
	}
}

func writeInventoryMutationFixture(t *testing.T, dir string) (string, string) {
	t.Helper()
	statePath := filepath.Join(dir, "state.json")
	toolID := identity.ToolID("codex", "AGENTS.md")
	agentID := identity.AgentID(toolID, "acme")
	record := manifest.IdentityRecord{
		AgentID:       agentID,
		ToolID:        toolID,
		ToolType:      "codex",
		Org:           "acme",
		Repo:          "acme/repo",
		Location:      "AGENTS.md",
		Status:        identity.StateUnderReview,
		ApprovalState: "missing",
		FirstSeen:     "2026-04-22T12:00:00Z",
		LastSeen:      "2026-04-22T12:00:00Z",
		Present:       true,
	}
	if err := manifest.Save(manifest.ResolvePath(statePath), manifest.Manifest{
		Version:   manifest.Version,
		UpdatedAt: "2026-04-22T12:00:00Z",
		Identities: []manifest.IdentityRecord{
			record,
		},
	}); err != nil {
		t.Fatalf("save manifest: %v", err)
	}
	inventory := agginventory.Inventory{
		InventoryVersion: "1",
		Org:              "acme",
		Tools: []agginventory.Tool{
			{
				ToolID:         toolID,
				AgentID:        agentID,
				ToolType:       "codex",
				Org:            "acme",
				Repos:          []string{"acme/repo"},
				Locations:      []agginventory.ToolLocation{{Repo: "acme/repo", Location: "AGENTS.md"}},
				ApprovalStatus: "missing",
				ApprovalClass:  "unapproved",
				LifecycleState: identity.StateUnderReview,
			},
		},
	}
	backlog := controlbacklog.Backlog{
		ControlBacklogVersion: controlbacklog.BacklogVersion,
		Summary:               controlbacklog.Summary{TotalItems: 1, ApproveActionItems: 1},
		Items: []controlbacklog.Item{
			{
				ID:                 "cb-1",
				Repo:               "acme/repo",
				Path:               "AGENTS.md",
				ControlSurfaceType: controlbacklog.ControlSurfaceCodingAssistant,
				ControlPathType:    controlbacklog.ControlPathAgentConfig,
				Capability:         "repo.contents.read",
				EvidenceSource:     "test",
				EvidenceBasis:      []string{"fixture"},
				ApprovalStatus:     "missing",
				SecurityVisibility: agginventory.SecurityVisibilityNeedsReview,
				SignalClass:        controlbacklog.SignalClassUniqueWrkrSignal,
				RecommendedAction:  controlbacklog.ActionApprove,
				Confidence:         controlbacklog.ConfidenceMedium,
				SLA:                "14d",
				ClosureCriteria:    "Record approval evidence and review cadence.",
			},
		},
	}
	if err := state.Save(statePath, state.Snapshot{
		Version:        state.SnapshotVersion,
		Target:         source.Target{Mode: "path", Value: dir},
		Findings:       []source.Finding{},
		Inventory:      &inventory,
		ControlBacklog: &backlog,
		Identities:     []manifest.IdentityRecord{record},
	}); err != nil {
		t.Fatalf("save state: %v", err)
	}
	return statePath, agentID
}
