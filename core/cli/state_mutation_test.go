package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/proofemit"
	"github.com/Clyra-AI/wrkr/core/regress"
	"github.com/Clyra-AI/wrkr/core/state"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

func TestIdentityApproveUpdatesSavedStateSnapshot(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	agentID := scanIdentityAgentID(t, statePath)

	var approveOut bytes.Buffer
	var approveErr bytes.Buffer
	if code := Run([]string{"identity", "approve", agentID, "--approver", "@maria", "--scope", "read-only", "--expires", "90d", "--state", statePath, "--json"}, &approveOut, &approveErr); code != 0 {
		t.Fatalf("identity approve failed: %d %s", code, approveErr.String())
	}

	snapshot, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	stateRecord, ok := testIdentityRecord(snapshot.Identities, agentID)
	if !ok {
		t.Fatalf("expected state identity %s in snapshot", agentID)
	}
	if stateRecord.Status != identity.StateApproved {
		t.Fatalf("expected saved state status approved, got %+v", stateRecord)
	}
	if stateRecord.ApprovalState != "valid" {
		t.Fatalf("expected saved state approval_status=valid, got %+v", stateRecord)
	}
	if snapshot.PostureScore == nil || snapshot.PostureScore.Breakdown.ApprovalCoverage <= 0 {
		t.Fatalf("expected recomputed posture score approval coverage, got %+v", snapshot.PostureScore)
	}

	loadedManifest, err := manifest.Load(manifest.ResolvePath(statePath))
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	manifestRecord, ok := testIdentityRecord(loadedManifest.Identities, agentID)
	if !ok {
		t.Fatalf("expected manifest identity %s", agentID)
	}
	if manifestRecord.Status != stateRecord.Status || manifestRecord.ApprovalState != stateRecord.ApprovalState {
		t.Fatalf("expected manifest/state parity, manifest=%+v state=%+v", manifestRecord, stateRecord)
	}
}

func TestInventoryApproveRollsBackSavedStateOnProofEmitFailure(t *testing.T) {
	tmp := t.TempDir()
	statePath, agentID := writeInventoryMutationFixture(t, tmp)
	manifestPath := manifest.ResolvePath(statePath)
	lifecyclePath := lifecycle.ChainPath(statePath)
	proofChainPath := proofemit.ChainPath(statePath)
	proofAttestationPath := proofemit.ChainAttestationPath(proofChainPath)
	signingKeyPath := proofemit.SigningKeyPath(statePath)

	stateBefore := readOptionalTestFile(t, statePath)
	manifestBefore := readOptionalTestFile(t, manifestPath)
	lifecycleBefore := readOptionalTestFile(t, lifecyclePath)
	proofBefore := readOptionalTestFile(t, proofChainPath)
	attestationBefore := readOptionalTestFile(t, proofAttestationPath)
	signingKeyBefore := readOptionalTestFile(t, signingKeyPath)

	var injected atomic.Bool
	restore := atomicwrite.SetBeforeRenameHookForTest(func(targetPath string, _ string) error {
		if filepath.Clean(targetPath) != filepath.Clean(proofChainPath) {
			return nil
		}
		if injected.CompareAndSwap(false, true) {
			return errors.New("simulated interruption before proof chain rename")
		}
		return nil
	})
	defer restore()

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
	if code != exitRuntime {
		t.Fatalf("expected runtime failure, got %d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "runtime_failure", exitRuntime)

	assertOptionalTestFileEquals(t, statePath, stateBefore)
	assertOptionalTestFileEquals(t, manifestPath, manifestBefore)
	assertOptionalTestFileEquals(t, lifecyclePath, lifecycleBefore)
	assertOptionalTestFileEquals(t, proofChainPath, proofBefore)
	assertOptionalTestFileEquals(t, proofAttestationPath, attestationBefore)
	assertOptionalTestFileEquals(t, signingKeyPath, signingKeyBefore)
}

func TestScoreReflectsIdentityApproveWithoutRescan(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	agentID := scanIdentityAgentID(t, statePath)

	before := runScoreJSON(t, statePath)
	beforeBreakdown, ok := before["breakdown"].(map[string]any)
	if !ok {
		t.Fatalf("expected score breakdown, got %v", before)
	}
	beforeCoverage, ok := beforeBreakdown["approval_coverage"].(float64)
	if !ok {
		t.Fatalf("expected approval_coverage float, got %v", beforeBreakdown)
	}

	var approveOut bytes.Buffer
	var approveErr bytes.Buffer
	if code := Run([]string{"identity", "approve", agentID, "--approver", "@maria", "--scope", "read-only", "--expires", "90d", "--state", statePath, "--json"}, &approveOut, &approveErr); code != 0 {
		t.Fatalf("identity approve failed: %d %s", code, approveErr.String())
	}

	after := runScoreJSON(t, statePath)
	afterBreakdown, ok := after["breakdown"].(map[string]any)
	if !ok {
		t.Fatalf("expected score breakdown after approval, got %v", after)
	}
	afterCoverage, ok := afterBreakdown["approval_coverage"].(float64)
	if !ok {
		t.Fatalf("expected approval_coverage float after approval, got %v", afterBreakdown)
	}
	if afterCoverage <= beforeCoverage {
		t.Fatalf("expected approval coverage to increase after approval, before=%.2f after=%.2f", beforeCoverage, afterCoverage)
	}
}

func TestReportReflectsInventoryApproveWithoutRescan(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	agentID := scanIdentityAgentID(t, statePath)

	snapshotBefore, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load state before approval: %v", err)
	}
	recordBefore, ok := testIdentityRecord(snapshotBefore.Identities, agentID)
	if !ok {
		t.Fatalf("missing identity %s before approval", agentID)
	}

	before := runReportJSON(t, statePath)
	beforeItem, ok := reportBacklogItem(before, recordBefore.Repo, recordBefore.Location)
	if !ok {
		t.Fatalf("expected report backlog item for %s %s before approval", recordBefore.Repo, recordBefore.Location)
	}
	if beforeItem["approval_status"] == "valid" {
		t.Fatalf("expected pre-approval report item to remain unapproved, got %v", beforeItem)
	}

	var approveOut bytes.Buffer
	var approveErr bytes.Buffer
	if code := Run([]string{
		"inventory", "approve", agentID,
		"--owner", "platform-security",
		"--evidence", "SEC-123",
		"--expires", "90d",
		"--state", statePath,
		"--json",
	}, &approveOut, &approveErr); code != 0 {
		t.Fatalf("inventory approve failed: %d %s", code, approveErr.String())
	}

	after := runReportJSON(t, statePath)
	afterItem, ok := reportBacklogItem(after, recordBefore.Repo, recordBefore.Location)
	if !ok {
		t.Fatalf("expected report backlog item for %s %s after approval", recordBefore.Repo, recordBefore.Location)
	}
	if afterItem["approval_status"] != "approved" {
		t.Fatalf("expected report backlog item approval_status=approved after approval, got %v", afterItem)
	}
	if afterItem["security_visibility"] != "known_approved" {
		t.Fatalf("expected report backlog item security_visibility=known_approved after approval, got %v", afterItem)
	}
}

func TestRegressBaselineInitializedAfterApprovalUsesUpdatedSavedState(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	baselinePath := filepath.Join(tmp, "baseline.json")
	agentID := scanIdentityAgentID(t, statePath)

	var approveOut bytes.Buffer
	var approveErr bytes.Buffer
	if code := Run([]string{"identity", "approve", agentID, "--approver", "@maria", "--scope", "read-only", "--expires", "90d", "--state", statePath, "--json"}, &approveOut, &approveErr); code != 0 {
		t.Fatalf("identity approve failed: %d %s", code, approveErr.String())
	}

	var initOut bytes.Buffer
	var initErr bytes.Buffer
	if code := Run([]string{"regress", "init", "--baseline", statePath, "--output", baselinePath, "--json"}, &initOut, &initErr); code != 0 {
		t.Fatalf("regress init failed: %d %s", code, initErr.String())
	}

	baseline, err := regress.LoadBaseline(baselinePath)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	for _, tool := range baseline.Tools {
		if tool.AgentID != agentID {
			continue
		}
		if tool.Status != identity.StateApproved {
			t.Fatalf("expected approved lifecycle state in baseline, got %+v", tool)
		}
		if tool.ApprovalStatus != "valid" {
			t.Fatalf("expected valid approval status in baseline, got %+v", tool)
		}
		return
	}
	t.Fatalf("expected baseline tool for %s", agentID)
}

func TestInventoryExcludeRemovesControlBacklogWithoutRescan(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	agentID := scanIdentityAgentID(t, statePath)

	snapshotBefore, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load state before exclude: %v", err)
	}
	recordBefore, ok := testIdentityRecord(snapshotBefore.Identities, agentID)
	if !ok {
		t.Fatalf("missing identity %s before exclude", agentID)
	}
	before := runReportJSON(t, statePath)
	if _, ok := reportBacklogItem(before, recordBefore.Repo, recordBefore.Location); !ok {
		t.Fatalf("expected report backlog item for %s %s before exclude", recordBefore.Repo, recordBefore.Location)
	}

	var excludeOut bytes.Buffer
	var excludeErr bytes.Buffer
	if code := Run([]string{
		"inventory", "exclude", agentID,
		"--reason", "retired_control_path",
		"--state", statePath,
		"--json",
	}, &excludeOut, &excludeErr); code != 0 {
		t.Fatalf("inventory exclude failed: %d %s", code, excludeErr.String())
	}

	after := runReportJSON(t, statePath)
	if _, ok := reportBacklogItem(after, recordBefore.Repo, recordBefore.Location); ok {
		t.Fatalf("expected excluded control path to be removed from report backlog without rescanning")
	}
}

func runScoreJSON(t *testing.T, statePath string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"score", "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("score failed: %d %s", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse score payload: %v", err)
	}
	return payload
}

func runReportJSON(t *testing.T, statePath string) map[string]any {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"report", "--state", statePath, "--json"}, &out, &errOut); code != 0 {
		t.Fatalf("report failed: %d %s", code, errOut.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	return payload
}

func reportBacklogItem(payload map[string]any, repo string, path string) (map[string]any, bool) {
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		return nil, false
	}
	backlog, ok := summary["control_backlog"].(map[string]any)
	if !ok {
		return nil, false
	}
	items, ok := backlog["items"].([]any)
	if !ok {
		return nil, false
	}
	for _, item := range items {
		typed, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if typed["repo"] == repo && typed["path"] == path {
			return typed, true
		}
	}
	return nil, false
}

func testIdentityRecord(records []manifest.IdentityRecord, agentID string) (manifest.IdentityRecord, bool) {
	for _, record := range records {
		if record.AgentID == agentID {
			return record, true
		}
	}
	return manifest.IdentityRecord{}, false
}
