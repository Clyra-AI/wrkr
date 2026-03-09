package proofemit

import (
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

func TestEmitScanProducesSignedRecords(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "state.json")
	findings := []model.Finding{
		{
			FindingType: "skill_policy_conflict",
			Severity:    model.SeverityHigh,
			ToolType:    "skill",
			Location:    ".claude/skills/deploy/SKILL.md",
			Repo:        "repo",
			Org:         "acme",
		},
	}
	report := risk.Score(findings, 5, now)
	profile := profileeval.Result{ProfileName: "standard", CompliancePercent: 90, Status: "pass"}
	posture := score.Result{Score: 82.5, Grade: "B", Weights: scoremodel.DefaultWeights()}

	summary, err := EmitScan(statePath, now, findings, report, profile, posture, nil)
	if err != nil {
		t.Fatalf("emit scan: %v", err)
	}
	if summary.Total == 0 {
		t.Fatal("expected at least one emitted proof record")
	}
	chain, err := LoadChain(summary.ChainPath)
	if err != nil {
		t.Fatalf("load proof chain: %v", err)
	}
	if len(chain.Records) != summary.Total {
		t.Fatalf("expected %d records, got %d", summary.Total, len(chain.Records))
	}
	if len(chain.Signatures) != 1 {
		t.Fatalf("expected 1 proof chain signature, got %d", len(chain.Signatures))
	}
	if _, err := os.Stat(chainAttestationPath(summary.ChainPath)); err != nil {
		t.Fatalf("expected proof chain attestation file: %v", err)
	}
	publicKey, err := LoadVerifierKey(statePath)
	if err != nil {
		t.Fatalf("load verifier key: %v", err)
	}
	if err := proof.VerifyChainSignature(chain, chain.Signatures[0], publicKey); err != nil {
		t.Fatalf("verify proof chain signature: %v", err)
	}
	for _, record := range chain.Records {
		if record.Integrity.Signature == "" {
			t.Fatalf("expected signed proof record, got empty signature for %s", record.RecordID)
		}
		if record.Integrity.SigningKeyID == "" {
			t.Fatalf("expected signing key id for %s", record.RecordID)
		}
		if record.Relationship == nil {
			t.Fatalf("expected relationship envelope for %s", record.RecordID)
		}
	}
	if len(chain.Records) > 1 {
		second := chain.Records[1]
		if second.Relationship.ParentRef == nil || second.Relationship.ParentRef.Kind != "evidence" {
			t.Fatalf("expected parent_ref evidence on second record relationship, got %#v", second.Relationship.ParentRef)
		}
		if second.Relationship.ParentRecordID == "" {
			t.Fatalf("expected legacy parent_record_id on second record relationship, got %#v", second.Relationship)
		}
		linked := false
		for _, record := range chain.Records[1:] {
			if len(record.Relationship.RelatedRecordIDs) > 0 {
				linked = true
				break
			}
		}
		if !linked {
			t.Fatalf("expected at least one related_record_ids linkage on emitted records, got %#v", chain.Records)
		}
	}
}

func TestEmitIdentityTransitionAddsApprovalRecord(t *testing.T) {
	t.Parallel()
	statePath := filepath.Join(t.TempDir(), "state.json")
	transition := lifecycle.Transition{
		AgentID:       "wrkr:mcp-1:acme",
		PreviousState: "under_review",
		NewState:      "approved",
		Trigger:       "manual_transition",
		Timestamp:     "2026-02-20T13:00:00Z",
		Diff: map[string]any{
			"approver": "@maria",
			"scope":    "read-only",
		},
	}
	if err := EmitIdentityTransition(statePath, transition, "approval"); err != nil {
		t.Fatalf("emit identity transition: %v", err)
	}
	chain, err := LoadChain(ChainPath(statePath))
	if err != nil {
		t.Fatalf("load proof chain: %v", err)
	}
	if len(chain.Records) != 1 {
		t.Fatalf("expected 1 proof record, got %d", len(chain.Records))
	}
	if len(chain.Signatures) != 1 {
		t.Fatalf("expected 1 proof chain signature, got %d", len(chain.Signatures))
	}
	if _, err := os.Stat(chainAttestationPath(statePath)); err != nil {
		t.Fatalf("expected proof chain attestation file: %v", err)
	}
	record := chain.Records[0]
	if record.RecordType != "approval" {
		t.Fatalf("expected approval record type, got %s", record.RecordType)
	}
	if record.Relationship == nil || len(record.Relationship.EntityRefs) == 0 {
		t.Fatalf("expected transition relationship envelope, got %#v", record.Relationship)
	}
}

func TestEmitScanLinksRiskRecordWhenOrgIsEmpty(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	statePath := filepath.Join(t.TempDir(), "state.json")
	findings := []model.Finding{
		{
			FindingType: "skill_policy_conflict",
			Severity:    model.SeverityHigh,
			ToolType:    "skill",
			Location:    ".agents/skills/deploy/SKILL.md",
			Repo:        "repo",
			Org:         "   ",
		},
	}
	report := risk.Score(findings, 5, now)
	profile := profileeval.Result{ProfileName: "standard", CompliancePercent: 90, Status: "pass"}
	posture := score.Result{Score: 82.5, Grade: "B", Weights: scoremodel.DefaultWeights()}

	summary, err := EmitScan(statePath, now, findings, report, profile, posture, nil)
	if err != nil {
		t.Fatalf("emit scan: %v", err)
	}
	chain, err := LoadChain(summary.ChainPath)
	if err != nil {
		t.Fatalf("load proof chain: %v", err)
	}
	linkedRisk := false
	for _, record := range chain.Records {
		if record.RecordType != "risk_assessment" {
			continue
		}
		assessmentType, _ := record.Event["assessment_type"].(string)
		if assessmentType != "finding_risk" {
			continue
		}
		if record.Relationship != nil && len(record.Relationship.RelatedRecordIDs) > 0 {
			linkedRisk = true
			break
		}
	}
	if !linkedRisk {
		t.Fatalf("expected finding_risk record with related_record_ids linkage for empty-org finding; chain=%#v", chain.Records)
	}
}

func TestProofChainSaveIsAtomicUnderInterruption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proof-chain.json")
	chain := proof.NewChain("wrkr-proof")
	if err := SaveChain(path, chain); err != nil {
		t.Fatalf("save initial chain: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read initial chain bytes: %v", err)
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

	updated := proof.NewChain("wrkr-proof-updated")
	if err := SaveChain(path, updated); err == nil {
		t.Fatal("expected proof chain save interruption failure")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read chain after interruption: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("expected proof chain bytes to remain unchanged after interruption\nbefore: %s\nafter: %s", before, after)
	}
	if _, err := LoadChain(path); err != nil {
		t.Fatalf("expected proof chain to remain parseable after interruption: %v", err)
	}
}
