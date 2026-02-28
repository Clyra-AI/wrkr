package proofemit

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
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
	record := chain.Records[0]
	if record.RecordType != "approval" {
		t.Fatalf("expected approval record type, got %s", record.RecordType)
	}
	if record.Relationship == nil || len(record.Relationship.EntityRefs) == 0 {
		t.Fatalf("expected transition relationship envelope, got %#v", record.Relationship)
	}
}
