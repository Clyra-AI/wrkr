package proofmap

import (
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/score"
	scoremodel "github.com/Clyra-AI/wrkr/core/score/model"
)

func TestMapFindingsDeduplicatesWRKR014Conflict(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	findings := []model.Finding{
		{
			FindingType: "policy_violation",
			RuleID:      "WRKR-014",
			Severity:    model.SeverityHigh,
			ToolType:    "policy",
			Location:    "WRKR-014",
			Repo:        "repo",
			Org:         "acme",
		},
		{
			FindingType: "skill_policy_conflict",
			Severity:    model.SeverityHigh,
			ToolType:    "skill",
			Location:    ".claude/skills/deploy/SKILL.md",
			Repo:        "repo",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "conflict_level", Value: "high"},
			},
		},
	}
	profile := &profileeval.Result{ProfileName: "standard", CompliancePercent: 92.5, Status: "pass"}
	records := MapFindings(findings, profile, now)
	if len(records) != 1 {
		t.Fatalf("expected one canonical scan_finding record, got %d", len(records))
	}
	record := records[0]
	if record.RecordType != "scan_finding" {
		t.Fatalf("expected record_type scan_finding, got %s", record.RecordType)
	}
	if record.Event["finding_type"] != "skill_policy_conflict" {
		t.Fatalf("expected representative finding_type skill_policy_conflict, got %v", record.Event["finding_type"])
	}
	metadata, ok := record.Metadata["linked_rule_ids"].([]string)
	if !ok {
		t.Fatalf("expected linked_rule_ids metadata, got %T", record.Metadata["linked_rule_ids"])
	}
	if len(metadata) != 1 || metadata[0] != "WRKR-014" {
		t.Fatalf("unexpected linked_rule_ids metadata: %v", metadata)
	}
	if linked, ok := record.Metadata["wrkr014_linked"].(bool); !ok || !linked {
		t.Fatalf("expected wrkr014_linked=true metadata, got %v", record.Metadata["wrkr014_linked"])
	}
}

func TestMapRiskIncludesPostureAssessment(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	report := risk.Report{
		Ranked: []risk.ScoredFinding{
			{
				CanonicalKey:  "k1",
				Score:         9.1,
				BlastRadius:   3.4,
				Privilege:     3.1,
				TrustDeficit:  2.6,
				EndpointClass: "ci_pipeline",
				DataClass:     "credentials",
				AutonomyLevel: "headless_auto",
				Reasons:       []string{"r1"},
				Finding: model.Finding{
					FindingType: "ci_autonomy",
					ToolType:    "ci_agent",
					Location:    ".github/workflows/agent.yml",
					Repo:        "infra",
					Org:         "acme",
				},
			},
		},
	}
	posture := score.Result{
		Score: 84.2,
		Grade: "B",
		Breakdown: score.Breakdown{
			PolicyPassRate: 91,
		},
		WeightedBreakdown: score.WeightedBreakdown{
			PolicyPassRate: 22.75,
		},
		Weights: scoremodel.DefaultWeights(),
	}
	profile := profileeval.Result{ProfileName: "standard", CompliancePercent: 88.1, Status: "pass"}

	records := MapRisk(report, posture, profile, now)
	if len(records) != 2 {
		t.Fatalf("expected 2 risk_assessment records, got %d", len(records))
	}
	if records[0].RecordType != "risk_assessment" {
		t.Fatalf("unexpected record type %s", records[0].RecordType)
	}
	if records[1].Event["assessment_type"] != "posture_score" {
		t.Fatalf("expected posture_score event in last record, got %v", records[1].Event["assessment_type"])
	}
	if records[1].Event["grade"] != "B" {
		t.Fatalf("expected posture grade B, got %v", records[1].Event["grade"])
	}
}

func TestMapTransitionApprovalIncludesScope(t *testing.T) {
	t.Parallel()
	transition := lifecycle.Transition{
		AgentID:       "wrkr:mcp-1:acme",
		PreviousState: "under_review",
		NewState:      "approved",
		Trigger:       "manual_transition",
		Timestamp:     "2026-02-20T13:00:00Z",
		Diff: map[string]any{
			"approver": "@maria",
			"scope":    "read-only",
			"expires":  "2026-05-21T13:00:00Z",
		},
	}
	record := MapTransition(transition, "approval")
	if record.RecordType != "approval" {
		t.Fatalf("expected approval record type, got %s", record.RecordType)
	}
	if record.ApprovedScope != "read-only" {
		t.Fatalf("expected approved scope read-only, got %q", record.ApprovedScope)
	}
	if got := record.Event["event_type"]; got != "approval" {
		t.Fatalf("expected event_type approval, got %v", got)
	}
}
