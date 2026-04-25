package proofmap

import (
	"fmt"
	"strings"
	"testing"
	"time"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
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
	records := MapFindings(findings, profile, SecurityVisibilityContext{}, now)
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
	if record.Relationship == nil {
		t.Fatal("expected relationship envelope on scan_finding proof map record")
	}
	if record.Relationship.PolicyRef == nil || len(record.Relationship.PolicyRef.MatchedRuleIDs) != 1 || record.Relationship.PolicyRef.MatchedRuleIDs[0] != "WRKR-014" {
		t.Fatalf("expected relationship policy_ref matched_rule_ids, got %#v", record.Relationship.PolicyRef)
	}
}

func TestMapFindingsRedactsMaterializedSourcePaths(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 24, 12, 0, 0, 0, time.UTC)
	materializedPath := "/tmp/work/.wrkr/materialized-sources/acme/backend/.codex/config.toml"
	findings := []model.Finding{
		{
			FindingType: "tool_config",
			Severity:    model.SeverityLow,
			ToolType:    "codex",
			Location:    materializedPath,
			Repo:        "backend",
			Org:         "acme",
			ParseError: &model.ParseError{
				Kind:     "invalid_config",
				Path:     materializedPath,
				Message:  "parse failed at " + materializedPath,
				Detector: "codex",
			},
			Evidence: []model.Evidence{{Key: "path", Value: materializedPath}},
		},
	}

	records := MapFindings(findings, nil, SecurityVisibilityContext{}, now)
	if len(records) != 1 {
		t.Fatalf("expected one proof map record, got %d", len(records))
	}
	if strings.Contains(fmt.Sprintf("%#v", records[0].Event), "materialized-sources") {
		t.Fatalf("expected event to redact materialized path, got %#v", records[0].Event)
	}
	if strings.Contains(fmt.Sprintf("%#v", records[0].Metadata), "materialized-sources") {
		t.Fatalf("expected metadata to redact materialized path, got %#v", records[0].Metadata)
	}
	if records[0].Relationship != nil && strings.Contains(fmt.Sprintf("%#v", records[0].Relationship.EntityRefs), "materialized-sources") {
		t.Fatalf("expected relationship refs to redact materialized path, got %#v", records[0].Relationship.EntityRefs)
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

	records := MapRisk(report, posture, profile, SecurityVisibilityContext{}, now)
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
	if records[0].Relationship == nil {
		t.Fatal("expected relationship envelope for finding risk record")
	}
	if len(records[0].Relationship.EntityRefs) == 0 {
		t.Fatalf("expected relationship entity refs on first risk record, got %#v", records[0].Relationship)
	}
	if records[1].Relationship == nil || len(records[1].Relationship.RelatedEntityIDs) == 0 {
		t.Fatalf("expected relationship metadata on posture record, got %#v", records[1].Relationship)
	}
}

func TestMapRiskIncludesActionPathGovernanceControls(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	report := risk.Report{
		ActionPaths: []risk.ActionPath{{
			PathID:                   "apc-test",
			AgentID:                  "wrkr:ci:acme",
			Org:                      "acme",
			Repo:                     "acme/app",
			ToolType:                 "ci_agent",
			Location:                 ".github/workflows/pr.yml",
			WriteCapable:             true,
			WritePathClasses:         []string{agginventory.WritePathPullRequestWrite, agginventory.WritePathSecretBearingExec},
			RecommendedAction:        "proof",
			SecurityVisibilityStatus: agginventory.SecurityVisibilityUnknownToSecurity,
			GovernanceControls: []agginventory.GovernanceControlMapping{{
				Control: agginventory.GovernanceControlApproval,
				Status:  agginventory.ControlStatusGap,
			}},
		}},
		ControlPathGraph: &aggattack.ControlPathGraph{
			Version: "1",
			Summary: aggattack.ControlPathGraphSummary{TotalNodes: 2, TotalEdges: 1},
		},
	}
	records := MapRisk(report, score.Result{}, profileeval.Result{}, SecurityVisibilityContext{}, now)
	if len(records) != 3 {
		t.Fatalf("expected action path governance, graph, plus posture records, got %d", len(records))
	}
	if records[0].Event["assessment_type"] != "action_path_governance" {
		t.Fatalf("expected action path governance event, got %+v", records[0].Event)
	}
	classes, ok := records[0].Event["write_path_classes"].([]string)
	if !ok || len(classes) != 2 {
		t.Fatalf("expected write_path_classes in proof event, got %+v", records[0].Event["write_path_classes"])
	}
	controls, ok := records[0].Event["governance_controls"].([]agginventory.GovernanceControlMapping)
	if !ok || len(controls) != 1 || controls[0].Control != agginventory.GovernanceControlApproval {
		t.Fatalf("expected governance controls in proof event, got %+v", records[0].Event["governance_controls"])
	}
	if records[1].Event["assessment_type"] != "control_path_graph" {
		t.Fatalf("expected control_path_graph event, got %+v", records[1].Event)
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
	if record.Relationship == nil {
		t.Fatal("expected relationship envelope on transition record")
	}
	if len(record.Relationship.EntityRefs) == 0 {
		t.Fatalf("expected transition relationship entity refs, got %#v", record.Relationship)
	}
}

func TestProofMap_ScanFindingIncludesAgentContextAdditively(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	findings := []model.Finding{
		{
			FindingType: "agent_framework",
			Severity:    model.SeverityHigh,
			ToolType:    "langchain",
			Location:    "agents/release.py",
			Repo:        "repo",
			Org:         "acme",
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "release_agent"},
				{Key: "bound_tools", Value: "deploy.write,search.read"},
				{Key: "data_sources", Value: "warehouse.events"},
				{Key: "auth_surfaces", Value: "token"},
				{Key: "deployment_artifacts", Value: ".github/workflows/release.yml"},
				{Key: "deployment_status", Value: "deployed"},
				{Key: "approval_status", Value: "missing"},
			},
		},
	}

	records := MapFindings(findings, nil, SecurityVisibilityContext{}, now)
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	if records[0].Event["agent_id"] == "" {
		t.Fatalf("expected additive event.agent_id, got %v", records[0].Event)
	}
	context, ok := records[0].Event["agent_context"].(map[string]any)
	if !ok {
		t.Fatalf("expected event.agent_context map, got %T", records[0].Event["agent_context"])
	}
	for _, key := range []string{"agent_instance_id", "bound_tools", "deployment_artifacts", "framework", "name"} {
		if _, ok := context[key]; !ok {
			t.Fatalf("expected agent_context key %s, got %v", key, context)
		}
	}
	if records[0].Metadata["agent_instance_id"] == "" {
		t.Fatalf("expected additive metadata.agent_instance_id, got %v", records[0].Metadata)
	}
}

func TestMapFindingsKeepsSameFileAgentsDistinctByInstanceIdentity(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	findings := []model.Finding{
		{
			FindingType:   "agent_framework",
			Severity:      model.SeverityHigh,
			ToolType:      "crewai",
			Location:      "agents/crew.py",
			LocationRange: &model.LocationRange{StartLine: 4, EndLine: 9},
			Repo:          "repo",
			Org:           "acme",
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "research_agent"},
				{Key: "bound_tools", Value: "search.read"},
			},
		},
		{
			FindingType:   "agent_framework",
			Severity:      model.SeverityHigh,
			ToolType:      "crewai",
			Location:      "agents/crew.py",
			LocationRange: &model.LocationRange{StartLine: 11, EndLine: 16},
			Repo:          "repo",
			Org:           "acme",
			Evidence: []model.Evidence{
				{Key: "symbol", Value: "publisher_agent"},
				{Key: "bound_tools", Value: "deploy.write"},
			},
		},
	}

	records := MapFindings(findings, nil, SecurityVisibilityContext{}, now)
	if len(records) != 2 {
		t.Fatalf("expected two scan_finding records, got %d", len(records))
	}
	if records[0].AgentID == records[1].AgentID {
		t.Fatalf("expected distinct proof agent ids for same-file agents, got %+v", records)
	}
	if records[0].Metadata["agent_instance_id"] == records[1].Metadata["agent_instance_id"] {
		t.Fatalf("expected distinct proof instance ids, got %+v", records)
	}
}

func TestMapFindingsIncludesSecurityVisibilityContextWhenProvided(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	findings := []model.Finding{{
		FindingType:   "agent_framework",
		Severity:      model.SeverityHigh,
		ToolType:      "langchain",
		Location:      "agents/release.py",
		LocationRange: &model.LocationRange{StartLine: 10, EndLine: 18},
		Repo:          "repo",
		Org:           "acme",
		Evidence: []model.Evidence{
			{Key: "symbol", Value: "release_agent"},
		},
	}}
	instanceID := agentInstanceIDForFinding(findings[0])

	records := MapFindings(findings, nil, SecurityVisibilityContext{
		Summary: agginventory.SecurityVisibilitySummary{
			ReferenceBasis: "state_snapshot",
		},
		StatusByInstance: map[string]string{
			instanceID: agginventory.SecurityVisibilityUnknownToSecurity,
		},
	}, now)
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	if records[0].Metadata["security_visibility_status"] != agginventory.SecurityVisibilityUnknownToSecurity {
		t.Fatalf("expected security visibility metadata, got %+v", records[0].Metadata)
	}
}

func TestMapFindingsSuppressesSecurityVisibilityContextWithoutReferenceBasis(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 2, 20, 12, 0, 0, 0, time.UTC)
	findings := []model.Finding{{
		FindingType:   "agent_framework",
		Severity:      model.SeverityHigh,
		ToolType:      "langchain",
		Location:      "agents/release.py",
		LocationRange: &model.LocationRange{StartLine: 10, EndLine: 18},
		Repo:          "repo",
		Org:           "acme",
		Evidence: []model.Evidence{
			{Key: "symbol", Value: "release_agent"},
		},
	}}
	instanceID := agentInstanceIDForFinding(findings[0])

	records := MapFindings(findings, nil, SecurityVisibilityContext{
		Summary: agginventory.SecurityVisibilitySummary{},
		StatusByInstance: map[string]string{
			instanceID: agginventory.SecurityVisibilityUnknownToSecurity,
		},
	}, now)
	if len(records) != 1 {
		t.Fatalf("expected one record, got %d", len(records))
	}
	if _, exists := records[0].Metadata["security_visibility_status"]; exists {
		t.Fatalf("expected security visibility metadata to be suppressed without a reference basis, got %+v", records[0].Metadata)
	}
	context, ok := records[0].Event["agent_context"].(map[string]any)
	if !ok {
		t.Fatalf("expected event.agent_context map, got %T", records[0].Event["agent_context"])
	}
	if _, exists := context["security_visibility_status"]; exists {
		t.Fatalf("expected agent_context security visibility to be suppressed without a reference basis, got %+v", context)
	}
}
