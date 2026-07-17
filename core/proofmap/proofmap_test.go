package proofmap

import (
	"fmt"
	"strings"
	"testing"
	"time"

	proof "github.com/Clyra-AI/proof"
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/model"
	profileeval "github.com/Clyra-AI/wrkr/core/policy/profileeval"
	"github.com/Clyra-AI/wrkr/core/risk"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
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

func TestMapFindingsGroupsPolicyFanoutByOutcome(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 6, 12, 12, 0, 0, 0, time.UTC)
	findings := []model.Finding{
		{
			FindingType:     "policy_check",
			RuleID:          "WRKR-010",
			CheckResult:     model.CheckResultFail,
			PolicyOutcomeID: "policy-same",
			Severity:        model.SeverityHigh,
			ToolType:        "policy",
			Location:        "WRKR-010",
			Repo:            "repo-a",
			Org:             "acme",
		},
		{
			FindingType:     "policy_violation",
			RuleID:          "WRKR-010",
			CheckResult:     model.CheckResultFail,
			PolicyOutcomeID: "policy-same",
			Severity:        model.SeverityHigh,
			ToolType:        "policy",
			Location:        "WRKR-010",
			Repo:            "repo-a",
			Org:             "acme",
		},
		{
			FindingType:     "policy_check",
			RuleID:          "WRKR-010",
			CheckResult:     model.CheckResultFail,
			PolicyOutcomeID: "policy-same",
			Severity:        model.SeverityHigh,
			ToolType:        "policy",
			Location:        "WRKR-010",
			Repo:            "repo-b",
			Org:             "acme",
		},
		{
			FindingType:     "policy_violation",
			RuleID:          "WRKR-010",
			CheckResult:     model.CheckResultFail,
			PolicyOutcomeID: "policy-same",
			Severity:        model.SeverityHigh,
			ToolType:        "policy",
			Location:        "WRKR-010",
			Repo:            "repo-b",
			Org:             "acme",
		},
	}

	records := MapFindings(findings, nil, SecurityVisibilityContext{}, now)
	if len(records) != 1 {
		t.Fatalf("expected one grouped policy proof record, got %d", len(records))
	}
	record := records[0]
	if record.Event["finding_type"] != "policy_violation" {
		t.Fatalf("expected failed grouped policy outcome to prefer violation representative, got %v", record.Event["finding_type"])
	}
	if record.Metadata["canonical_finding_key"] != "policy_outcome:acme:policy-same" {
		t.Fatalf("unexpected canonical finding key: %v", record.Metadata["canonical_finding_key"])
	}
	if record.Metadata["source_findings_count"] != 4 {
		t.Fatalf("expected source count 4, got %v", record.Metadata["source_findings_count"])
	}
	if record.Metadata["policy_outcome_id"] != "policy-same" {
		t.Fatalf("expected policy outcome metadata, got %v", record.Metadata["policy_outcome_id"])
	}
	if record.Metadata["affected_repo_count"] != 2 {
		t.Fatalf("expected affected repo count 2, got %v", record.Metadata["affected_repo_count"])
	}
	sourceKeys, ok := record.Metadata["source_finding_keys"].([]string)
	if !ok || len(sourceKeys) != 4 {
		t.Fatalf("expected four source_finding_keys aliases, got %#v", record.Metadata["source_finding_keys"])
	}
	topRefs, ok := record.Metadata["top_repo_refs"].([]string)
	if !ok || len(topRefs) != 2 || topRefs[0] != "acme/repo-a" || topRefs[1] != "acme/repo-b" {
		t.Fatalf("unexpected top repo refs: %#v", record.Metadata["top_repo_refs"])
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

func TestMapRiskBoundsDetailedProofRecords(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)
	ranked := make([]risk.ScoredFinding, 0, 40)
	for idx := 0; idx < 40; idx++ {
		ranked = append(ranked, risk.ScoredFinding{
			CanonicalKey: fmt.Sprintf("finding-%02d", idx),
			Score:        float64(100 - idx),
			Finding: model.Finding{
				FindingType: "ci_autonomy",
				ToolType:    "ci_agent",
				Location:    fmt.Sprintf(".github/workflows/release-%02d.yml", idx),
				Repo:        "repo",
				Org:         "acme",
			},
		})
	}
	attackPaths := make([]riskattack.ScoredPath, 0, 40)
	for idx := 0; idx < 40; idx++ {
		attackPaths = append(attackPaths, riskattack.ScoredPath{PathID: fmt.Sprintf("attack-%02d", idx)})
	}
	actionPaths := make([]risk.ActionPath, 0, maxActionPathProofRecords+10)
	for idx := 0; idx < maxActionPathProofRecords+10; idx++ {
		actionPaths = append(actionPaths, risk.ActionPath{
			PathID: fmt.Sprintf("action-%02d", idx),
			Repo:   "repo",
			Org:    "acme",
		})
	}
	report := risk.Report{
		TopN:           append([]risk.ScoredFinding(nil), ranked[:3]...),
		Ranked:         ranked,
		TopAttackPaths: append([]riskattack.ScoredPath(nil), attackPaths[:2]...),
		AttackPaths:    attackPaths,
		ActionPaths:    actionPaths,
		ControlPathGraph: &aggattack.ControlPathGraph{
			Version: "1",
			Summary: aggattack.ControlPathGraphSummary{
				TotalNodes: 12,
				TotalEdges: 6,
			},
		},
	}

	records := MapRisk(report, score.Result{}, profileeval.Result{}, SecurityVisibilityContext{}, now)
	counts := mapRiskAssessmentTypes(records)
	if counts["finding_risk"] != 3 {
		t.Fatalf("expected top finding risk records only, got counts %+v", counts)
	}
	if counts["attack_path_risk"] != 2 {
		t.Fatalf("expected top attack path records only, got counts %+v", counts)
	}
	if counts["action_path_governance"] != maxActionPathProofRecords {
		t.Fatalf("expected %d bounded action path governance records, got counts %+v", maxActionPathProofRecords, counts)
	}
	if counts["control_path_graph"] != 1 || counts["posture_score"] != 1 {
		t.Fatalf("expected graph and posture summary proof records, got counts %+v", counts)
	}

	foundLastIncluded := false
	foundFirstExcluded := false
	for _, record := range records {
		if record.Event["assessment_type"] != "action_path_governance" {
			continue
		}
		switch record.Event["path_id"] {
		case fmt.Sprintf("action-%02d", maxActionPathProofRecords-1):
			foundLastIncluded = true
		case fmt.Sprintf("action-%02d", maxActionPathProofRecords):
			foundFirstExcluded = true
		}
	}
	if !foundLastIncluded || foundFirstExcluded {
		t.Fatalf("expected deterministic action path cap boundary, found_last=%v found_excluded=%v", foundLastIncluded, foundFirstExcluded)
	}
}

func TestMapDecisionTracesEmitsBoundedHighImpactRecords(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	paths := make([]risk.ActionPath, 0, maxDecisionTraceRecords+5)
	for idx := 0; idx < maxDecisionTraceRecords+5; idx++ {
		paths = append(paths, risk.ProjectActionPath(risk.ActionPath{
			PathID:           fmt.Sprintf("apc-trace-%02d", idx),
			AgentID:          "wrkr:codex:acme",
			Org:              "acme",
			Repo:             "acme/release",
			ToolType:         "skill",
			Location:         ".agents/skills/release/SKILL.md",
			WriteCapable:     true,
			DeployWrite:      true,
			CredentialAccess: true,
			HighStakesPresets: []risk.HighStakesPreset{{
				Preset: risk.HighStakesPresetReleaseAutomation,
			}},
		}))
	}
	// Add one low-signal path that should not emit a trace.
	paths = append(paths, risk.ProjectActionPath(risk.ActionPath{
		PathID:   "apc-low-signal",
		Org:      "acme",
		Repo:     "acme/release",
		ToolType: "prompt_channel",
		Location: "AGENTS.md",
	}))

	records := MapDecisionTraces(paths, now)
	if len(records) != maxDecisionTraceRecords {
		t.Fatalf("expected bounded decision traces, got %d", len(records))
	}
	if records[0].RecordType != "decision_trace" {
		t.Fatalf("expected decision_trace record type, got %+v", records[0])
	}
	if records[0].Event["event_type"] != "decision_trace" {
		t.Fatalf("expected decision_trace event type, got %+v", records[0].Event)
	}
	if _, ok := records[0].Event["what_changed"].(map[string]any); !ok {
		t.Fatalf("expected bounded what_changed payload, got %+v", records[0].Event)
	}
	for _, record := range records {
		if record.Metadata["path_id"] == "apc-low-signal" {
			t.Fatalf("did not expect low-signal path to emit decision trace, got %+v", record)
		}
	}
}

func TestDecisionTraceCarriesCompositionAndProposedContractRefs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 13, 14, 36, 19, 0, time.UTC)
	path := risk.ProjectActionPath(risk.ActionPath{
		PathID:                     "apc-release",
		ResolutionKey:              "rk-release-prod",
		AgentID:                    "wrkr:codex:acme",
		Org:                        "acme",
		Repo:                       "acme/release",
		ToolType:                   "compiled_action",
		Location:                   ".github/workflows/release.yml",
		WriteCapable:               true,
		DeployWrite:                true,
		CredentialAccess:           true,
		WorkflowChainRefs:          []string{"workflow_chain:wfc-release"},
		CompositionIDs:             []string{"cap-release-prod"},
		ProposedActionContractRefs: []string{"pac-release-prod"},
		AutonomyTier:               risk.AutonomyTier4ProdPrivilegedCustomerImpact,
		RecommendedControl:         risk.RecommendedControlBlockStandingCredential,
		ApprovalEvidenceState:      risk.EvidenceStateUnknown,
		OwnerEvidenceState:         risk.EvidenceStateVerified,
		ProofEvidenceState:         risk.EvidenceStateInferred,
		RuntimeEvidenceState:       risk.EvidenceStateUnknown,
		TargetEvidenceState:        risk.EvidenceStateVerified,
		CredentialEvidenceState:    risk.EvidenceStateVerified,
	})

	records := MapDecisionTraces([]risk.ActionPath{path}, now)
	if len(records) != 1 {
		t.Fatalf("expected one decision trace, got %+v", records)
	}
	event := records[0].Event
	for key, want := range map[string]string{
		"resolution_key":      "rk-release-prod",
		"autonomy_tier":       risk.AutonomyTier4ProdPrivilegedCustomerImpact,
		"recommended_control": risk.RecommendedControlApprovalRequired,
	} {
		if got, _ := event[key].(string); got != want {
			t.Fatalf("expected event.%s=%q, got %q in %+v", key, want, got, event)
		}
	}
	for key, want := range map[string]string{
		"composition_ids":               "cap-release-prod",
		"proposed_action_contract_refs": "pac-release-prod",
		"workflow_chain_refs":           "workflow_chain:wfc-release",
	} {
		values, _ := event[key].([]string)
		if len(values) != 1 || values[0] != want {
			t.Fatalf("expected event.%s to carry %q, got %#v", key, want, event[key])
		}
		metadataValues, _ := records[0].Metadata[key].([]string)
		if len(metadataValues) != 1 || metadataValues[0] != want {
			t.Fatalf("expected metadata.%s to carry %q, got %#v", key, want, records[0].Metadata[key])
		}
	}
	states, _ := event["evidence_states"].(map[string]string)
	if states["approval"] != risk.EvidenceStateUnknown || states["credential"] != risk.EvidenceStateVerified {
		t.Fatalf("expected decision trace evidence states, got %#v", event["evidence_states"])
	}
	if !relationshipHasRef(records[0].Relationship, "resource", "composition:cap-release-prod") {
		t.Fatalf("expected relationship composition ref, got %+v", records[0].Relationship)
	}
	if !relationshipHasRef(records[0].Relationship, "evidence", "proposed_action_contract:pac-release-prod") {
		t.Fatalf("expected relationship proposed contract ref, got %+v", records[0].Relationship)
	}
}

func TestDecisionTraceOmitsEmptyCompositionAndWorkflowRefs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 17, 17, 30, 37, 0, time.UTC)
	path := risk.ProjectActionPath(risk.ActionPath{
		PathID:                "apc-standalone",
		ResolutionKey:         "rk-standalone",
		AgentID:               "wrkr:codex:acme",
		Org:                   "acme",
		Repo:                  "acme/release",
		ToolType:              "compiled_action",
		Location:              ".github/workflows/release.yml",
		WriteCapable:          true,
		DeployWrite:           true,
		CredentialAccess:      true,
		AutonomyTier:          risk.AutonomyTier4ProdPrivilegedCustomerImpact,
		RecommendedControl:    risk.RecommendedControlBlockStandingCredential,
		ApprovalEvidenceState: risk.EvidenceStateUnknown,
		OwnerEvidenceState:    risk.EvidenceStateVerified,
		ProofEvidenceState:    risk.EvidenceStateInferred,
	})

	records := MapDecisionTraces([]risk.ActionPath{path}, now)
	if len(records) != 1 {
		t.Fatalf("expected one decision trace, got %+v", records)
	}
	for _, key := range []string{"workflow_chain_refs", "composition_ids", "proposed_action_contract_refs"} {
		if _, ok := records[0].Event[key]; ok {
			t.Fatalf("expected event.%s to be omitted when empty, got %+v", key, records[0].Event[key])
		}
		if _, ok := records[0].Metadata[key]; ok {
			t.Fatalf("expected metadata.%s to be omitted when empty, got %+v", key, records[0].Metadata[key])
		}
	}
	whatChanged, _ := records[0].Event["what_changed"].(map[string]any)
	if _, ok := whatChanged["workflow_chains"]; ok {
		t.Fatalf("expected what_changed.workflow_chains to be omitted when empty, got %+v", whatChanged["workflow_chains"])
	}
}

func relationshipHasRef(rel *proof.Relationship, kind, id string) bool {
	if rel == nil {
		return false
	}
	for _, ref := range rel.EntityRefs {
		if ref.Kind == kind && ref.ID == id {
			return true
		}
	}
	return false
}

func mapRiskAssessmentTypes(records []MappedRecord) map[string]int {
	out := map[string]int{}
	for _, record := range records {
		assessmentType, _ := record.Event["assessment_type"].(string)
		out[assessmentType]++
	}
	return out
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

func TestMapTransitionLifecycleTransitionRecordType(t *testing.T) {
	t.Parallel()
	transition := lifecycle.Transition{
		AgentID:       "wrkr:mcp-1:acme",
		PreviousState: "discovered",
		NewState:      "under_review",
		Trigger:       "state_changed",
		Timestamp:     "2026-02-20T13:00:00Z",
		Diff: map[string]any{
			"reason": "expired approval",
		},
	}

	record := MapTransition(transition, "lifecycle_transition")
	if record.RecordType != "lifecycle_transition" {
		t.Fatalf("expected lifecycle_transition record type, got %s", record.RecordType)
	}
	if got := record.Event["event_type"]; got != "lifecycle_transition" {
		t.Fatalf("expected event_type lifecycle_transition, got %v", got)
	}

	defaulted := MapTransition(transition, "")
	if defaulted.RecordType != "lifecycle_transition" {
		t.Fatalf("expected blank event type to default to lifecycle_transition, got %s", defaulted.RecordType)
	}
	if got := defaulted.Event["event_type"]; got != "lifecycle_transition" {
		t.Fatalf("expected blank event_type to default to lifecycle_transition, got %v", got)
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
