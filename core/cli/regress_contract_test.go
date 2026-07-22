package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/identity"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/regress"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestRegressRunJSONCarriesAgentInstanceIDInReasons(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	baselinePath := filepath.Join(tmp, "baseline.json")
	if err := os.WriteFile(baselinePath, []byte("{\"version\":\"v1\",\"tools\":[]}\n"), 0o600); err != nil {
		t.Fatalf("write baseline: %v", err)
	}

	instanceID := identity.AgentInstanceID("agentframework", ".wrkr/agents/research.yaml", "ops_agent", 30, 42)
	if err := state.Save(statePath, state.Snapshot{
		Version: state.SnapshotVersion,
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
			AgentID:       identity.AgentID(instanceID, "acme"),
			ToolID:        instanceID,
			Org:           "acme",
			Status:        identity.StateUnderReview,
			ApprovalState: "missing",
			Present:       true,
		}},
	}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"regress", "run", "--baseline", baselinePath, "--state", statePath, "--json"}, &out, &errOut)
	if code != 5 {
		t.Fatalf("expected drift exit 5, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse regress run payload: %v", err)
	}
	reasons, ok := payload["reasons"].([]any)
	if !ok || len(reasons) != 1 {
		t.Fatalf("expected one regress reason, got %v", payload["reasons"])
	}
	reason, ok := reasons[0].(map[string]any)
	if !ok {
		t.Fatalf("expected regress reason object, got %T", reasons[0])
	}
	if reason["agent_instance_id"] != instanceID {
		t.Fatalf("expected additive agent_instance_id=%q, got %v", instanceID, reason["agent_instance_id"])
	}
}

func TestRegressInitProjectsActionContractLifecycleSidecar(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	baselinePath := filepath.Join(tmp, "baseline.json")
	contract := saveRegressLifecycleState(t, statePath)
	saveRegressLifecycleSidecar(t, statePath, contract, risk.LifecycleObservationActivationReceipt)

	var out bytes.Buffer
	var errOut bytes.Buffer
	if code := Run([]string{"regress", "init", "--baseline", statePath, "--output", baselinePath, "--json"}, &out, &errOut); code != exitSuccess {
		t.Fatalf("regress init failed: %d %s", code, errOut.String())
	}

	baseline, err := regress.LoadBaseline(baselinePath)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	if len(baseline.Compositions) != 1 || len(baseline.Compositions[0].ContractActivation) != 1 {
		t.Fatalf("expected lifecycle sidecar activation in regress baseline, got %+v", baseline.Compositions)
	}
}

func TestRegressRunProjectsActionContractLifecycleSidecarsForRawSnapshots(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	baselineStatePath := filepath.Join(tmp, "baseline", "state.json")
	currentStatePath := filepath.Join(tmp, "current", "state.json")
	baselineContract := saveRegressLifecycleState(t, baselineStatePath)
	currentContract := saveRegressLifecycleState(t, currentStatePath)
	saveRegressLifecycleSidecar(t, baselineStatePath, baselineContract, risk.LifecycleObservationActivationReceipt)
	saveRegressLifecycleSidecar(t, currentStatePath, currentContract, risk.LifecycleObservationActivationReceipt, risk.LifecycleObservationExecution)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"regress", "run", "--baseline", baselineStatePath, "--state", currentStatePath, "--json"}, &out, &errOut)
	if code != exitRegressionDrift {
		t.Fatalf("expected execution-effect drift exit, got %d stderr=%s stdout=%s", code, errOut.String(), out.String())
	}

	var result regress.Result
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("parse regress result: %v", err)
	}
	if !regressResultHasCategory(result, regress.DriftCategoryActionContractExecutionEffectChanged) {
		t.Fatalf("expected current sidecar execution drift, got %+v", result.DriftCategories)
	}
	if regressResultHasCategory(result, regress.DriftCategoryActionContractActivationChanged) {
		t.Fatalf("baseline sidecar activation should suppress false activation drift, got %+v", result.DriftCategories)
	}
}

func saveRegressLifecycleState(t *testing.T, statePath string) *risk.ProposedActionContract {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatalf("create state dir: %v", err)
	}
	composition := risk.ComposedActionPath{
		CompositionID:        "cap-regress-lifecycle",
		PatternID:            risk.CompositionPatternCodeToDeploy,
		PathIDs:              []string{"apc-regress-lifecycle"},
		TargetIdentity:       "prod",
		OutcomeKey:           "asset=prod|target_class=production_impacting|outcome=production_deploy|environment=production",
		OutcomeClass:         "production_deploy",
		Environment:          "production",
		RecommendedControl:   risk.RecommendedControlApprovalRequired,
		EvidenceState:        risk.EvidenceStateDeclared,
		FreshnessState:       "fresh",
		PolicyCoverageStatus: risk.PolicyCoverageStatusMatched,
		Stages: []risk.CompositionStage{
			{StageID: "source", Role: risk.CompositionStageRoleSource, ResolutionKey: "rk-source", ToolType: "ci_agent", Location: ".github/workflows/release.yml"},
			{StageID: "sink", Role: risk.CompositionStageRoleExternalSink, ResolutionKey: "rk-sink", ToolType: "ci_agent", Location: ".github/workflows/release.yml"},
		},
	}
	composition.ProposedActionContract = risk.BuildProposedActionContract(composition)
	composition.ProposedActionContractRefs = []string{composition.ProposedActionContract.ContractID}
	snapshot := state.Snapshot{
		Version: state.SnapshotVersion,
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{PathID: "apc-regress-lifecycle", AgentID: "wrkr:workflow-release:acme", Repo: "acme/release", Location: ".github/workflows/release.yml"}},
			ComposedActionPaths: []risk.ComposedActionPath{
				composition,
			},
		},
	}
	if err := state.Save(statePath, snapshot); err != nil {
		t.Fatalf("save state: %v", err)
	}
	return composition.ProposedActionContract
}

func saveRegressLifecycleSidecar(t *testing.T, statePath string, contract *risk.ProposedActionContract, events ...string) {
	t.Helper()
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	records := make([]ingest.Record, 0, len(events))
	for idx, event := range events {
		evidenceClass := ingest.EvidenceClassApproval
		if event == risk.LifecycleObservationExecution || event == risk.LifecycleObservationEffect {
			evidenceClass = ingest.EvidenceClassActionOutcome
		}
		records = append(records, ingest.Record{
			RecordKind: ingest.RecordKindExternalControl, SourceType: "signed_declaration", Source: "gait-export", ObservedAt: now.Add(time.Duration(idx) * time.Minute).Format(time.RFC3339), EvidenceClass: evidenceClass,
			ProposedActionContractRef: contract.ContractID, ContractFamilyID: contract.ContractFamilyID, ContractRevision: contract.Revision, ActionContractArtifactRef: "paca-" + event, ActionContractEvent: event, Producer: "gait", EvidenceState: risk.EvidenceStateVerified,
		})
	}
	if err := ingest.Save(ingest.DefaultPath(statePath), ingest.Bundle{GeneratedAt: now.Format(time.RFC3339), Records: records}); err != nil {
		t.Fatalf("save runtime sidecar: %v", err)
	}
}

func regressResultHasCategory(result regress.Result, want string) bool {
	for _, category := range result.DriftCategories {
		if category.Category == want {
			return true
		}
	}
	return false
}
