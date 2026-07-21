//go:build scenario

package scenarios

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	"github.com/Clyra-AI/wrkr/core/risk"
)

type multiStageCompositionScenarioFixture struct {
	Cases []multiStageCompositionScenarioCase `json:"cases"`
}

type multiStageCompositionScenarioCase struct {
	ScenarioID                string   `json:"scenario_id"`
	Systems                   []string `json:"systems"`
	Correlated                bool     `json:"correlated"`
	Observed                  bool     `json:"observed"`
	CrossRepo                 bool     `json:"cross_repo"`
	ExpectedStageCount        int      `json:"expected_stage_count"`
	ExpectedReachabilityState string   `json:"expected_reachability_state"`
}

func TestScenarioBoundedMultiStageCompositions(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)
	fixturePath := filepath.Join(repoRoot, "scenarios", "wrkr", "composed-action-paths", "expected", "multi-stage-composition-fixtures.json")
	payload, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read multi-stage fixture: %v", err)
	}
	var fixture multiStageCompositionScenarioFixture
	if err := json.Unmarshal(payload, &fixture); err != nil {
		t.Fatalf("parse multi-stage fixture: %v", err)
	}
	if len(fixture.Cases) != 5 {
		t.Fatalf("expected five bounded multi-stage cases, got %d", len(fixture.Cases))
	}

	for _, scenario := range fixture.Cases {
		scenario := scenario
		t.Run(scenario.ScenarioID, func(t *testing.T) {
			paths := make([]risk.ActionPath, 0, len(scenario.Systems))
			for index, systemClass := range scenario.Systems {
				paths = append(paths, multiStageScenarioPath(index, len(scenario.Systems), systemClass, scenario.CrossRepo, scenario.Observed))
			}
			var chains *agentresolver.WorkflowChainArtifact
			if scenario.Correlated {
				pathIDs := make([]string, 0, len(paths))
				for _, path := range paths {
					pathIDs = append(pathIDs, path.PathID)
				}
				chains = &agentresolver.WorkflowChainArtifact{Chains: []agentresolver.WorkflowChain{{ChainID: "wfc-" + scenario.ScenarioID, PathIDs: pathIDs}}}
			}

			compositions, _ := risk.BuildComposedActionPaths(paths, chains)
			matched := findMultiStageScenarioComposition(compositions, scenario.ExpectedStageCount)
			if scenario.ExpectedStageCount == 0 {
				if matched != nil {
					t.Fatalf("uncorrelated cross-repo fixture must not guess a join: %+v", matched)
				}
				return
			}
			if matched == nil {
				t.Fatalf("expected %d-stage composition, got %+v", scenario.ExpectedStageCount, compositions)
			}
			if matched.ReachabilityState != scenario.ExpectedReachabilityState || matched.ObservedExecution != scenario.Observed {
				t.Fatalf("unexpected possible-versus-observed state: %+v", matched)
			}
			if matched.ProposedActionContract == nil || matched.ProposedActionContract.ContractVersion != risk.ProposedActionContractVersionV3 {
				t.Fatalf("expected version 3 proposed Action Contract: %+v", matched.ProposedActionContract)
			}
			for index, stage := range matched.Stages {
				if stage.SystemClass != scenario.Systems[index] || stage.TrustBoundary == "" || len(stage.CorrelationRefs) == 0 {
					t.Fatalf("stage %d lost ordered system/trust/correlation semantics: %+v", index, stage)
				}
			}
		})
	}
}

func multiStageScenarioPath(index, total int, systemClass string, crossRepo, observed bool) risk.ActionPath {
	actions := []string{"write", "transform"}
	targetClass := risk.TargetClassReleaseAdjacent
	if index == 0 {
		actions = []string{"read_sensitive"}
		targetClass = risk.TargetClassCustomerDataAdjacent
	} else if index == total-1 {
		actions = []string{"external_write", "egress"}
		targetClass = risk.TargetClassProductionImpacting
	}
	path := risk.ActionPath{
		PathID:               fmt.Sprintf("apc-stage-%02d", index),
		Org:                  "fixture-org",
		Repo:                 "fixture-repo",
		ResolutionKey:        fmt.Sprintf("rk-stage-%02d", index),
		ActionClasses:        actions,
		TargetClass:          targetClass,
		WriteCapable:         index > 0,
		ActionBindingState:   risk.ActionBindingStateBound,
		ActionPathEligible:   true,
		PolicyCoverageStatus: risk.PolicyCoverageStatusDeclared,
		TargetEvidenceState:  risk.EvidenceStateDeclared,
		RuntimeEvidenceState: risk.EvidenceStateUnknown,
		GaitCoverage:         &risk.GaitCoverage{ActionOutcome: risk.GaitCoverageDetail{Status: risk.GaitStatusMissing}},
	}
	if crossRepo {
		path.Repo = fmt.Sprintf("fixture-repo-%02d", index)
	}
	switch systemClass {
	case risk.CompositionSystemClassRepo:
		path.ToolType = "codex"
		path.Location = ".codex/config.toml"
	case risk.CompositionSystemClassCI:
		path.ToolType = "github_actions"
		path.Location = ".github/workflows/build.yml"
	case risk.CompositionSystemClassCloud:
		path.ToolType = "mcp_aws_lambda"
		path.Location = "cloud://lambda/deploy"
	case risk.CompositionSystemClassSaaS:
		path.ToolType = "mcp_saas_connector"
		path.Location = "saas://change-management"
	case risk.CompositionSystemClassCommunications:
		path.ToolType = "mcp_webhook"
		path.Location = "https://notifications.example.invalid/hook"
	}
	if observed {
		path.RuntimeEvidenceState = risk.EvidenceStateVerified
		path.GaitCoverage.ActionOutcome = risk.GaitCoverageDetail{Status: risk.GaitStatusPresent, EvidenceRefs: []string{"runtime:stage"}}
	}
	return path
}

func findMultiStageScenarioComposition(compositions []risk.ComposedActionPath, stageCount int) *risk.ComposedActionPath {
	for index := range compositions {
		if compositions[index].PatternID == risk.CompositionPatternSensitiveReadToEgressMultiStage && (stageCount == 0 || len(compositions[index].Stages) == stageCount) {
			return &compositions[index]
		}
	}
	return nil
}
