package report

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestBuildSummaryMultiStageDefaultOutputSizeDeltaBudget(t *testing.T) {
	t.Parallel()

	paths := []risk.ActionPath{multiStageReportPath(0, "repo", []string{"read_sensitive"}, risk.TargetClassCustomerDataAdjacent)}
	index := 1
	for _, systemClass := range []string{"ci", "cloud", "saas"} {
		for candidate := 0; candidate < 6; candidate++ {
			paths = append(paths, multiStageReportPath(index, systemClass, []string{"write", "transform"}, risk.TargetClassReleaseAdjacent))
			index++
		}
	}
	paths = append(paths, multiStageReportPath(index, "communications", []string{"external_write", "egress"}, risk.TargetClassProductionImpacting))
	pathIDs := make([]string, 0, len(paths))
	for _, path := range paths {
		pathIDs = append(pathIDs, path.PathID)
	}
	chains := &agentresolver.WorkflowChainArtifact{Chains: []agentresolver.WorkflowChain{{ChainID: "wfc-default-output-budget", PathIDs: pathIDs}}}
	compositions, _ := risk.BuildComposedActionPaths(paths, chains)
	pairwise := make([]risk.ComposedActionPath, 0, len(compositions))
	for _, composition := range compositions {
		if composition.ReachabilityState == "" {
			pairwise = append(pairwise, composition)
		}
	}
	if len(compositions) == len(pairwise) {
		t.Fatal("expected the default-output fixture to include bounded multi-stage compositions")
	}

	generatedAt := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	full, err := BuildSummary(BuildInput{
		GeneratedAt: generatedAt,
		Snapshot: state.Snapshot{RiskReport: &risk.Report{
			ActionPaths: paths, WorkflowChains: chains, ComposedActionPaths: compositions,
		}},
		Template: TemplateOperator, ShareProfile: ShareProfileInternal,
	})
	if err != nil {
		t.Fatalf("build full multi-stage summary: %v", err)
	}
	baseline, err := BuildSummary(BuildInput{
		GeneratedAt: generatedAt,
		Snapshot: state.Snapshot{RiskReport: &risk.Report{
			ActionPaths: paths, WorkflowChains: chains, ComposedActionPaths: pairwise,
		}},
		Template: TemplateOperator, ShareProfile: ShareProfileInternal,
	})
	if err != nil {
		t.Fatalf("build pairwise comparison summary: %v", err)
	}
	if len(full.TopRisks) != len(baseline.TopRisks) {
		t.Fatalf("multi-stage composition must not add finding noise: full=%d baseline=%d", len(full.TopRisks), len(baseline.TopRisks))
	}
	fullPayload, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal full multi-stage summary: %v", err)
	}
	baselinePayload, err := json.Marshal(baseline)
	if err != nil {
		t.Fatalf("marshal pairwise comparison summary: %v", err)
	}
	delta := len(fullPayload) - len(baselinePayload)
	const defaultSummaryDeltaBudget = 2 * 1024 * 1024
	if delta > defaultSummaryDeltaBudget {
		t.Fatalf("multi-stage default summary delta exceeded budget: delta=%d budget=%d", delta, defaultSummaryDeltaBudget)
	}
	t.Logf("multi-stage-default-summary measured_bytes=%d pairwise_bytes=%d delta_bytes=%d compositions=%d", len(fullPayload), len(baselinePayload), delta, len(full.ComposedActionPaths))
}

func multiStageReportPath(index int, systemClass string, actions []string, targetClass string) risk.ActionPath {
	path := risk.ActionPath{
		PathID:               fmt.Sprintf("apc-report-stage-%02d", index),
		Org:                  "fixture-org",
		Repo:                 "fixture-repo",
		ResolutionKey:        fmt.Sprintf("rk-report-stage-%02d", index),
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
	switch systemClass {
	case risk.CompositionSystemClassRepo:
		path.ToolType = "codex"
		path.Location = ".codex/config.toml"
	case risk.CompositionSystemClassCI:
		path.ToolType = "github_actions"
		path.Location = fmt.Sprintf(".github/workflows/build-%02d.yml", index)
	case risk.CompositionSystemClassCloud:
		path.ToolType = "mcp_aws_lambda"
		path.Location = fmt.Sprintf("cloud://lambda/deploy-%02d", index)
	case risk.CompositionSystemClassSaaS:
		path.ToolType = "mcp_saas_connector"
		path.Location = fmt.Sprintf("saas://change-management/%02d", index)
	case risk.CompositionSystemClassCommunications:
		path.ToolType = "mcp_webhook"
		path.Location = "https://notifications.example.invalid/hook"
	}
	return path
}
