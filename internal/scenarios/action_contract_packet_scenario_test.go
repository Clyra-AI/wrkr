//go:build scenario

package scenarios

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/export/actioncontracts"
	"github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestScenarioActionContractPacketPaidAssessment(t *testing.T) {
	t.Parallel()

	composition := risk.ComposedActionPath{
		CompositionID: "cap-paid-assessment", PatternID: risk.CompositionPatternPackageChangeToRelease,
		OutcomeClass: "release_publish", TargetIdentity: "release:stable", TargetClass: risk.TargetClassReleaseAdjacent, AffectedAsset: "release:stable",
		ClaimState: risk.CompositionClaimStaticOnly, EvidenceState: risk.EvidenceStateDeclared, FreshnessState: evidencepolicy.FreshnessStateFresh,
		RecommendedControl: risk.RecommendedControlApprovalRequired,
		EvidenceRefs:       []string{"validation:release", "effect:publish", "check:tests", "producer:gait_policy", "sandbox:release", "compensation:rollback", "owner:business:platform", "owner:system:release"},
		SourceDecisionRefs: []string{"policy:release", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Stages: []risk.CompositionStage{
			{StageID: "source", Role: risk.CompositionStageRoleSource, ToolType: "agent", Location: "AGENTS.md", ParentAuthorityRef: "authority:root"},
			{StageID: "sink", Role: risk.CompositionStageRoleDestructiveSink, ToolType: "ci", Location: ".github/workflows/release.yml"},
		},
	}
	composition.ProposedActionContract = risk.BuildProposedActionContract(composition)
	composition.ProposedActionContractRefs = []string{composition.ProposedActionContract.ContractID}
	snapshot := state.Snapshot{Version: state.SnapshotVersion, RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{composition}}}
	packet, err := actioncontracts.BuildPacket(snapshot, actioncontracts.BuildOptions{ShareProfile: report.ShareProfileCustomerRedacted, ContractID: composition.ProposedActionContract.ContractID})
	if err != nil {
		t.Fatalf("build paid-assessment packet: %v", err)
	}
	jsonPayload, err := json.Marshal(packet)
	if err != nil {
		t.Fatalf("marshal paid-assessment packet: %v", err)
	}
	markdown := report.RenderActionContractPacketMarkdown(packet)
	if !strings.Contains(string(jsonPayload), packet.Identity.ContractID) || !strings.Contains(markdown, packet.Identity.ContractID) {
		t.Fatalf("JSON and Markdown must project the same selected contract: id=%s json=%s markdown=%s", packet.Identity.ContractID, jsonPayload, markdown)
	}
	if len(packet.EvidenceGaps) == 0 || !strings.Contains(markdown, "## Evidence Gaps") {
		t.Fatalf("declared or missing evidence must remain visible in both views: packet=%+v markdown=%s", packet, markdown)
	}
	if packet.Reachability.ObservedExecution || !strings.Contains(markdown, "not observed execution") {
		t.Fatalf("static paid-assessment path must not imply execution: %+v", packet.Reachability)
	}
	if !packet.Identity.Redacted || packet.ReportOnly != true {
		t.Fatalf("buyer packet must be redacted and report only: %+v", packet)
	}
}
