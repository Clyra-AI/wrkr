package contracts

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/export/actioncontracts"
	"github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
	"github.com/santhosh-tekuri/jsonschema/v5"
)

func TestActionContractPacketSchemaValidatesRealArtifactProjection(t *testing.T) {
	t.Parallel()

	composition := risk.ComposedActionPath{
		CompositionID: "cap-packet-schema", PatternID: risk.CompositionPatternPackageChangeToRelease,
		OutcomeClass: "release_publish", TargetIdentity: "release:stable", TargetClass: risk.TargetClassReleaseAdjacent, AffectedAsset: "release:stable",
		ClaimState: risk.CompositionClaimStaticOnly, EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh,
		RecommendedControl: risk.RecommendedControlApprovalRequired,
		EvidenceRefs:       []string{"validation:release", "effect:publish", "check:tests", "producer:gait_policy", "sandbox:release", "compensation:rollback", "owner:business:platform", "owner:system:release", "sod:requester_not_approver"},
		SourceDecisionRefs: []string{"policy:release", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Stages: []risk.CompositionStage{
			{StageID: "source", Role: risk.CompositionStageRoleSource, ToolType: "agent", Location: "AGENTS.md", ParentAuthorityRef: "authority:root"},
			{StageID: "sink", Role: risk.CompositionStageRoleDestructiveSink, ToolType: "ci", Location: ".github/workflows/release.yml"},
		},
	}
	composition.ProposedActionContract = risk.BuildProposedActionContract(composition)
	composition.ProposedActionContractRefs = []string{composition.ProposedActionContract.ContractID}
	snapshot := state.Snapshot{Version: state.SnapshotVersion, RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{composition}}}
	packet, err := actioncontracts.BuildPacket(snapshot, actioncontracts.BuildOptions{ShareProfile: report.ShareProfileInternal, ContractID: composition.ProposedActionContract.ContractID})
	if err != nil {
		t.Fatalf("build real packet projection: %v", err)
	}
	payload, err := json.Marshal(packet)
	if err != nil {
		t.Fatalf("marshal packet: %v", err)
	}
	var document any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode packet document: %v", err)
	}

	repoRoot := mustFindRepoRoot(t)
	packetSchemaPath := filepath.Join(repoRoot, "schemas", "v1", "report", "action-contract-packet.schema.json")
	v3SchemaPath := filepath.Join(repoRoot, "schemas", "v1", "proposed-action-contract-v3.schema.json")
	compiler := jsonschema.NewCompiler()
	mustAddCompositionSchemaResourceAs(t, compiler, "https://wrkr.dev/schemas/v1/proposed-action-contract-v3.schema.json", v3SchemaPath)
	mustAddCompositionSchemaResource(t, compiler, packetSchemaPath)
	compiled, err := compiler.Compile(packetSchemaPath)
	if err != nil {
		t.Fatalf("compile packet schema: %v", err)
	}
	if err := compiled.Validate(document); err != nil {
		t.Fatalf("real packet projection must validate: %v\n%s", err, payload)
	}

	tampered := document.(map[string]any)
	tampered["report_only"] = false
	if err := compiled.Validate(tampered); err == nil {
		t.Fatal("packet schema must reject a runtime-authority claim")
	}
}
