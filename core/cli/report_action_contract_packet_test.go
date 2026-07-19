package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestReportActionContractPacketJSONAndMarkdown(t *testing.T) {
	t.Parallel()

	statePath, contractID := seedActionContractPacketState(t)
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"report", "--template", "action-contract-packet", "--contract-id", contractID, "--share-profile", "internal", "--state", statePath, "--json"}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("packet JSON report failed: code=%d stderr=%s", code, errOut.String())
	}
	var packet map[string]any
	if err := json.Unmarshal(out.Bytes(), &packet); err != nil {
		t.Fatalf("parse packet JSON: %v\n%s", err, out.String())
	}
	if packet["schema_id"] != "https://wrkr.dev/schemas/v1/report/action-contract-packet.schema.json" || packet["report_only"] != true {
		t.Fatalf("unexpected packet contract: %+v", packet)
	}
	identity, _ := packet["identity"].(map[string]any)
	if identity["contract_id"] != contractID {
		t.Fatalf("selected contract identity mismatch: %+v", identity)
	}

	out.Reset()
	errOut.Reset()
	code = Run([]string{"report", "--template", "action-contract-packet", "--contract-id", contractID, "--share-profile", "internal", "--state", statePath}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("packet Markdown report failed: code=%d stderr=%s", code, errOut.String())
	}
	for _, want := range []string{"# Wrkr Action Contract Packet", contractID, "not observed execution", "Wrkr proposes"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("packet Markdown missing %q:\n%s", want, out.String())
		}
	}
}

func TestReportActionContractPacketRequiresExplicitSelector(t *testing.T) {
	t.Parallel()

	statePath, _ := seedActionContractPacketState(t)
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"report", "--template", "action-contract-packet", "--state", statePath, "--json"}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected explicit-selector exit %d, got %d stdout=%s stderr=%s", exitInvalidInput, code, out.String(), errOut.String())
	}
}

func TestReportDefaultOutputDoesNotIncludeActionContractPacket(t *testing.T) {
	t.Parallel()

	statePath, _ := seedActionContractPacketState(t)
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"report", "--state", statePath, "--share-profile", "internal", "--json"}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("default report failed: code=%d stderr=%s", code, errOut.String())
	}
	if strings.Contains(out.String(), "action-contract-packet") || strings.Contains(out.String(), "action_contract_packet") {
		t.Fatalf("default report must not grow the opt-in packet surface: %s", out.String())
	}
}

func seedActionContractPacketState(t *testing.T) (string, string) {
	t.Helper()
	composition := risk.ComposedActionPath{
		CompositionID: "cap-packet-01", PatternID: risk.CompositionPatternPackageChangeToRelease, OutcomeClass: "release_publish",
		TargetIdentity: "release:stable", TargetClass: risk.TargetClassReleaseAdjacent, AffectedAsset: "release:stable", ClaimState: risk.CompositionClaimStaticOnly,
		EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh, RecommendedControl: risk.RecommendedControlApprovalRequired,
		EvidenceRefs: []string{"validation:release", "effect:publish", "check:tests", "producer:gait_policy", "sandbox:release", "compensation:rollback"}, SourceDecisionRefs: []string{"policy:release"},
		Stages: []risk.CompositionStage{{StageID: "source", Role: risk.CompositionStageRoleSource, Location: "AGENTS.md", ParentAuthorityRef: "authority:root"}, {StageID: "sink", Role: risk.CompositionStageRoleDestructiveSink, Location: ".github/workflows/release.yml"}},
	}
	composition.ProposedActionContract = risk.BuildProposedActionContract(composition)
	composition.ProposedActionContractRefs = []string{composition.ProposedActionContract.ContractID}
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(statePath, state.Snapshot{Version: state.SnapshotVersion, RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{composition}}}); err != nil {
		t.Fatalf("save packet state: %v", err)
	}
	return statePath, composition.ProposedActionContract.ContractID
}
