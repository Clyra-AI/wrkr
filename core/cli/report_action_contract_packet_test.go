package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/export/actioncontracts"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
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

func TestReportActionContractPacketJSONSkipsMarkdownBudget(t *testing.T) {
	t.Parallel()

	statePath, contractID := seedOversizedActionContractPacketState(t)
	snapshot, err := state.Load(statePath)
	if err != nil {
		t.Fatalf("load oversized packet state: %v", err)
	}
	packet, err := actioncontracts.BuildPacket(snapshot, actioncontracts.BuildOptions{ShareProfile: reportcore.ShareProfileInternal, ContractID: contractID})
	if err != nil {
		t.Fatalf("build oversized packet fixture: %v", err)
	}
	if lines := strings.Count(reportcore.RenderActionContractPacketMarkdown(packet), "\n"); lines <= reportcore.ActionContractPacketMarkdownLineCap {
		t.Fatalf("oversized fixture must exceed Markdown cap to cover JSON-only path: lines=%d cap=%d", lines, reportcore.ActionContractPacketMarkdownLineCap)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"report", "--template", "action-contract-packet", "--contract-id", contractID, "--share-profile", "internal", "--state", statePath, "--json"}, &out, &errOut)
	if code != exitSuccess {
		t.Fatalf("packet JSON report must not render or budget Markdown: code=%d stderr=%s", code, errOut.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("parse oversized packet JSON: %v\n%s", err, out.String())
	}
	if decoded["schema_id"] != reportcore.ActionContractPacketSchemaID || decoded["report_only"] != true {
		t.Fatalf("unexpected oversized packet JSON contract: %+v", decoded)
	}

	out.Reset()
	errOut.Reset()
	code = Run([]string{"report", "--template", "action-contract-packet", "--contract-id", contractID, "--share-profile", "internal", "--state", statePath}, &out, &errOut)
	if code != exitRuntime || !strings.Contains(errOut.String(), "Markdown line budget") {
		t.Fatalf("Markdown output must still enforce packet line budget: code=%d stdout=%s stderr=%s", code, out.String(), errOut.String())
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

func TestScanRejectsActionContractPacketReportTemplate(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"scan",
		"--path", tmp,
		"--state", filepath.Join(tmp, "state.json"),
		"--report-md",
		"--report-template", "action-contract-packet",
		"--json",
	}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("scan must reject action-contract-packet outside report selector path: code=%d stdout=%s stderr=%s", code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
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

func seedOversizedActionContractPacketState(t *testing.T) (string, string) {
	t.Helper()
	composition := risk.ComposedActionPath{
		CompositionID: "cap-packet-oversized", PatternID: risk.CompositionPatternPackageChangeToRelease, OutcomeClass: "release_publish",
		TargetIdentity: "release:stable", TargetClass: risk.TargetClassProductionImpacting, AffectedAsset: "release:stable", ClaimState: risk.CompositionClaimStaticOnly,
		EvidenceState: risk.EvidenceStateUnknown, FreshnessState: evidencepolicy.FreshnessStateUnknown, RecommendedControl: risk.RecommendedControlApprovalRequired,
		EvidenceRefs:       []string{"owner:business:platform", "owner:system:release", "sod:requester_not_approver", "validation:release", "effect:publish", "check:tests", "producer:gait_policy", "sandbox:release", "compensation:rollback"},
		SourceDecisionRefs: []string{"policy:release", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Stages: []risk.CompositionStage{
			{StageID: "source", Role: risk.CompositionStageRoleSource, Location: "AGENTS.md", ParentAuthorityRef: "authority:root"},
			{StageID: "transform-a", Role: risk.CompositionStageRoleTransform, Location: "scripts/build.sh"},
			{StageID: "transform-b", Role: risk.CompositionStageRoleTransform, Location: "scripts/package.sh"},
			{StageID: "sink", Role: risk.CompositionStageRoleDestructiveSink, Location: ".github/workflows/release.yml", TargetClass: risk.TargetClassProductionImpacting},
		},
	}
	contract := risk.BuildProposedActionContract(composition)
	contract.AuthorityRequirements = make([]risk.ProposedActionRequirement, 0, 40)
	for index := 0; index < 40; index++ {
		contract.AuthorityRequirements = append(contract.AuthorityRequirements, risk.ProposedActionRequirement{
			RequirementID:      fmt.Sprintf("pacr-large-%02d", index),
			Kind:               "requester_identity",
			RequiredConstraint: fmt.Sprintf("requester:%02d", index),
			ObservedValue:      fmt.Sprintf("automation:%02d", index),
			EvidenceState:      risk.EvidenceStateUnknown,
			FreshnessState:     evidencepolicy.FreshnessStateUnknown,
			ReasonCodes:        oversizedPacketReasonCodes("authority", index),
		})
	}
	contract.Preconditions = make([]risk.ProposedActionPrecondition, 0, 40)
	for index := 0; index < 40; index++ {
		contract.Preconditions = append(contract.Preconditions, risk.ProposedActionPrecondition{
			RequirementID:      fmt.Sprintf("pacp-large-%02d", index),
			Kind:               "required_check",
			RequiredConstraint: fmt.Sprintf("check:%02d", index),
			ObservedResult:     "missing",
			EvidenceState:      risk.EvidenceStateUnknown,
			FreshnessState:     evidencepolicy.FreshnessStateUnknown,
			ReasonCodes:        oversizedPacketReasonCodes("precondition", index),
		})
	}
	contract.LifecycleObservations = make([]risk.ProposedActionLifecycleObservation, 0, 24)
	for index := 0; index < 24; index++ {
		contract.LifecycleObservations = append(contract.LifecycleObservations, risk.ProposedActionLifecycleObservation{
			ObservationID:  fmt.Sprintf("paco-large-%02d", index),
			Kind:           "gait_execution",
			Producer:       "gait",
			EvidenceState:  risk.EvidenceStateContradictory,
			FreshnessState: evidencepolicy.FreshnessStateUnknown,
			ReasonCodes:    oversizedPacketReasonCodes("lifecycle", index),
		})
	}
	risk.RefreshProposedActionContractIdentity(contract)
	composition.ProposedActionContract = contract
	composition.ProposedActionContractRefs = []string{contract.ContractID}
	statePath := filepath.Join(t.TempDir(), "state.json")
	if err := state.Save(statePath, state.Snapshot{Version: state.SnapshotVersion, RiskReport: &risk.Report{ComposedActionPaths: []risk.ComposedActionPath{composition}}}); err != nil {
		t.Fatalf("save oversized packet state: %v", err)
	}
	return statePath, contract.ContractID
}

func oversizedPacketReasonCodes(prefix string, index int) []string {
	out := make([]string, 0, 10)
	for reason := 0; reason < 10; reason++ {
		out = append(out, fmt.Sprintf("%s:%02d:%02d", prefix, index, reason))
	}
	return out
}
