package report

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestBuildActionContractPacketNormalizesBuyerSectionsAndVisibleGaps(t *testing.T) {
	t.Parallel()

	input := actionContractPacketTestInput()
	packet, err := BuildActionContractPacket(input)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	if packet.SchemaVersion != "1" || packet.PacketID == "" || !packet.ReportOnly {
		t.Fatalf("unexpected packet identity: %+v", packet)
	}
	if packet.Identity.ContractID != input.Contract.ContractID || packet.Identity.ArtifactID != input.ArtifactID {
		t.Fatalf("packet must preserve selected artifact identity: %+v", packet.Identity)
	}
	if len(packet.Path.Stages) != 2 || packet.Path.Stages[0].Role != risk.CompositionStageRoleSource {
		t.Fatalf("packet stages must be deterministically source-to-sink: %+v", packet.Path.Stages)
	}
	if len(packet.AuthorityRequirements) != 2 || packet.AuthorityRequirements[0].Kind != "business_owner" {
		t.Fatalf("authority requirements must be stably sorted: %+v", packet.AuthorityRequirements)
	}
	if len(packet.EvidenceGaps) < 2 {
		t.Fatalf("weak and stale evidence must remain visible as gaps: %+v", packet.EvidenceGaps)
	}
	if !strings.Contains(packet.AuthorityRequirements[1].ObservedValue, ActionContractPacketTruncationMarker) || len(packet.Truncations) == 0 {
		t.Fatalf("long presentation values must be explicitly truncated: requirements=%+v truncations=%+v", packet.AuthorityRequirements, packet.Truncations)
	}
	if packet.Reachability.ObservedExecution {
		t.Fatalf("static composition must not be rendered as observed execution: %+v", packet.Reachability)
	}
	if !strings.Contains(packet.NextStep.Action, "Gait") {
		t.Fatalf("next step must preserve the Wrkr/Gait authority boundary: %+v", packet.NextStep)
	}
}

func TestBuildActionContractPacketIsStableAcrossInputOrdering(t *testing.T) {
	t.Parallel()

	leftInput := actionContractPacketTestInput()
	rightInput := actionContractPacketTestInput()
	reverseRequirements(rightInput.Contract.AuthorityRequirements)
	reversePreconditions(rightInput.Contract.Preconditions)
	reversePacketStages(rightInput.Composition.Stages)

	left, err := BuildActionContractPacket(leftInput)
	if err != nil {
		t.Fatalf("build left packet: %v", err)
	}
	right, err := BuildActionContractPacket(rightInput)
	if err != nil {
		t.Fatalf("build right packet: %v", err)
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("packet model changed under input reordering\nleft=%+v\nright=%+v", left, right)
	}
}

func TestBuildActionContractPacketEvidenceGapsUseUncappedRequirements(t *testing.T) {
	t.Parallel()

	input := actionContractPacketTestInput()
	input.Contract.AuthorityRequirements = make([]risk.ProposedActionRequirement, 0, actionContractPacketRequirementCap+1)
	for index := 0; index < actionContractPacketRequirementCap; index++ {
		input.Contract.AuthorityRequirements = append(input.Contract.AuthorityRequirements, risk.ProposedActionRequirement{
			RequirementID:      "pacr-a-verified-" + twoDigitIndex(index),
			Kind:               "aaa_verified_authority",
			RequiredConstraint: "owner:required",
			ObservedValue:      "team-platform",
			EvidenceState:      risk.EvidenceStateVerified,
			FreshnessState:     evidencepolicy.FreshnessStateFresh,
		})
	}
	input.Contract.AuthorityRequirements = append(input.Contract.AuthorityRequirements, risk.ProposedActionRequirement{
		RequirementID:      "pacr-z-uncapped-gap",
		Kind:               "zzz_requesting_identity",
		RequiredConstraint: "requester:verified",
		ObservedValue:      "automation",
		EvidenceState:      risk.EvidenceStateUnknown,
		FreshnessState:     evidencepolicy.FreshnessStateFresh,
		ReasonCodes:        []string{"requester_identity:missing"},
	})
	input.Contract.Preconditions = nil
	input.Contract.ConfirmationRequirement = &risk.ProposedActionConfirmation{Mode: "explicit", Required: true, EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh}
	input.Contract.ApprovalRequirement = &risk.ProposedActionApproval{Required: true, EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh}
	input.Contract.CompensationRequirement = &risk.ProposedActionCompensation{Required: true, EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh}
	input.Contract.LifecycleObservations = nil

	packet, err := BuildActionContractPacket(input)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	if len(packet.AuthorityRequirements) != actionContractPacketRequirementCap {
		t.Fatalf("expected display requirements to stay capped, got %d", len(packet.AuthorityRequirements))
	}
	if packetHasAuthorityRequirement(packet, "pacr-z-uncapped-gap") {
		t.Fatalf("expected uncapped gap fixture to be outside capped display requirements: %+v", packet.AuthorityRequirements)
	}
	if !packetHasEvidenceGap(packet, "pacr-z-uncapped-gap") {
		t.Fatalf("expected evidence gap from uncapped requirement source, got %+v", packet.EvidenceGaps)
	}
	if !strings.Contains(packet.NextStep.Action, "pacr-z-uncapped-gap") {
		t.Fatalf("next step must not claim activation readiness while uncapped evidence gap exists: %+v", packet.NextStep)
	}
}

func TestBuildActionContractPacketCapsEvidenceGapReasonCodes(t *testing.T) {
	t.Parallel()

	input := actionContractPacketTestInput()
	reasons := make([]string, 0, actionContractPacketReferenceCap+2)
	for index := 0; index < actionContractPacketReferenceCap+2; index++ {
		reasons = append(reasons, "gap_reason:"+twoDigitIndex(index))
	}
	input.Contract.AuthorityRequirements = append(input.Contract.AuthorityRequirements, risk.ProposedActionRequirement{
		RequirementID:      "pacr-many-reasons",
		Kind:               "requester_identity",
		RequiredConstraint: "requester:verified",
		EvidenceState:      risk.EvidenceStateUnknown,
		FreshnessState:     evidencepolicy.FreshnessStateUnknown,
		ReasonCodes:        reasons,
	})

	packet, err := BuildActionContractPacket(input)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	gap, ok := packetEvidenceGapForID(packet, "pacr-many-reasons")
	if !ok {
		t.Fatalf("expected evidence gap for uncapped reason fixture: %+v", packet.EvidenceGaps)
	}
	if len(gap.ReasonCodes) != actionContractPacketReferenceCap {
		t.Fatalf("gap reason codes must honor packet schema cap: got=%d codes=%v", len(gap.ReasonCodes), gap.ReasonCodes)
	}
	if !packetHasTruncation(packet, "evidence_gaps.pacr-many-reasons.reason_codes") {
		t.Fatalf("expected gap reason-code truncation receipt: %+v", packet.Truncations)
	}
}

func TestBuildActionContractPacketEmitsRequiredPlaceholdersForMissingSections(t *testing.T) {
	t.Parallel()

	input := actionContractPacketTestInput()
	input.Contract.ConfirmationRequirement = nil
	input.Contract.ApprovalRequirement = nil
	input.Contract.CompensationRequirement = nil

	packet, err := BuildActionContractPacket(input)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	if packet.Confirmation == nil || packet.Confirmation.Mode != "explicit_confirmation" || !packet.Confirmation.Required || packet.Confirmation.EvidenceState != risk.EvidenceStateUnknown {
		t.Fatalf("missing confirmation must project a fail-closed placeholder: %+v", packet.Confirmation)
	}
	if packet.Approval == nil || !packet.Approval.Required || packet.Approval.MinimumApprovals != 1 || !strings.HasPrefix(packet.Approval.ScopeDigest, "sha256:") || packet.Approval.EvidenceState != risk.EvidenceStateUnknown {
		t.Fatalf("missing approval must project a schema-valid placeholder: %+v", packet.Approval)
	}
	if packet.Compensation == nil || !packet.Compensation.Required || packet.Compensation.Kind != "documented_recovery" || !packet.Compensation.VerificationRequired || packet.Compensation.EvidenceState != risk.EvidenceStateUnknown {
		t.Fatalf("missing compensation must project a fail-closed placeholder: %+v", packet.Compensation)
	}
	for _, id := range []string{"confirmation", "approval", "compensation"} {
		if !packetHasEvidenceGap(packet, id) {
			t.Fatalf("missing %s section must stay visible as an evidence gap: %+v", id, packet.EvidenceGaps)
		}
	}
	payload, err := json.Marshal(packet)
	if err != nil {
		t.Fatalf("marshal packet: %v", err)
	}
	var document map[string]any
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatalf("decode packet: %v", err)
	}
	for _, key := range []string{"confirmation_requirement", "approval_requirement", "compensation_requirement"} {
		if _, ok := document[key]; !ok {
			t.Fatalf("required packet section %q must not be omitted: %s", key, payload)
		}
	}
}

func TestBuildActionContractPacketDerivedSectionsUseUncappedSources(t *testing.T) {
	t.Parallel()

	input := actionContractPacketTestInput()
	input.Contract.AuthorityRequirements = make([]risk.ProposedActionRequirement, 0, actionContractPacketRequirementCap+1)
	for index := 0; index < actionContractPacketRequirementCap; index++ {
		input.Contract.AuthorityRequirements = append(input.Contract.AuthorityRequirements, risk.ProposedActionRequirement{
			RequirementID:      "pacr-a-verified-" + twoDigitIndex(index),
			Kind:               "aaa_verified_authority",
			RequiredConstraint: "owner:required",
			ObservedValue:      "team-platform",
			EvidenceState:      risk.EvidenceStateVerified,
			FreshnessState:     evidencepolicy.FreshnessStateFresh,
		})
	}
	input.Contract.AuthorityRequirements = append(input.Contract.AuthorityRequirements, risk.ProposedActionRequirement{
		RequirementID:      "pacr-z-hidden-credential",
		Kind:               "zzz_credential_scope",
		RequiredConstraint: "credential:ephemeral",
		ObservedValue:      "standing_token",
		EvidenceState:      risk.EvidenceStateUnknown,
		FreshnessState:     evidencepolicy.FreshnessStateStale,
	})
	input.Contract.Preconditions = make([]risk.ProposedActionPrecondition, 0, actionContractPacketPreconditionCap+2)
	for index := 0; index < actionContractPacketPreconditionCap; index++ {
		input.Contract.Preconditions = append(input.Contract.Preconditions, risk.ProposedActionPrecondition{
			RequirementID:      "pacp-a-verified-" + twoDigitIndex(index),
			Kind:               "aaa_required_check",
			RequiredConstraint: "check:pass",
			ObservedResult:     "pass",
			EvidenceState:      risk.EvidenceStateVerified,
			FreshnessState:     evidencepolicy.FreshnessStateFresh,
		})
	}
	input.Contract.Preconditions = append(input.Contract.Preconditions,
		risk.ProposedActionPrecondition{RequirementID: "pacp-z-hidden-expected", Kind: "expected_effect", RequiredConstraint: "hidden_expected_effect", EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh},
		risk.ProposedActionPrecondition{RequirementID: "pacp-z-hidden-forbidden", Kind: "forbidden_effect", RequiredConstraint: "hidden_forbidden_effect", EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh},
	)
	input.Contract.ConfirmationRequirement = &risk.ProposedActionConfirmation{Mode: "explicit", Required: true, EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh}
	input.Contract.ApprovalRequirement = &risk.ProposedActionApproval{Required: true, EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh}
	input.Contract.CompensationRequirement = &risk.ProposedActionCompensation{Required: true, EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh}
	input.Contract.LifecycleObservations = nil

	packet, err := BuildActionContractPacket(input)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	if packetHasAuthorityRequirement(packet, "pacr-z-hidden-credential") || packetHasReadinessCheck(packet, "pacp-z-hidden-forbidden") {
		t.Fatalf("hidden summary sources must remain outside capped display sections: requirements=%+v preconditions=%+v", packet.AuthorityRequirements, packet.ReadinessChecks)
	}
	if !packetContainsString(packet.CredentialPosture.RequirementIDs, "pacr-z-hidden-credential") || packet.CredentialPosture.EvidenceState != risk.EvidenceStateUnknown {
		t.Fatalf("credential posture must use uncapped authority source, got %+v", packet.CredentialPosture)
	}
	if !packetContainsString(packet.Effects.Expected, "hidden_expected_effect") || !packetContainsString(packet.Effects.Forbidden, "hidden_forbidden_effect") {
		t.Fatalf("effects must use uncapped precondition source, got %+v", packet.Effects)
	}
}

func TestBuildActionContractPacketStageCapPreservesHighImpactSink(t *testing.T) {
	t.Parallel()

	input := actionContractPacketTestInput()
	input.Composition.Stages = []risk.CompositionStage{
		{StageID: "stage-source", Role: risk.CompositionStageRoleSource, Location: "AGENTS.md", TargetClass: risk.TargetClassReleaseAdjacent},
		{StageID: "stage-transform-a", Role: risk.CompositionStageRoleTransform, Location: "step-a"},
		{StageID: "stage-transform-b", Role: risk.CompositionStageRoleTransform, Location: "step-b"},
		{StageID: "stage-transform-c", Role: risk.CompositionStageRoleTransform, Location: "step-c"},
		{StageID: "stage-transform-d", Role: risk.CompositionStageRoleTransform, Location: "step-d"},
		{StageID: "stage-sink", Role: risk.CompositionStageRoleDestructiveSink, Location: ".github/workflows/release.yml", TargetClass: risk.TargetClassProductionImpacting},
	}

	packet, err := BuildActionContractPacket(input)
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	if len(packet.Path.Stages) != actionContractPacketStageCap {
		t.Fatalf("expected capped stage presentation, got %+v", packet.Path.Stages)
	}
	if !packetHasStage(packet, "stage-sink") {
		t.Fatalf("high-impact sink stage must survive presentation cap: %+v", packet.Path.Stages)
	}
	if packet.Path.Stages[len(packet.Path.Stages)-1].StageID != "stage-sink" {
		t.Fatalf("selected packet stages must remain source-to-sink after capping: %+v", packet.Path.Stages)
	}
	if !packetHasTruncation(packet, "path.stages") {
		t.Fatalf("expected path stage cap to be recorded: %+v", packet.Truncations)
	}
}

func TestRenderActionContractPacketMarkdownProjectsSharedModel(t *testing.T) {
	t.Parallel()

	packet, err := BuildActionContractPacket(actionContractPacketTestInput())
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	markdown := RenderActionContractPacketMarkdown(packet)
	for _, want := range []string{
		"# Wrkr Action Contract Packet",
		"## Contract and Artifact Identity",
		"## Composed Path",
		"## Authority Requirements",
		"## Credential Posture",
		"## Readiness Checks",
		"## Expected and Forbidden Effects",
		"## Confirmation and Approval",
		"## Compensation",
		"## Evidence Gaps",
		"## Imported Gait and Axym Evidence",
		"## Next Action",
		packet.Identity.ContractID,
		"possible static reachability; not observed execution",
	} {
		if !strings.Contains(markdown, want) {
			t.Fatalf("markdown missing %q:\n%s", want, markdown)
		}
	}
	if lines := strings.Count(markdown, "\n"); lines > ActionContractPacketMarkdownLineCap {
		t.Fatalf("packet markdown exceeded line cap: got=%d cap=%d", lines, ActionContractPacketMarkdownLineCap)
	}
}

func TestActionContractPacketSizeReadabilityAndCloneStripBudgets(t *testing.T) {
	t.Parallel()

	packet, err := BuildActionContractPacket(actionContractPacketTestInput())
	if err != nil {
		t.Fatalf("build packet: %v", err)
	}
	payload, err := json.MarshalIndent(packet, "", "  ")
	if err != nil {
		t.Fatalf("marshal packet: %v", err)
	}
	markdown := RenderActionContractPacketMarkdown(packet)
	const jsonBudget = 64 * 1024
	const markdownBudget = 32 * 1024
	if len(payload) > jsonBudget || len(markdown) > markdownBudget {
		t.Fatalf("packet exceeded size budget: json=%d/%d markdown=%d/%d", len(payload), jsonBudget, len(markdown), markdownBudget)
	}
	if lines := strings.Count(markdown, "\n"); lines > ActionContractPacketMarkdownLineCap {
		t.Fatalf("packet exceeded readability line cap: lines=%d cap=%d", lines, ActionContractPacketMarkdownLineCap)
	}
	if strings.Contains(string(payload), "allowed_transitions") || strings.Contains(string(payload), "contract_kind") {
		t.Fatalf("packet must project buyer fields instead of cloning the full contract: %s", payload)
	}
	t.Logf("action-contract-packet measured_bytes json=%d markdown=%d markdown_lines=%d", len(payload), len(markdown), strings.Count(markdown, "\n"))
}

func actionContractPacketTestInput() ActionContractPacketInput {
	longObserved := "owner:" + strings.Repeat("customer-private-identity-", 16)
	contract := risk.ProposedActionContract{
		ContractID:              "pac-0123456789abcdef",
		ContractFamilyID:        "pacf-0123456789abcdef",
		ContractContentDigest:   "sha256:" + strings.Repeat("a", 64),
		ContractVersion:         risk.ProposedActionContractVersionV3,
		ContractKind:            risk.ProposedActionContractKind,
		CompositionRef:          "cap-01234567",
		Revision:                2,
		SupersedesRef:           "pac-fedcba9876543210",
		RequiredCredentialMode:  "ephemeral",
		ExpectedOutcomeClass:    "release_publish",
		ReadinessState:          "needs_evidence",
		AuthorityReadinessState: "needs_evidence",
		ReportOnly:              true,
		AuthorityRequirements: []risk.ProposedActionRequirement{
			{RequirementID: "pacr-requester", Kind: "requesting_identity", RequiredConstraint: "requester:verified", ObservedValue: longObserved, EvidenceState: risk.EvidenceStateInferred, FreshnessState: evidencepolicy.FreshnessStateUnknown, EvidenceRefs: []string{"identity:requester"}},
			{RequirementID: "pacr-owner", Kind: "business_owner", RequiredConstraint: "owner:required", ObservedValue: "team-platform", EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh, EvidenceRefs: []string{"owner:platform"}},
		},
		Preconditions: []risk.ProposedActionPrecondition{
			{RequirementID: "pacp-check", Kind: "required_check", RequiredConstraint: "tests:pass", ObservedResult: "pass", EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateStale, EvidenceRefs: []string{"check:tests"}},
			{RequirementID: "pacp-effect", Kind: "expected_effect", RequiredConstraint: "release_publish", EvidenceState: risk.EvidenceStateDeclared, FreshnessState: evidencepolicy.FreshnessStateFresh},
			{RequirementID: "pacp-forbidden", Kind: "forbidden_effect", RequiredConstraint: "secret_disclosure", EvidenceState: risk.EvidenceStateVerified, FreshnessState: evidencepolicy.FreshnessStateFresh},
		},
		ConfirmationRequirement: &risk.ProposedActionConfirmation{Mode: "explicit", Required: true, EvidenceState: risk.EvidenceStateUnknown, FreshnessState: evidencepolicy.FreshnessStateUnknown},
		ApprovalRequirement:     &risk.ProposedActionApproval{Required: true, ApproverRoles: []string{"security", "system_owner"}, MinimumApprovals: 2, SeparationOfDuties: []string{"requester_not_approver"}, ScopeDigest: "sha256:" + strings.Repeat("b", 64), ValidityWindow: "PT1H", EvidenceState: risk.EvidenceStateDeclared, FreshnessState: evidencepolicy.FreshnessStateFresh},
		CompensationRequirement: &risk.ProposedActionCompensation{Required: true, Kind: "rollback", ProcedureRef: "runbook:rollback", Target: "release:stable", ExecutionWindow: "PT15M", VerificationRequired: true, EvidenceState: risk.EvidenceStateDeclared, FreshnessState: evidencepolicy.FreshnessStateFresh},
		LifecycleObservations:   []risk.ProposedActionLifecycleObservation{{ObservationID: "paco-1", Kind: "gait_activation_request", Producer: "gait", EvidenceState: risk.EvidenceStateDeclared, FreshnessState: evidencepolicy.FreshnessStateFresh, EvidenceRefs: []string{"gait:request:1"}}},
	}
	composition := risk.ComposedActionPath{
		CompositionID: "cap-01234567", PatternID: risk.CompositionPatternPackageChangeToRelease,
		ResolutionKey: "release|stable", PathIDs: []string{"apc-source", "apc-sink"}, AffectedAsset: "release:stable", TargetIdentity: "release:stable", TargetClass: risk.TargetClassReleaseAdjacent,
		OutcomeClass: "release_publish", ClaimState: risk.CompositionClaimStaticOnly, EvidenceState: risk.EvidenceStateDeclared, FreshnessState: evidencepolicy.FreshnessStateFresh,
		Stages: []risk.CompositionStage{
			{StageID: "stage-sink", Role: risk.CompositionStageRoleDestructiveSink, ToolType: "ci", Location: ".github/workflows/release.yml", TargetClass: risk.TargetClassReleaseAdjacent},
			{StageID: "stage-source", Role: risk.CompositionStageRoleSource, ToolType: "agent", Location: "AGENTS.md", ActionClasses: []string{"package_write"}},
		},
	}
	return ActionContractPacketInput{
		ArtifactID: "paca-0123456789abcdef", CanonicalContentDigest: "sha256:" + strings.Repeat("c", 64),
		ShareProfile: string(ShareProfileInternal), ArtifactRedacted: false, SourceScanRefs: []string{"saved_scan:v1"}, CreationEvidence: []string{"proof:risk-assessment"},
		Contract: contract, Composition: composition,
	}
}

func reverseRequirements(values []risk.ProposedActionRequirement) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func reversePreconditions(values []risk.ProposedActionPrecondition) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func reversePacketStages(values []risk.CompositionStage) {
	for left, right := 0, len(values)-1; left < right; left, right = left+1, right-1 {
		values[left], values[right] = values[right], values[left]
	}
}

func twoDigitIndex(index int) string {
	return fmt.Sprintf("%02d", index)
}

func packetHasAuthorityRequirement(packet ActionContractPacket, id string) bool {
	for _, item := range packet.AuthorityRequirements {
		if item.RequirementID == id {
			return true
		}
	}
	return false
}

func packetHasEvidenceGap(packet ActionContractPacket, id string) bool {
	_, ok := packetEvidenceGapForID(packet, id)
	return ok
}

func packetEvidenceGapForID(packet ActionContractPacket, id string) (ActionContractPacketGap, bool) {
	for _, item := range packet.EvidenceGaps {
		if item.RequirementID == id {
			return item, true
		}
	}
	return ActionContractPacketGap{}, false
}

func packetHasReadinessCheck(packet ActionContractPacket, id string) bool {
	for _, item := range packet.ReadinessChecks {
		if item.RequirementID == id {
			return true
		}
	}
	return false
}

func packetHasStage(packet ActionContractPacket, id string) bool {
	for _, item := range packet.Path.Stages {
		if item.StageID == id {
			return true
		}
	}
	return false
}

func packetContainsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func packetHasTruncation(packet ActionContractPacket, field string) bool {
	for _, item := range packet.Truncations {
		if item.Field == field {
			return true
		}
	}
	return false
}
