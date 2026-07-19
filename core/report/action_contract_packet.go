package report

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const (
	ActionContractPacketSchemaID         = "https://wrkr.dev/schemas/v1/report/action-contract-packet.schema.json"
	ActionContractPacketSchemaVersion    = "1"
	ActionContractPacketTemplate         = "action-contract-packet"
	ActionContractPacketTruncationMarker = "… [truncated]"
	ActionContractPacketMarkdownLineCap  = 180
	actionContractPacketValueRuneCap     = 160
	actionContractPacketReferenceCap     = 8
	actionContractPacketRequirementCap   = 24
	actionContractPacketPreconditionCap  = 32
	actionContractPacketLifecycleCap     = 16
	actionContractPacketGapCap           = 32
)

// ActionContractPacketInput is deliberately shaped like the durable portable
// artifact plus its normalized composition. Callers must build the artifact
// first; report code does not rescore or infer a second contract truth.
type ActionContractPacketInput struct {
	ArtifactID             string
	CanonicalContentDigest string
	ShareProfile           string
	ArtifactRedacted       bool
	SourceScanRefs         []string
	CreationEvidence       []string
	Contract               risk.ProposedActionContract
	Composition            risk.ComposedActionPath
}

type ActionContractPacket struct {
	SchemaID              string                                    `json:"schema_id"`
	SchemaVersion         string                                    `json:"schema_version"`
	PacketID              string                                    `json:"packet_id"`
	Template              string                                    `json:"template"`
	SectionOrder          []string                                  `json:"section_order"`
	Identity              ActionContractPacketIdentity              `json:"identity"`
	Path                  ActionContractPacketPath                  `json:"path"`
	AffectedAsset         string                                    `json:"affected_asset,omitempty"`
	AuthorityRequirements []risk.ProposedActionRequirement          `json:"authority_requirements"`
	CredentialPosture     ActionContractPacketCredentialPosture     `json:"credential_posture"`
	ReadinessChecks       []risk.ProposedActionPrecondition         `json:"readiness_checks"`
	Effects               ActionContractPacketEffects               `json:"effects"`
	Confirmation          *risk.ProposedActionConfirmation          `json:"confirmation_requirement,omitempty"`
	Approval              *risk.ProposedActionApproval              `json:"approval_requirement,omitempty"`
	Compensation          *risk.ProposedActionCompensation          `json:"compensation_requirement,omitempty"`
	EvidenceGaps          []ActionContractPacketGap                 `json:"evidence_gaps"`
	LifecycleObservations []risk.ProposedActionLifecycleObservation `json:"lifecycle_observations"`
	Reachability          ActionContractPacketReachability          `json:"reachability"`
	NextStep              ActionContractPacketNextStep              `json:"next_step"`
	Truncations           []ActionContractPacketTruncation          `json:"truncations,omitempty"`
	Boundary              string                                    `json:"authority_boundary"`
	ReportOnly            bool                                      `json:"report_only"`
}

type ActionContractPacketIdentity struct {
	ArtifactID             string   `json:"artifact_id"`
	ContractID             string   `json:"contract_id"`
	ContractFamilyID       string   `json:"contract_family_id"`
	ContractContentDigest  string   `json:"contract_content_digest"`
	CanonicalContentDigest string   `json:"canonical_content_digest"`
	ContractVersion        string   `json:"contract_version"`
	Revision               int      `json:"revision"`
	SupersedesRef          string   `json:"supersedes_ref,omitempty"`
	ShareProfile           string   `json:"share_profile"`
	Redacted               bool     `json:"redacted"`
	SourceScanRefs         []string `json:"source_scan_refs"`
	CreationEvidence       []string `json:"creation_evidence"`
}

type ActionContractPacketPath struct {
	CompositionID string                      `json:"composition_id"`
	PatternID     string                      `json:"pattern_id,omitempty"`
	ResolutionKey string                      `json:"resolution_key,omitempty"`
	PathIDs       []string                    `json:"path_ids,omitempty"`
	Target        string                      `json:"target,omitempty"`
	TargetClass   string                      `json:"target_class,omitempty"`
	OutcomeClass  string                      `json:"outcome_class,omitempty"`
	Stages        []ActionContractPacketStage `json:"stages"`
}

type ActionContractPacketStage struct {
	StageID       string   `json:"stage_id"`
	Role          string   `json:"role"`
	ToolType      string   `json:"tool_type,omitempty"`
	Location      string   `json:"location,omitempty"`
	ActionClasses []string `json:"action_classes,omitempty"`
	TargetClass   string   `json:"target_class,omitempty"`
	EvidenceState string   `json:"evidence_state,omitempty"`
	Freshness     string   `json:"freshness_state,omitempty"`
}

type ActionContractPacketCredentialPosture struct {
	RequiredMode    string   `json:"required_mode,omitempty"`
	RequirementIDs  []string `json:"requirement_ids,omitempty"`
	EvidenceState   string   `json:"evidence_state"`
	FreshnessState  string   `json:"freshness_state"`
	ActivationGrant bool     `json:"activation_grant"`
}

type ActionContractPacketEffects struct {
	Expected  []string `json:"expected"`
	Forbidden []string `json:"forbidden"`
}

type ActionContractPacketGap struct {
	RequirementID string   `json:"requirement_id"`
	Kind          string   `json:"kind"`
	EvidenceState string   `json:"evidence_state"`
	Freshness     string   `json:"freshness_state"`
	ReasonCodes   []string `json:"reason_codes,omitempty"`
}

type ActionContractPacketReachability struct {
	ClaimState        string `json:"claim_state"`
	EvidenceState     string `json:"evidence_state"`
	FreshnessState    string `json:"freshness_state"`
	ObservedExecution bool   `json:"observed_execution"`
	BuyerLabel        string `json:"buyer_label"`
}

type ActionContractPacketNextStep struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
	Owner  string `json:"owner"`
}

type ActionContractPacketTruncation struct {
	Field        string `json:"field"`
	OmittedCount int    `json:"omitted_count,omitempty"`
	Reason       string `json:"reason"`
}

func BuildActionContractPacket(input ActionContractPacketInput) (ActionContractPacket, error) {
	contract := risk.CloneProposedActionContract(&input.Contract)
	if contract == nil || strings.TrimSpace(contract.ContractVersion) != risk.ProposedActionContractVersionV3 {
		return ActionContractPacket{}, fmt.Errorf("Action Contract packet requires one proposed Action Contract v3")
	}
	if strings.TrimSpace(input.ArtifactID) == "" || strings.TrimSpace(input.CanonicalContentDigest) == "" {
		return ActionContractPacket{}, fmt.Errorf("Action Contract packet requires portable artifact identity")
	}
	if strings.TrimSpace(input.Composition.CompositionID) == "" || strings.TrimSpace(input.Composition.CompositionID) != strings.TrimSpace(contract.CompositionRef) {
		return ActionContractPacket{}, fmt.Errorf("Action Contract packet composition does not match selected artifact")
	}

	truncations := make([]ActionContractPacketTruncation, 0)
	authority := normalizePacketAuthority(contract.AuthorityRequirements, &truncations)
	preconditions := normalizePacketPreconditions(contract.Preconditions, &truncations)
	lifecycle := normalizePacketLifecycle(contract.LifecycleObservations, &truncations)
	stages := normalizePacketStages(input.Composition.Stages, &truncations)
	gaps := packetEvidenceGaps(authority, preconditions, contract.ConfirmationRequirement, contract.ApprovalRequirement, contract.CompensationRequirement, lifecycle)
	if len(gaps) > actionContractPacketGapCap {
		truncations = append(truncations, ActionContractPacketTruncation{Field: "evidence_gaps", OmittedCount: len(gaps) - actionContractPacketGapCap, Reason: "item_cap"})
		gaps = gaps[:actionContractPacketGapCap]
	}

	identity := ActionContractPacketIdentity{
		ArtifactID:             strings.TrimSpace(input.ArtifactID),
		ContractID:             strings.TrimSpace(contract.ContractID),
		ContractFamilyID:       strings.TrimSpace(contract.ContractFamilyID),
		ContractContentDigest:  strings.TrimSpace(contract.ContractContentDigest),
		CanonicalContentDigest: strings.TrimSpace(input.CanonicalContentDigest),
		ContractVersion:        strings.TrimSpace(contract.ContractVersion),
		Revision:               contract.Revision,
		SupersedesRef:          strings.TrimSpace(contract.SupersedesRef),
		ShareProfile:           strings.TrimSpace(input.ShareProfile),
		Redacted:               input.ArtifactRedacted,
		SourceScanRefs:         capPacketStrings("identity.source_scan_refs", input.SourceScanRefs, actionContractPacketReferenceCap, &truncations),
		CreationEvidence:       capPacketStrings("identity.creation_evidence", input.CreationEvidence, actionContractPacketReferenceCap, &truncations),
	}
	packet := ActionContractPacket{
		SchemaID:      ActionContractPacketSchemaID,
		SchemaVersion: ActionContractPacketSchemaVersion,
		PacketID:      actionContractPacketID(identity.ArtifactID),
		Template:      ActionContractPacketTemplate,
		SectionOrder: []string{
			"identity", "path", "authority_requirements", "credential_posture", "readiness_checks", "effects", "confirmation_approval", "compensation", "evidence_gaps", "lifecycle_observations", "next_step",
		},
		Identity:              identity,
		Path:                  buildActionContractPacketPath(input.Composition, stages, &truncations),
		AffectedAsset:         truncatePacketValue("affected_asset", input.Composition.AffectedAsset, &truncations),
		AuthorityRequirements: authority,
		CredentialPosture:     packetCredentialPosture(contract, authority, preconditions),
		ReadinessChecks:       preconditions,
		Effects:               packetEffects(contract, preconditions),
		Confirmation:          clonePacketConfirmation(contract.ConfirmationRequirement, &truncations),
		Approval:              clonePacketApproval(contract.ApprovalRequirement, &truncations),
		Compensation:          clonePacketCompensation(contract.CompensationRequirement, &truncations),
		EvidenceGaps:          gaps,
		LifecycleObservations: lifecycle,
		Reachability:          packetReachability(input.Composition),
		Boundary:              "Wrkr proposes and reports this contract; Gait alone decides activation and runtime enforcement, and Axym verifies downstream evidence.",
		ReportOnly:            true,
	}
	packet.NextStep = packetNextStep(packet)
	packet.Truncations = normalizePacketTruncations(truncations)
	return packet, nil
}

func buildActionContractPacketPath(composition risk.ComposedActionPath, stages []ActionContractPacketStage, truncations *[]ActionContractPacketTruncation) ActionContractPacketPath {
	return ActionContractPacketPath{
		CompositionID: strings.TrimSpace(composition.CompositionID),
		PatternID:     strings.TrimSpace(composition.PatternID),
		ResolutionKey: truncatePacketValue("path.resolution_key", composition.ResolutionKey, truncations),
		PathIDs:       capPacketStrings("path.path_ids", composition.PathIDs, actionContractPacketReferenceCap, truncations),
		Target:        truncatePacketValue("path.target", composition.TargetIdentity, truncations),
		TargetClass:   strings.TrimSpace(composition.TargetClass),
		OutcomeClass:  strings.TrimSpace(composition.OutcomeClass),
		Stages:        stages,
	}
}

func normalizePacketAuthority(values []risk.ProposedActionRequirement, truncations *[]ActionContractPacketTruncation) []risk.ProposedActionRequirement {
	out := append(make([]risk.ProposedActionRequirement, 0, len(values)), values...)
	for index := range out {
		field := "authority_requirements." + strings.TrimSpace(out[index].RequirementID)
		out[index].RequiredConstraint = truncatePacketValue(field+".required_constraint", out[index].RequiredConstraint, truncations)
		out[index].ObservedValue = truncatePacketValue(field+".observed_value", out[index].ObservedValue, truncations)
		out[index].EvidenceRefs = capPacketStrings(field+".evidence_refs", out[index].EvidenceRefs, actionContractPacketReferenceCap, truncations)
		out[index].ReasonCodes = capPacketStrings(field+".reason_codes", out[index].ReasonCodes, actionContractPacketReferenceCap, truncations)
	}
	sort.Slice(out, func(i, j int) bool {
		left := strings.TrimSpace(out[i].Kind) + "|" + strings.TrimSpace(out[i].RequirementID)
		right := strings.TrimSpace(out[j].Kind) + "|" + strings.TrimSpace(out[j].RequirementID)
		return left < right
	})
	if len(out) > actionContractPacketRequirementCap {
		*truncations = append(*truncations, ActionContractPacketTruncation{Field: "authority_requirements", OmittedCount: len(out) - actionContractPacketRequirementCap, Reason: "item_cap"})
		out = out[:actionContractPacketRequirementCap]
	}
	return out
}

func normalizePacketPreconditions(values []risk.ProposedActionPrecondition, truncations *[]ActionContractPacketTruncation) []risk.ProposedActionPrecondition {
	out := append(make([]risk.ProposedActionPrecondition, 0, len(values)), values...)
	for index := range out {
		field := "readiness_checks." + strings.TrimSpace(out[index].RequirementID)
		out[index].RequiredConstraint = truncatePacketValue(field+".required_constraint", out[index].RequiredConstraint, truncations)
		out[index].ObservedValue = truncatePacketValue(field+".observed_value", out[index].ObservedValue, truncations)
		out[index].ObservedResult = truncatePacketValue(field+".observed_result", out[index].ObservedResult, truncations)
		out[index].AcceptableProducers = capPacketStrings(field+".acceptable_producers", out[index].AcceptableProducers, actionContractPacketReferenceCap, truncations)
		out[index].EvidenceRefs = capPacketStrings(field+".evidence_refs", out[index].EvidenceRefs, actionContractPacketReferenceCap, truncations)
		out[index].ReasonCodes = capPacketStrings(field+".reason_codes", out[index].ReasonCodes, actionContractPacketReferenceCap, truncations)
	}
	sort.Slice(out, func(i, j int) bool {
		left := strings.TrimSpace(out[i].Kind) + "|" + strings.TrimSpace(out[i].RequirementID)
		right := strings.TrimSpace(out[j].Kind) + "|" + strings.TrimSpace(out[j].RequirementID)
		return left < right
	})
	if len(out) > actionContractPacketPreconditionCap {
		*truncations = append(*truncations, ActionContractPacketTruncation{Field: "readiness_checks", OmittedCount: len(out) - actionContractPacketPreconditionCap, Reason: "item_cap"})
		out = out[:actionContractPacketPreconditionCap]
	}
	return out
}

func normalizePacketStages(values []risk.CompositionStage, truncations *[]ActionContractPacketTruncation) []ActionContractPacketStage {
	out := make([]ActionContractPacketStage, 0, len(values))
	for _, value := range values {
		field := "path.stages." + strings.TrimSpace(value.StageID)
		out = append(out, ActionContractPacketStage{
			StageID: strings.TrimSpace(value.StageID), Role: strings.TrimSpace(value.Role), ToolType: strings.TrimSpace(value.ToolType),
			Location:      truncatePacketValue(field+".location", value.Location, truncations),
			ActionClasses: capPacketStrings(field+".action_classes", value.ActionClasses, actionContractPacketReferenceCap, truncations),
			TargetClass:   strings.TrimSpace(value.TargetClass), EvidenceState: strings.TrimSpace(value.EvidenceState), Freshness: strings.TrimSpace(value.FreshnessState),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		left := fmt.Sprintf("%02d|%s", packetStageRoleRank(out[i].Role), out[i].StageID)
		right := fmt.Sprintf("%02d|%s", packetStageRoleRank(out[j].Role), out[j].StageID)
		return left < right
	})
	if len(out) > 5 {
		*truncations = append(*truncations, ActionContractPacketTruncation{Field: "path.stages", OmittedCount: len(out) - 5, Reason: "item_cap"})
		out = out[:5]
	}
	return out
}

func normalizePacketLifecycle(values []risk.ProposedActionLifecycleObservation, truncations *[]ActionContractPacketTruncation) []risk.ProposedActionLifecycleObservation {
	out := append(make([]risk.ProposedActionLifecycleObservation, 0, len(values)), values...)
	for index := range out {
		field := "lifecycle_observations." + strings.TrimSpace(out[index].ObservationID)
		out[index].EvidenceRefs = capPacketStrings(field+".evidence_refs", out[index].EvidenceRefs, actionContractPacketReferenceCap, truncations)
		out[index].ProofRefs = capPacketStrings(field+".proof_refs", out[index].ProofRefs, actionContractPacketReferenceCap, truncations)
		out[index].ReasonCodes = capPacketStrings(field+".reason_codes", out[index].ReasonCodes, actionContractPacketReferenceCap, truncations)
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.TrimSpace(out[i].Kind)+"|"+strings.TrimSpace(out[i].ObservationID) < strings.TrimSpace(out[j].Kind)+"|"+strings.TrimSpace(out[j].ObservationID)
	})
	if len(out) > actionContractPacketLifecycleCap {
		*truncations = append(*truncations, ActionContractPacketTruncation{Field: "lifecycle_observations", OmittedCount: len(out) - actionContractPacketLifecycleCap, Reason: "item_cap"})
		out = out[:actionContractPacketLifecycleCap]
	}
	return out
}

func packetEvidenceGaps(authority []risk.ProposedActionRequirement, preconditions []risk.ProposedActionPrecondition, confirmation *risk.ProposedActionConfirmation, approval *risk.ProposedActionApproval, compensation *risk.ProposedActionCompensation, lifecycle []risk.ProposedActionLifecycleObservation) []ActionContractPacketGap {
	gaps := make([]ActionContractPacketGap, 0)
	for _, item := range authority {
		if packetEvidenceNeedsAttention(item.EvidenceState, item.FreshnessState) {
			gaps = append(gaps, ActionContractPacketGap{RequirementID: item.RequirementID, Kind: "authority:" + item.Kind, EvidenceState: item.EvidenceState, Freshness: item.FreshnessState, ReasonCodes: append([]string(nil), item.ReasonCodes...)})
		}
	}
	for _, item := range preconditions {
		if packetEvidenceNeedsAttention(item.EvidenceState, item.FreshnessState) {
			gaps = append(gaps, ActionContractPacketGap{RequirementID: item.RequirementID, Kind: "precondition:" + item.Kind, EvidenceState: item.EvidenceState, Freshness: item.FreshnessState, ReasonCodes: append([]string(nil), item.ReasonCodes...)})
		}
	}
	if confirmation == nil {
		gaps = append(gaps, ActionContractPacketGap{RequirementID: "confirmation", Kind: "confirmation", EvidenceState: risk.EvidenceStateUnknown, Freshness: evidencepolicy.FreshnessStateUnknown, ReasonCodes: []string{"confirmation:missing"}})
	} else if confirmation.Required && packetEvidenceNeedsAttention(confirmation.EvidenceState, confirmation.FreshnessState) {
		gaps = append(gaps, ActionContractPacketGap{RequirementID: "confirmation", Kind: "confirmation", EvidenceState: confirmation.EvidenceState, Freshness: confirmation.FreshnessState, ReasonCodes: append([]string(nil), confirmation.ReasonCodes...)})
	}
	if approval == nil {
		gaps = append(gaps, ActionContractPacketGap{RequirementID: "approval", Kind: "approval", EvidenceState: risk.EvidenceStateUnknown, Freshness: evidencepolicy.FreshnessStateUnknown, ReasonCodes: []string{"approval:missing"}})
	} else if approval.Required && packetEvidenceNeedsAttention(approval.EvidenceState, approval.FreshnessState) {
		gaps = append(gaps, ActionContractPacketGap{RequirementID: "approval", Kind: "approval", EvidenceState: approval.EvidenceState, Freshness: approval.FreshnessState, ReasonCodes: append([]string(nil), approval.ReasonCodes...)})
	}
	if compensation == nil {
		gaps = append(gaps, ActionContractPacketGap{RequirementID: "compensation", Kind: "compensation", EvidenceState: risk.EvidenceStateUnknown, Freshness: evidencepolicy.FreshnessStateUnknown, ReasonCodes: []string{"compensation:missing"}})
	} else if compensation.Required && packetEvidenceNeedsAttention(compensation.EvidenceState, compensation.FreshnessState) {
		gaps = append(gaps, ActionContractPacketGap{RequirementID: "compensation", Kind: "compensation", EvidenceState: compensation.EvidenceState, Freshness: compensation.FreshnessState, ReasonCodes: append([]string(nil), compensation.ReasonCodes...)})
	}
	for _, item := range lifecycle {
		if strings.TrimSpace(item.EvidenceState) == risk.EvidenceStateContradictory {
			gaps = append(gaps, ActionContractPacketGap{RequirementID: item.ObservationID, Kind: "lifecycle:" + item.Kind, EvidenceState: item.EvidenceState, Freshness: item.FreshnessState, ReasonCodes: append([]string(nil), item.ReasonCodes...)})
		}
	}
	sort.Slice(gaps, func(i, j int) bool {
		return gaps[i].Kind+"|"+gaps[i].RequirementID < gaps[j].Kind+"|"+gaps[j].RequirementID
	})
	return gaps
}

func packetCredentialPosture(contract *risk.ProposedActionContract, authority []risk.ProposedActionRequirement, preconditions []risk.ProposedActionPrecondition) ActionContractPacketCredentialPosture {
	ids := make([]string, 0)
	state := risk.EvidenceStateUnknown
	freshness := evidencepolicy.FreshnessStateUnknown
	consider := func(id, evidenceState, freshnessState string) {
		ids = append(ids, strings.TrimSpace(id))
		if state == risk.EvidenceStateUnknown || packetEvidenceRank(evidenceState) < packetEvidenceRank(state) {
			state = strings.TrimSpace(evidenceState)
		}
		if freshness == evidencepolicy.FreshnessStateUnknown || packetFreshnessRank(freshnessState) < packetFreshnessRank(freshness) {
			freshness = strings.TrimSpace(freshnessState)
		}
	}
	for _, item := range authority {
		if strings.Contains(item.Kind, "credential") || strings.Contains(item.Kind, "requester_identity") {
			consider(item.RequirementID, item.EvidenceState, item.FreshnessState)
		}
	}
	for _, item := range preconditions {
		if item.Kind == "credential_mode" {
			consider(item.RequirementID, item.EvidenceState, item.FreshnessState)
		}
	}
	return ActionContractPacketCredentialPosture{RequiredMode: strings.TrimSpace(contract.RequiredCredentialMode), RequirementIDs: uniquePacketStrings(ids), EvidenceState: state, FreshnessState: freshness, ActivationGrant: false}
}

func packetEffects(contract *risk.ProposedActionContract, preconditions []risk.ProposedActionPrecondition) ActionContractPacketEffects {
	expected := []string{strings.TrimSpace(contract.ExpectedOutcomeClass)}
	forbidden := make([]string, 0)
	for _, item := range preconditions {
		switch item.Kind {
		case "expected_effect":
			expected = append(expected, firstPacketValue(item.ObservedValue, item.RequiredConstraint))
		case "forbidden_effect":
			forbidden = append(forbidden, firstPacketValue(item.ObservedValue, item.RequiredConstraint))
		}
	}
	return ActionContractPacketEffects{Expected: uniquePacketStrings(expected), Forbidden: uniquePacketStrings(forbidden)}
}

func packetReachability(composition risk.ComposedActionPath) ActionContractPacketReachability {
	observed := strings.TrimSpace(composition.ClaimState) == risk.CompositionClaimObservedExecution
	label := "possible static reachability; not observed execution"
	if observed {
		label = "observed execution backed by imported runtime evidence"
	}
	return ActionContractPacketReachability{ClaimState: strings.TrimSpace(composition.ClaimState), EvidenceState: strings.TrimSpace(composition.EvidenceState), FreshnessState: strings.TrimSpace(composition.FreshnessState), ObservedExecution: observed, BuyerLabel: label}
}

func packetNextStep(packet ActionContractPacket) ActionContractPacketNextStep {
	if len(packet.EvidenceGaps) > 0 {
		gap := packet.EvidenceGaps[0]
		return ActionContractPacketNextStep{Action: "Resolve " + gap.RequirementID + " before requesting a Gait activation decision.", Reason: gap.Kind + " remains " + firstPacketValue(gap.EvidenceState, risk.EvidenceStateUnknown), Owner: "contract owner"}
	}
	if len(packet.LifecycleObservations) > 0 {
		return ActionContractPacketNextStep{Action: "Verify the imported Gait lifecycle evidence and correlate it in Axym.", Reason: "downstream observations are evidence, not Wrkr-owned state transitions", Owner: "security reviewer"}
	}
	return ActionContractPacketNextStep{Action: "Submit this report-only proposal to Gait for independent validation and an activation decision.", Reason: "Wrkr does not activate or enforce Action Contracts", Owner: "contract owner"}
}

func clonePacketConfirmation(in *risk.ProposedActionConfirmation, truncations *[]ActionContractPacketTruncation) *risk.ProposedActionConfirmation {
	if in == nil {
		return nil
	}
	out := *in
	out.EvidenceRefs = capPacketStrings("confirmation_requirement.evidence_refs", in.EvidenceRefs, actionContractPacketReferenceCap, truncations)
	out.ReasonCodes = capPacketStrings("confirmation_requirement.reason_codes", in.ReasonCodes, actionContractPacketReferenceCap, truncations)
	return &out
}

func clonePacketApproval(in *risk.ProposedActionApproval, truncations *[]ActionContractPacketTruncation) *risk.ProposedActionApproval {
	if in == nil {
		return nil
	}
	out := *in
	out.ApproverRoles = capPacketStrings("approval_requirement.approver_roles", in.ApproverRoles, actionContractPacketReferenceCap, truncations)
	out.SeparationOfDuties = capPacketStrings("approval_requirement.separation_of_duties", in.SeparationOfDuties, actionContractPacketReferenceCap, truncations)
	out.ReapprovalTriggers = capPacketStrings("approval_requirement.reapproval_triggers", in.ReapprovalTriggers, actionContractPacketReferenceCap, truncations)
	out.EvidenceRefs = capPacketStrings("approval_requirement.evidence_refs", in.EvidenceRefs, actionContractPacketReferenceCap, truncations)
	out.ReasonCodes = capPacketStrings("approval_requirement.reason_codes", in.ReasonCodes, actionContractPacketReferenceCap, truncations)
	return &out
}

func clonePacketCompensation(in *risk.ProposedActionCompensation, truncations *[]ActionContractPacketTruncation) *risk.ProposedActionCompensation {
	if in == nil {
		return nil
	}
	out := *in
	out.ProcedureRef = truncatePacketValue("compensation_requirement.procedure_ref", in.ProcedureRef, truncations)
	out.Target = truncatePacketValue("compensation_requirement.target", in.Target, truncations)
	out.AcceptableProducers = capPacketStrings("compensation_requirement.acceptable_producers", in.AcceptableProducers, actionContractPacketReferenceCap, truncations)
	out.EvidenceRefs = capPacketStrings("compensation_requirement.evidence_refs", in.EvidenceRefs, actionContractPacketReferenceCap, truncations)
	out.ReasonCodes = capPacketStrings("compensation_requirement.reason_codes", in.ReasonCodes, actionContractPacketReferenceCap, truncations)
	return &out
}

func truncatePacketValue(field, raw string, truncations *[]ActionContractPacketTruncation) string {
	value := strings.TrimSpace(raw)
	value = strings.Join(strings.Fields(value), " ")
	if utf8.RuneCountInString(value) <= actionContractPacketValueRuneCap {
		return value
	}
	runes := []rune(value)
	keep := actionContractPacketValueRuneCap - utf8.RuneCountInString(ActionContractPacketTruncationMarker) - 1
	if keep < 1 {
		keep = 1
	}
	*truncations = append(*truncations, ActionContractPacketTruncation{Field: field, OmittedCount: len(runes) - keep, Reason: "value_rune_cap"})
	return strings.TrimSpace(string(runes[:keep])) + " " + ActionContractPacketTruncationMarker
}

func capPacketStrings(field string, values []string, capValue int, truncations *[]ActionContractPacketTruncation) []string {
	out := uniquePacketStrings(values)
	for index := range out {
		out[index] = truncatePacketValue(field, out[index], truncations)
	}
	out = uniquePacketStrings(out)
	if len(out) > capValue {
		*truncations = append(*truncations, ActionContractPacketTruncation{Field: field, OmittedCount: len(out) - capValue, Reason: "item_cap"})
		out = out[:capValue]
	}
	return out
}

func normalizePacketTruncations(values []ActionContractPacketTruncation) []ActionContractPacketTruncation {
	byKey := map[string]ActionContractPacketTruncation{}
	for _, value := range values {
		key := value.Field + "|" + value.Reason
		current := byKey[key]
		value.OmittedCount += current.OmittedCount
		byKey[key] = value
	}
	out := make([]ActionContractPacketTruncation, 0, len(byKey))
	for _, value := range byKey {
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Field+"|"+out[i].Reason < out[j].Field+"|"+out[j].Reason })
	return out
}

func uniquePacketStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func packetEvidenceNeedsAttention(state, freshness string) bool {
	return strings.TrimSpace(state) != risk.EvidenceStateVerified || strings.TrimSpace(freshness) != evidencepolicy.FreshnessStateFresh
}

func packetEvidenceRank(value string) int {
	switch strings.TrimSpace(value) {
	case risk.EvidenceStateContradictory:
		return 0
	case risk.EvidenceStateUnknown:
		return 1
	case risk.EvidenceStateInferred:
		return 2
	case risk.EvidenceStateDeclared:
		return 3
	case risk.EvidenceStateVerified:
		return 4
	default:
		return 0
	}
}

func packetFreshnessRank(value string) int {
	switch strings.TrimSpace(value) {
	case evidencepolicy.FreshnessStateExpired:
		return 0
	case evidencepolicy.FreshnessStateStale:
		return 1
	case evidencepolicy.FreshnessStateUnknown:
		return 2
	case evidencepolicy.FreshnessStateFresh:
		return 3
	default:
		return 0
	}
}

func packetStageRoleRank(role string) int {
	switch strings.TrimSpace(role) {
	case risk.CompositionStageRoleSource:
		return 0
	case risk.CompositionStageRoleTransform:
		return 1
	case risk.CompositionStageRoleInternalSink:
		return 2
	case risk.CompositionStageRoleSink:
		return 3
	case risk.CompositionStageRoleExternalSink:
		return 4
	case risk.CompositionStageRolePrivilegedSink:
		return 5
	case risk.CompositionStageRoleDestructiveSink:
		return 6
	default:
		return 7
	}
}

func actionContractPacketID(artifactID string) string {
	digest := sha256.Sum256([]byte("wrkr:action-contract-packet:v1:" + strings.TrimSpace(artifactID)))
	return "pacpkt-" + hex.EncodeToString(digest[:8])
}

func firstPacketValue(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
