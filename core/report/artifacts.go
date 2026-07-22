package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
)

type EvidenceBundle struct {
	ReportBundleVersion    string                               `json:"report_bundle_version"`
	GeneratedAt            string                               `json:"generated_at"`
	Template               string                               `json:"template"`
	ShareProfile           string                               `json:"share_profile"`
	DeploymentMode         string                               `json:"deployment_mode,omitempty"`
	ShareProfileMetadata   *ShareProfileMetadata                `json:"share_profile_metadata,omitempty"`
	ArtifactMetadata       *ArtifactMetadata                    `json:"artifact_metadata,omitempty"`
	ArtifactBudget         *ArtifactBudget                      `json:"artifact_budget,omitempty"`
	AppendixAvailable      bool                                 `json:"appendix_available,omitempty"`
	FocusedBundleAvailable bool                                 `json:"focused_bundle_available,omitempty"`
	FullExportAvailable    bool                                 `json:"full_export_available,omitempty"`
	SuppressedCounts       *SuppressedCounts                    `json:"suppressed_counts,omitempty"`
	ControlBacklog         *controlbacklog.Backlog              `json:"control_backlog,omitempty"`
	ExecutiveRollup        *controlbacklog.ExecutiveRollup      `json:"executive_rollup,omitempty"`
	GovernedUsageMetrics   *controlbacklog.GovernedUsageMetrics `json:"governed_usage_metrics,omitempty"`
	ControlPathGraph       *aggattack.ControlPathGraph          `json:"control_path_graph,omitempty"`
	WorkflowChains         *agentresolver.WorkflowChainArtifact `json:"workflow_chains,omitempty"`
	ActionSurfaceRegistry  []ActionSurfaceRegistryEntry         `json:"action_surface_registry,omitempty"`
	RuntimeSessions        *ingest.SessionSummary               `json:"runtime_sessions,omitempty"`
	RuntimeEvidence        *ingest.Summary                      `json:"runtime_evidence,omitempty"`
	EvidencePackets        *ingest.EvidencePacketSummary        `json:"evidence_packets,omitempty"`
	CompositionRefs        []CompositionCorrelationRef          `json:"composition_refs,omitempty"`
	AgentActionBOM         *AgentActionBOM                      `json:"agent_action_bom,omitempty"`
	ComplianceSummary      any                                  `json:"compliance_summary"`
	Proof                  ProofReference                       `json:"proof"`
	NextActions            []ChecklistItem                      `json:"next_actions"`
}

type CompositionCorrelationRef struct {
	CompositionID              string            `json:"composition_id"`
	ResolutionKey              string            `json:"resolution_key,omitempty"`
	PatternID                  string            `json:"pattern_id,omitempty"`
	PathIDs                    []string          `json:"path_ids,omitempty"`
	WorkflowChainRefs          []string          `json:"workflow_chain_refs,omitempty"`
	ProposedActionContractRefs []string          `json:"proposed_action_contract_refs,omitempty"`
	RecommendedControl         string            `json:"recommended_control,omitempty"`
	EvidenceState              string            `json:"evidence_state,omitempty"`
	PolicyCoverageStatus       string            `json:"policy_coverage_status,omitempty"`
	GaitCoverageSummary        map[string]string `json:"gait_coverage_summary,omitempty"`
	ProposedActionContractID   string            `json:"proposed_action_contract_id,omitempty"`
	ContractFamilyID           string            `json:"contract_family_id,omitempty"`
	ContractRevision           int               `json:"contract_revision,omitempty"`
	ContractContentDigest      string            `json:"contract_content_digest,omitempty"`
	SupersedesRef              string            `json:"supersedes_ref,omitempty"`
	ActionContractArtifactRefs []string          `json:"action_contract_artifact_refs,omitempty"`
	LifecycleObservationRefs   []string          `json:"lifecycle_observation_refs,omitempty"`
}

func BuildEvidenceBundle(summary Summary) EvidenceBundle {
	summary = FinalizeSummaryForSerialization(summary)
	return EvidenceBundle{
		ReportBundleVersion:    "1",
		GeneratedAt:            summary.GeneratedAt,
		Template:               summary.Template,
		ShareProfile:           summary.ShareProfile,
		DeploymentMode:         summary.DeploymentMode,
		ShareProfileMetadata:   cloneShareProfileMetadata(summary.ShareProfileMetadata),
		ArtifactMetadata:       cloneArtifactMetadata(summary.ArtifactMetadata),
		ArtifactBudget:         cloneArtifactBudget(summary.ArtifactBudget),
		AppendixAvailable:      summary.AppendixAvailable,
		FocusedBundleAvailable: summary.FocusedBundleAvailable,
		FullExportAvailable:    summary.FullExportAvailable,
		SuppressedCounts:       cloneSuppressedCounts(summary.SuppressedCounts),
		ControlBacklog:         summary.ControlBacklog,
		ExecutiveRollup:        summary.ExecutiveRollup,
		GovernedUsageMetrics:   summary.GovernedUsageMetrics,
		ControlPathGraph:       summary.ControlPathGraph,
		WorkflowChains:         summary.WorkflowChains,
		ActionSurfaceRegistry:  append([]ActionSurfaceRegistryEntry(nil), summary.ActionSurfaceRegistry...),
		RuntimeSessions:        summary.RuntimeSessions,
		RuntimeEvidence:        summary.RuntimeEvidence,
		EvidencePackets:        summary.EvidencePackets,
		CompositionRefs:        buildCompositionCorrelationRefs(summary),
		AgentActionBOM:         summary.AgentActionBOM,
		ComplianceSummary:      summary.ComplianceSummary,
		Proof:                  summary.Proof,
		NextActions:            append([]ChecklistItem(nil), summary.NextActions...),
	}
}

func buildCompositionCorrelationRefs(summary Summary) []CompositionCorrelationRef {
	compositions := append([]risk.ComposedActionPath(nil), summary.ComposedActionPaths...)
	if len(compositions) == 0 && summary.AgentActionBOM != nil {
		compositions = append([]risk.ComposedActionPath(nil), summary.AgentActionBOM.ComposedActionPaths...)
	}
	if len(compositions) == 0 {
		return nil
	}
	refsByID := map[string]CompositionCorrelationRef{}
	for _, composition := range compositions {
		compositionID := strings.TrimSpace(composition.CompositionID)
		if compositionID == "" {
			continue
		}
		ref := refsByID[compositionID]
		ref.CompositionID = compositionID
		ref.ResolutionKey = firstNonEmptyValue(ref.ResolutionKey, strings.TrimSpace(composition.ResolutionKey))
		ref.PatternID = firstNonEmptyValue(ref.PatternID, strings.TrimSpace(composition.PatternID))
		ref.PathIDs = uniqueSortedStrings(append(ref.PathIDs, composition.PathIDs...))
		ref.WorkflowChainRefs = uniqueSortedStrings(append(ref.WorkflowChainRefs, composition.WorkflowChainRefs...))
		ref.ProposedActionContractRefs = uniqueSortedStrings(append(ref.ProposedActionContractRefs, composition.ProposedActionContractRefs...))
		ref.RecommendedControl = firstNonEmptyValue(ref.RecommendedControl, strings.TrimSpace(composition.RecommendedControl))
		ref.EvidenceState = firstNonEmptyValue(ref.EvidenceState, strings.TrimSpace(composition.EvidenceState))
		ref.PolicyCoverageStatus = firstNonEmptyValue(ref.PolicyCoverageStatus, strings.TrimSpace(composition.PolicyCoverageStatus))
		if gaitCoverage := compositionGaitCoverageSummary(composition.GaitCoverage); len(gaitCoverage) > 0 {
			ref.GaitCoverageSummary = gaitCoverage
		}
		if contract := composition.ProposedActionContract; contract != nil {
			ref.ProposedActionContractID = firstNonEmptyValue(ref.ProposedActionContractID, strings.TrimSpace(contract.ContractID))
			ref.ContractFamilyID = firstNonEmptyValue(ref.ContractFamilyID, strings.TrimSpace(contract.ContractFamilyID))
			if ref.ContractRevision == 0 {
				ref.ContractRevision = contract.Revision
			}
			ref.ContractContentDigest = firstNonEmptyValue(ref.ContractContentDigest, strings.TrimSpace(contract.ContractContentDigest))
			ref.SupersedesRef = firstNonEmptyValue(ref.SupersedesRef, strings.TrimSpace(contract.SupersedesRef))
			for _, observation := range contract.LifecycleObservations {
				ref.LifecycleObservationRefs = append(ref.LifecycleObservationRefs, observation.ObservationID)
				ref.ActionContractArtifactRefs = append(ref.ActionContractArtifactRefs, lifecycleActionContractArtifactRefs(observation)...)
			}
			ref.LifecycleObservationRefs = uniqueSortedStrings(ref.LifecycleObservationRefs)
			ref.ActionContractArtifactRefs = uniqueSortedStrings(ref.ActionContractArtifactRefs)
		}
		refsByID[compositionID] = ref
	}
	if len(refsByID) == 0 {
		return nil
	}
	ids := make([]string, 0, len(refsByID))
	for id := range refsByID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]CompositionCorrelationRef, 0, len(ids))
	for _, id := range ids {
		out = append(out, refsByID[id])
	}
	return out
}

func lifecycleActionContractArtifactRefs(observation risk.ProposedActionLifecycleObservation) []string {
	if len(observation.ActionContractArtifactRefs) > 0 {
		return uniqueSortedStrings(observation.ActionContractArtifactRefs)
	}
	refs := []string{}
	for _, ref := range observation.EvidenceRefs {
		if looksActionContractArtifactRef(ref) {
			refs = append(refs, ref)
		}
	}
	return uniqueSortedStrings(refs)
}

func looksActionContractArtifactRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	switch {
	case strings.HasPrefix(ref, "paca-"):
		return true
	case strings.HasPrefix(ref, "axym:artifact:"):
		return true
	case strings.HasPrefix(ref, "axym:bundle:"):
		return true
	default:
		return false
	}
}

func compositionGaitCoverageSummary(coverage *risk.GaitCoverage) map[string]string {
	if coverage == nil {
		return nil
	}
	out := map[string]string{
		"policy_decision":    strings.TrimSpace(coverage.PolicyDecision.Status),
		"approval":           strings.TrimSpace(coverage.Approval.Status),
		"jit_credential":     strings.TrimSpace(coverage.JITCredential.Status),
		"freeze_window":      strings.TrimSpace(coverage.FreezeWindow.Status),
		"kill_switch":        strings.TrimSpace(coverage.KillSwitch.Status),
		"action_outcome":     strings.TrimSpace(coverage.ActionOutcome.Status),
		"proof_verification": strings.TrimSpace(coverage.ProofVerification.Status),
	}
	for key, value := range out {
		if value == "" {
			delete(out, key)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func RenderEvidenceBundleJSON(summary Summary) ([]byte, error) {
	var buf bytes.Buffer
	if err := encodeEvidenceBundleJSON(&buf, summary); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func WriteEvidenceBundleJSON(path string, summary Summary) error {
	if err := atomicwrite.WriteFileFunc(path, 0o600, func(w io.Writer) error {
		return encodeEvidenceBundleJSON(w, summary)
	}); err != nil {
		return err
	}
	return nil
}

func encodeEvidenceBundleJSON(w io.Writer, summary Summary) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(BuildEvidenceBundle(summary)); err != nil {
		return err
	}
	return nil
}

func RenderBacklogCSV(backlog *controlbacklog.Backlog) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	if err := writer.Write([]string{"id", "repo", "path", "owner", "evidence", "recommended_action", "sla", "closure_criteria"}); err != nil {
		return nil, err
	}
	if backlog != nil {
		for _, item := range backlog.Items {
			if err := writer.Write([]string{
				strings.TrimSpace(item.ID),
				strings.TrimSpace(item.Repo),
				strings.TrimSpace(item.Path),
				strings.TrimSpace(item.Owner),
				strings.Join(item.EvidenceBasis, ";"),
				strings.TrimSpace(item.RecommendedAction),
				strings.TrimSpace(item.SLA),
				strings.TrimSpace(item.ClosureCriteria),
			}); err != nil {
				return nil, err
			}
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
