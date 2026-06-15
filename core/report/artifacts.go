package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"strings"

	"github.com/Clyra-AI/wrkr/core/aggregate/agentresolver"
	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	"github.com/Clyra-AI/wrkr/core/ingest"
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
	AgentActionBOM         *AgentActionBOM                      `json:"agent_action_bom,omitempty"`
	ComplianceSummary      any                                  `json:"compliance_summary"`
	Proof                  ProofReference                       `json:"proof"`
	NextActions            []ChecklistItem                      `json:"next_actions"`
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
		AgentActionBOM:         summary.AgentActionBOM,
		ComplianceSummary:      summary.ComplianceSummary,
		Proof:                  summary.Proof,
		NextActions:            append([]ChecklistItem(nil), summary.NextActions...),
	}
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
