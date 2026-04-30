package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/aggregate/controlbacklog"
	"github.com/Clyra-AI/wrkr/core/ingest"
)

type EvidenceBundle struct {
	ReportBundleVersion string                      `json:"report_bundle_version"`
	GeneratedAt         string                      `json:"generated_at"`
	Template            string                      `json:"template"`
	ShareProfile        string                      `json:"share_profile"`
	ControlBacklog      *controlbacklog.Backlog     `json:"control_backlog,omitempty"`
	ControlPathGraph    *aggattack.ControlPathGraph `json:"control_path_graph,omitempty"`
	RuntimeEvidence     *ingest.Summary             `json:"runtime_evidence,omitempty"`
	AgentActionBOM      *AgentActionBOM             `json:"agent_action_bom,omitempty"`
	ComplianceSummary   any                         `json:"compliance_summary"`
	Proof               ProofReference              `json:"proof"`
	NextActions         []ChecklistItem             `json:"next_actions"`
}

func BuildEvidenceBundle(summary Summary) EvidenceBundle {
	return EvidenceBundle{
		ReportBundleVersion: "1",
		GeneratedAt:         summary.GeneratedAt,
		Template:            summary.Template,
		ShareProfile:        summary.ShareProfile,
		ControlBacklog:      summary.ControlBacklog,
		ControlPathGraph:    summary.ControlPathGraph,
		RuntimeEvidence:     summary.RuntimeEvidence,
		AgentActionBOM:      summary.AgentActionBOM,
		ComplianceSummary:   summary.ComplianceSummary,
		Proof:               summary.Proof,
		NextActions:         append([]ChecklistItem(nil), summary.NextActions...),
	}
}

func RenderEvidenceBundleJSON(summary Summary) ([]byte, error) {
	payload, err := json.MarshalIndent(BuildEvidenceBundle(summary), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
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
