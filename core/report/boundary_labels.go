package report

import (
	"strings"

	aggattack "github.com/Clyra-AI/wrkr/core/aggregate/attackpath"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const (
	BoundaryLabelDiscoveryOnly      = "discovery_only"
	BoundaryLabelReportOnly         = "report_only"
	BoundaryLabelApprovalCapable    = "approval_capable"
	BoundaryLabelEnforcementCapable = "enforcement_capable"
)

func decorateBoundaryLabelsForReport(
	paths []risk.ActionPath,
	runtimeByPath map[string]ingest.Correlation,
	sessionByPath map[string]sessionProjection,
	packetByPath map[string]evidencePacketProjection,
) []risk.ActionPath {
	if len(paths) == 0 {
		return nil
	}
	out := append([]risk.ActionPath(nil), paths...)
	for idx := range out {
		pathID := strings.TrimSpace(out[idx].PathID)
		out[idx].BoundaryLabel = deriveBoundaryLabel(out[idx], runtimeByPath[pathID], sessionByPath[pathID], packetByPath[pathID])
	}
	return out
}

func decorateRuntimeEvidenceSummaryBoundary(summary *ingest.Summary, paths []risk.ActionPath) *ingest.Summary {
	if summary == nil {
		return nil
	}
	pathLabels := boundaryLabelByPath(paths)
	out := *summary
	out.Correlations = append([]ingest.Correlation(nil), summary.Correlations...)
	label := BoundaryLabelReportOnly
	for idx := range out.Correlations {
		copyItem := out.Correlations[idx]
		copyItem.BoundaryLabel = strongestBoundaryLabel(copyItem.BoundaryLabel, firstNonEmptyValue(pathLabels[strings.TrimSpace(copyItem.PathID)], BoundaryLabelReportOnly))
		label = strongestBoundaryLabel(label, copyItem.BoundaryLabel)
		out.Correlations[idx] = copyItem
	}
	out.BoundaryLabel = label
	return &out
}

func decorateEvidencePacketSummaryBoundary(summary *ingest.EvidencePacketSummary, paths []risk.ActionPath) *ingest.EvidencePacketSummary {
	if summary == nil {
		return nil
	}
	pathLabels := boundaryLabelByPath(paths)
	out := *summary
	out.Correlations = append([]ingest.EvidencePacketCorrelation(nil), summary.Correlations...)
	label := BoundaryLabelReportOnly
	for idx := range out.Correlations {
		copyItem := out.Correlations[idx]
		copyItem.BoundaryLabel = strongestBoundaryLabel(copyItem.BoundaryLabel, firstNonEmptyValue(pathLabels[strings.TrimSpace(copyItem.PathID)], BoundaryLabelReportOnly))
		label = strongestBoundaryLabel(label, copyItem.BoundaryLabel)
		out.Correlations[idx] = copyItem
	}
	out.BoundaryLabel = label
	return &out
}

func decorateSessionSummaryBoundary(summary *ingest.SessionSummary, paths []risk.ActionPath) *ingest.SessionSummary {
	if summary == nil {
		return nil
	}
	pathLabels := boundaryLabelByPath(paths)
	out := *summary
	out.Correlations = append([]ingest.SessionCorrelation(nil), summary.Correlations...)
	label := BoundaryLabelReportOnly
	for idx := range out.Correlations {
		copyItem := out.Correlations[idx]
		copyItem.BoundaryLabel = strongestBoundaryLabel(copyItem.BoundaryLabel, firstNonEmptyValue(pathLabels[strings.TrimSpace(copyItem.PathID)], BoundaryLabelReportOnly))
		label = strongestBoundaryLabel(label, copyItem.BoundaryLabel)
		out.Correlations[idx] = copyItem
	}
	out.BoundaryLabel = label
	return &out
}

func decorateControlPathGraphBoundary(graph *aggattack.ControlPathGraph, paths []risk.ActionPath) *aggattack.ControlPathGraph {
	if graph == nil {
		return nil
	}
	pathLabels := boundaryLabelByPath(paths)
	out := *graph
	out.Nodes = append([]aggattack.ControlPathNode(nil), graph.Nodes...)
	out.Edges = append([]aggattack.ControlPathEdge(nil), graph.Edges...)
	for idx := range out.Nodes {
		out.Nodes[idx].BoundaryLabel = firstNonEmptyValue(pathLabels[strings.TrimSpace(out.Nodes[idx].PathID)], BoundaryLabelReportOnly)
	}
	for idx := range out.Edges {
		out.Edges[idx].BoundaryLabel = firstNonEmptyValue(pathLabels[strings.TrimSpace(out.Edges[idx].PathID)], BoundaryLabelReportOnly)
	}
	return &out
}

func boundaryLabelByPath(paths []risk.ActionPath) map[string]string {
	out := map[string]string{}
	for _, path := range paths {
		if strings.TrimSpace(path.PathID) == "" {
			continue
		}
		out[strings.TrimSpace(path.PathID)] = firstNonEmptyValue(strings.TrimSpace(path.BoundaryLabel), BoundaryLabelReportOnly)
	}
	return out
}

func deriveBoundaryLabel(
	path risk.ActionPath,
	runtime ingest.Correlation,
	session sessionProjection,
	packet evidencePacketProjection,
) string {
	switch {
	case pathHasEnforcementEvidence(path):
		return BoundaryLabelEnforcementCapable
	case pathHasApprovalEvidence(path, runtime, session, packet):
		return BoundaryLabelApprovalCapable
	case pathHasReportLevelClaims(path):
		return BoundaryLabelReportOnly
	default:
		return BoundaryLabelDiscoveryOnly
	}
}

func pathHasReportLevelClaims(path risk.ActionPath) bool {
	return strings.TrimSpace(path.ControlPriority) != "" ||
		strings.TrimSpace(path.RecommendedAction) != "" ||
		strings.TrimSpace(path.ControlState) != "" ||
		path.WriteCapable ||
		path.CredentialAccess ||
		path.ProductionWrite ||
		len(path.ActionClasses) > 0
}

func pathHasApprovalEvidence(path risk.ActionPath, runtime ingest.Correlation, session sessionProjection, packet evidencePacketProjection) bool {
	if path.GaitCoverage != nil && gaitDetailPresent(path.GaitCoverage.Approval) {
		return true
	}
	if strings.TrimSpace(runtime.Status) == ingest.CorrelationStatusMatched && (containsEvidenceClass(runtime.EvidenceClasses, ingest.EvidenceClassApproval) || containsEvidenceClass(runtime.EvidenceClasses, ingest.EvidenceClassPolicyDecision)) {
		return true
	}
	if strings.TrimSpace(session.Status) == ingest.CorrelationStatusMatched && len(session.SessionRefs) > 0 {
		return true
	}
	return strings.TrimSpace(packet.Status) == ingest.CorrelationStatusMatched && len(packet.PacketRefs) > 0
}

func pathHasEnforcementEvidence(path risk.ActionPath) bool {
	if strings.TrimSpace(path.DelegationReadinessState) != risk.DelegationReadinessReadyForControl || path.GaitCoverage == nil {
		return false
	}
	return gaitDetailPresent(path.GaitCoverage.PolicyDecision) ||
		(gaitDetailPresent(path.GaitCoverage.KillSwitch) && gaitContainmentConfirmed(path.GaitCoverage.Containment)) ||
		gaitDetailPresent(path.GaitCoverage.FreezeWindow) ||
		gaitDetailPresent(path.GaitCoverage.JITCredential)
}

func gaitContainmentConfirmed(coverage *risk.ContainmentCoverage) bool {
	return coverage != nil &&
		strings.TrimSpace(coverage.Status) == risk.ContainmentCoverageContained &&
		len(coverage.ScopeRefs) > 0 &&
		gaitDetailPresent(coverage.ContainmentReceipt) &&
		(gaitDetailPresent(coverage.CoveredActionDenial) || gaitDetailPresent(coverage.CapabilityInvalidation))
}

func gaitDetailPresent(detail risk.GaitCoverageDetail) bool {
	return strings.TrimSpace(detail.Status) == risk.GaitStatusPresent
}

func strongestBoundaryLabel(current, incoming string) string {
	if boundaryLabelRank(incoming) > boundaryLabelRank(current) {
		return strings.TrimSpace(incoming)
	}
	if strings.TrimSpace(current) != "" {
		return strings.TrimSpace(current)
	}
	return strings.TrimSpace(incoming)
}

func boundaryLabelRank(value string) int {
	switch strings.TrimSpace(value) {
	case BoundaryLabelEnforcementCapable:
		return 4
	case BoundaryLabelApprovalCapable:
		return 3
	case BoundaryLabelReportOnly:
		return 2
	case BoundaryLabelDiscoveryOnly:
		return 1
	default:
		return 0
	}
}
