package report

import (
	"strings"

	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func decorateActionPathsForReport(paths []risk.ActionPath, runtimeEvidence *ingest.Summary) []risk.ActionPath {
	if len(paths) == 0 {
		return nil
	}
	out := append([]risk.ActionPath(nil), paths...)
	byPath := map[string]ingest.Correlation{}
	if runtimeEvidence != nil {
		for _, item := range runtimeEvidence.Correlations {
			if strings.TrimSpace(item.PathID) == "" {
				continue
			}
			byPath[strings.TrimSpace(item.PathID)] = item
		}
	}
	for i := range out {
		item, ok := byPath[strings.TrimSpace(out[i].PathID)]
		if len(out[i].ConstraintEvidenceRefs) > 0 {
			out[i].PolicyEvidenceRefs = uniqueSortedStrings(append(append([]string(nil), out[i].PolicyEvidenceRefs...), out[i].ConstraintEvidenceRefs...))
		}
		if pathHasPolicyConstraintEvidence(out[i]) {
			switch strings.TrimSpace(out[i].ConstraintEvidenceStatus) {
			case "conflict":
				out[i].PolicyCoverageStatus = risk.PolicyCoverageStatusConflict
				out[i].PolicyStatusReasons = uniqueSortedStrings(append(append([]string(nil), out[i].PolicyStatusReasons...), "constraint_evidence_conflict"))
				out[i].PolicyConfidence = "high"
			case "stale":
				out[i].PolicyCoverageStatus = risk.PolicyCoverageStatusStale
				out[i].PolicyStatusReasons = uniqueSortedStrings(append(append([]string(nil), out[i].PolicyStatusReasons...), "constraint_evidence_stale"))
				out[i].PolicyConfidence = "medium"
			case "unmatched":
				out[i].PolicyStatusReasons = uniqueSortedStrings(append(append([]string(nil), out[i].PolicyStatusReasons...), "constraint_evidence_unmatched"))
			default:
				if strings.TrimSpace(out[i].PolicyCoverageStatus) == "" || strings.TrimSpace(out[i].PolicyCoverageStatus) == risk.PolicyCoverageStatusNone {
					out[i].PolicyCoverageStatus = risk.PolicyCoverageStatusMatched
				}
				out[i].PolicyStatusReasons = uniqueSortedStrings(append(append([]string(nil), out[i].PolicyStatusReasons...), "constraint_policy_attached"))
				if strings.TrimSpace(out[i].PolicyConfidence) == "" {
					out[i].PolicyConfidence = "high"
				}
			}
		}
		if !ok {
			out[i].GaitCoverage = gaitCoverageForPath(out[i], ingest.Correlation{})
			continue
		}
		out[i].PolicyRefs = uniqueSortedStrings(append(append([]string(nil), out[i].PolicyRefs...), item.PolicyRefs...))
		out[i].PolicyEvidenceRefs = uniqueSortedStrings(append(append([]string(nil), out[i].PolicyEvidenceRefs...), item.RecordIDs...))
		switch strings.TrimSpace(item.Status) {
		case ingest.CorrelationStatusConflict:
			out[i].PolicyCoverageStatus = risk.PolicyCoverageStatusConflict
			out[i].PolicyStatusReasons = uniqueSortedStrings(append(append([]string(nil), out[i].PolicyStatusReasons...), "runtime_evidence_conflict"))
			out[i].PolicyConfidence = "high"
		case ingest.CorrelationStatusMatched:
			if containsEvidenceClass(item.EvidenceClasses, ingest.EvidenceClassPolicyDecision) {
				out[i].PolicyCoverageStatus = risk.PolicyCoverageStatusRuntimeProven
				out[i].PolicyStatusReasons = uniqueSortedStrings(append(append([]string(nil), out[i].PolicyStatusReasons...), "runtime_policy_decision_attached"))
				out[i].PolicyConfidence = "high"
			}
		case ingest.CorrelationStatusStale:
			out[i].PolicyCoverageStatus = risk.PolicyCoverageStatusStale
			out[i].PolicyStatusReasons = uniqueSortedStrings(append(append([]string(nil), out[i].PolicyStatusReasons...), "runtime_evidence_stale"))
			out[i].PolicyConfidence = "medium"
		}
		out[i].GaitCoverage = gaitCoverageForPath(out[i], item)
	}
	return risk.ProjectActionPaths(out)
}

func decorateControlFirstForReport(paths []risk.ActionPath, scanCoverageReduced bool) *risk.ActionPathToControlFirst {
	if len(paths) == 0 {
		return nil
	}
	return &risk.ActionPathToControlFirst{
		Summary: risk.SummarizeActionPaths(paths, risk.ActionPathSummaryOptions{
			ScanCoverageReduced: scanCoverageReduced,
		}),
		Path: paths[0],
	}
}

func containsEvidenceClass(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}

func pathHasPolicyConstraintEvidence(path risk.ActionPath) bool {
	for _, class := range path.ConstraintEvidenceClasses {
		switch strings.TrimSpace(class) {
		case "branch_protection", "required_check", "security_gate", "policy_record":
			return true
		}
	}
	return false
}
