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
	if runtimeEvidence == nil {
		return out
	}
	byPath := map[string]ingest.Correlation{}
	for _, item := range runtimeEvidence.Correlations {
		if strings.TrimSpace(item.PathID) == "" {
			continue
		}
		byPath[strings.TrimSpace(item.PathID)] = item
	}
	for i := range out {
		item, ok := byPath[strings.TrimSpace(out[i].PathID)]
		if !ok {
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
	}
	return out
}

func decorateControlFirstForReport(controlFirst *risk.ActionPathToControlFirst, paths []risk.ActionPath) *risk.ActionPathToControlFirst {
	if controlFirst == nil {
		return nil
	}
	out := *controlFirst
	for _, path := range paths {
		if strings.TrimSpace(path.PathID) == strings.TrimSpace(out.Path.PathID) {
			out.Path = path
			return &out
		}
	}
	return &out
}

func containsEvidenceClass(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(want) {
			return true
		}
	}
	return false
}
