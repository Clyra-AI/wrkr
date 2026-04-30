package risk

import (
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/model"
)

const (
	PolicyCoverageStatusNone          = "none"
	PolicyCoverageStatusDeclared      = "declared"
	PolicyCoverageStatusMatched       = "matched"
	PolicyCoverageStatusRuntimeProven = "runtime_proven"
	PolicyCoverageStatusStale         = "stale"
	PolicyCoverageStatusConflict      = "conflict"

	policyConfidenceHigh   = "high"
	policyConfidenceMedium = "medium"
	policyConfidenceLow    = "low"
)

func DecoratePolicyCoverage(paths []ActionPath, findings []model.Finding) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	if len(findings) == 0 {
		out := append([]ActionPath(nil), paths...)
		for i := range out {
			out[i] = decoratePolicyCoverageForPath(out[i], nil, false, nil)
		}
		return out
	}

	byRepoLocation := map[string][]string{}
	byRepo := map[string][]string{}
	policyFilesByRepo := map[string][]string{}
	for _, finding := range findings {
		repoKey := repoKey(finding.Org, finding.Repo)
		if strings.TrimSpace(repoKey) == "::" {
			continue
		}
		if strings.TrimSpace(finding.ToolType) == "gait_policy" && strings.TrimSpace(finding.FindingType) == "tool_config" {
			policyFilesByRepo[repoKey] = mergePolicyStrings(policyFilesByRepo[repoKey], []string{strings.TrimSpace(finding.Location)})
		}
		refs := collectPolicyRefs(finding)
		if len(refs) == 0 {
			continue
		}
		byRepo[repoKey] = mergePolicyStrings(byRepo[repoKey], refs)
		key := repoLocationKey(finding.Org, finding.Repo, finding.Location)
		byRepoLocation[key] = mergePolicyStrings(byRepoLocation[key], refs)
	}

	out := append([]ActionPath(nil), paths...)
	for i := range out {
		repoKey := repoKey(out[i].Org, out[i].Repo)
		locationKey := repoLocationKey(out[i].Org, out[i].Repo, out[i].Location)
		refs := mergePolicyStrings(policyRefsFromPath(out[i]), byRepoLocation[locationKey], byRepo[repoKey])
		out[i] = decoratePolicyCoverageForPath(out[i], refs, len(policyFilesByRepo[repoKey]) > 0, policyFilesByRepo[repoKey])
	}
	return out
}

func decoratePolicyCoverageForPath(path ActionPath, refs []string, hasPolicyFiles bool, evidenceRefs []string) ActionPath {
	path.PolicyRefs = mergePolicyStrings(refs)
	path.PolicyEvidenceRefs = mergePolicyStrings(evidenceRefs)
	path.PolicyMissingReasons = dedupeSortedStrings(policyMissingReasons(path, len(path.PolicyRefs) > 0))
	path.PolicyStatusReasons = nil
	path.PolicyConfidence = policyConfidenceLow
	path.PolicyCoverageStatus = PolicyCoverageStatusNone

	switch {
	case len(path.PolicyRefs) == 0:
		path.PolicyCoverageStatus = PolicyCoverageStatusNone
		path.PolicyStatusReasons = dedupeSortedStrings(append([]string{"policy_ref_missing"}, path.PolicyMissingReasons...))
	case hasPolicyFiles:
		path.PolicyCoverageStatus = PolicyCoverageStatusMatched
		path.PolicyConfidence = policyConfidenceHigh
	case len(path.PolicyRefs) > 0:
		path.PolicyCoverageStatus = PolicyCoverageStatusDeclared
		path.PolicyConfidence = policyConfidenceMedium
		path.PolicyStatusReasons = []string{"gait_policy_file_missing"}
	}

	if path.PolicyCoverageStatus == PolicyCoverageStatusMatched && path.PolicyConfidence == "" {
		path.PolicyConfidence = policyConfidenceHigh
	}
	if path.PolicyCoverageStatus == PolicyCoverageStatusNone && path.PolicyConfidence == "" {
		path.PolicyConfidence = policyConfidenceLow
	}
	return path
}

func collectPolicyRefs(finding model.Finding) []string {
	if len(finding.Evidence) == 0 {
		return nil
	}
	values := []string{}
	for _, item := range finding.Evidence {
		switch strings.ToLower(strings.TrimSpace(item.Key)) {
		case "policy_refs", "declared_policy_refs":
			values = append(values, splitPolicyCSV(item.Value)...)
		}
	}
	return mergePolicyStrings(values)
}

func policyRefsFromPath(path ActionPath) []string {
	values := []string{}
	if normalized := agginventory.NormalizeTrustDepth(path.TrustDepth); normalized != nil {
		values = append(values, normalized.PolicyRefs...)
	}
	return mergePolicyStrings(values, path.PolicyRefs)
}

func policyMissingReasons(path ActionPath, hasRefs bool) []string {
	reasons := []string{}
	if !hasRefs {
		reasons = append(reasons, "policy_ref_missing")
	}
	if len(path.ActionClasses) == 0 {
		reasons = append(reasons, "action_class_gap")
	}
	if strings.TrimSpace(path.ToolType) == "" {
		reasons = append(reasons, "tool_gap")
	}
	if strings.TrimSpace(path.Location) == "" {
		reasons = append(reasons, "workflow_gap")
	}
	if !path.ProductionWrite && len(path.MatchedProductionTargets) == 0 {
		reasons = append(reasons, "target_gap")
	}
	if normalized := agginventory.NormalizeTrustDepth(path.TrustDepth); normalized != nil {
		for _, gap := range normalized.TrustGaps {
			if strings.TrimSpace(gap) == "policy_ref_missing" {
				reasons = append(reasons, "policy_ref_missing")
				break
			}
		}
	}
	return reasons
}

func splitPolicyCSV(raw string) []string {
	parts := strings.Split(strings.TrimSpace(raw), ",")
	return mergePolicyStrings(parts)
}

func mergePolicyStrings(sets ...[]string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	for _, set := range sets {
		for _, item := range set {
			trimmed := strings.TrimSpace(item)
			if trimmed == "" {
				continue
			}
			if _, ok := seen[trimmed]; ok {
				continue
			}
			seen[trimmed] = struct{}{}
			out = append(out, trimmed)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func repoLocationKey(org, repo, location string) string {
	return strings.Join([]string{
		strings.TrimSpace(org),
		strings.TrimSpace(repo),
		strings.TrimSpace(location),
	}, "::")
}

func choosePolicyCoverageStatus(current, incoming string) string {
	if policyCoverageRank(incoming) > policyCoverageRank(current) {
		return strings.TrimSpace(incoming)
	}
	if strings.TrimSpace(current) != "" {
		return strings.TrimSpace(current)
	}
	return strings.TrimSpace(incoming)
}

func choosePolicyConfidence(current, incoming string) string {
	if policyConfidenceRank(incoming) > policyConfidenceRank(current) {
		return strings.TrimSpace(incoming)
	}
	if strings.TrimSpace(current) != "" {
		return strings.TrimSpace(current)
	}
	return strings.TrimSpace(incoming)
}

func policyCoverageRank(value string) int {
	switch strings.TrimSpace(value) {
	case PolicyCoverageStatusConflict:
		return 5
	case PolicyCoverageStatusRuntimeProven:
		return 4
	case PolicyCoverageStatusStale:
		return 3
	case PolicyCoverageStatusMatched:
		return 2
	case PolicyCoverageStatusDeclared:
		return 1
	default:
		return 0
	}
}

func policyConfidenceRank(value string) int {
	switch strings.TrimSpace(value) {
	case policyConfidenceHigh:
		return 3
	case policyConfidenceMedium:
		return 2
	case policyConfidenceLow:
		return 1
	default:
		return 0
	}
}
