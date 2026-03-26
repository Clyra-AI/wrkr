package fix

import "sort"

type PRGroup struct {
	Index int
	Total int
	Plan  Plan
}

// SplitPlanForPRs partitions remediations into deterministic contiguous groups.
// Skipped findings stay attached to the first group only so the overall reason-code
// context is preserved without duplicating it across every PR payload.
func SplitPlanForPRs(plan Plan, maxPRs int) []PRGroup {
	if maxPRs <= 1 || len(plan.Remediations) <= 1 {
		return []PRGroup{{Index: 0, Total: 1, Plan: plan}}
	}

	total := maxPRs
	if len(plan.Remediations) < total {
		total = len(plan.Remediations)
	}
	chunkSize := (len(plan.Remediations) + total - 1) / total
	groups := make([]PRGroup, 0, total)
	for idx := 0; idx < total; idx++ {
		start := idx * chunkSize
		if start >= len(plan.Remediations) {
			break
		}
		end := start + chunkSize
		if end > len(plan.Remediations) {
			end = len(plan.Remediations)
		}
		groupPlan := Plan{
			RequestedTop: end - start,
			Remediations: append([]Remediation(nil), plan.Remediations[start:end]...),
		}
		if idx == 0 {
			groupPlan.Skipped = append([]Skipped(nil), plan.Skipped...)
		}
		groupPlan.Fingerprint = planFingerprint(groupPlan.Remediations, groupPlan.Skipped)
		groups = append(groups, PRGroup{
			Index: idx,
			Total: total,
			Plan:  groupPlan,
		})
	}
	for idx := range groups {
		groups[idx].Total = len(groups)
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Index < groups[j].Index })
	return groups
}
