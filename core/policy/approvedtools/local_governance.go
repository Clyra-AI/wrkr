package approvedtools

import (
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/model"
)

const (
	LocalGovernanceBasisApprovedTools = "approved_tools_policy"
	LocalGovernanceBasisUnavailable   = "unavailable"
	LocalGovernanceStatusConfigured   = "configured"
	LocalGovernanceStatusUnavailable  = "unavailable"
)

func CompareLocalInventory(inv *agginventory.Inventory, configured bool, referencePath string) []model.Finding {
	if inv == nil {
		return nil
	}
	if !configured {
		inv.LocalGovernance = &agginventory.LocalGovernanceSummary{
			ReferenceBasis: LocalGovernanceBasisUnavailable,
			Status:         LocalGovernanceStatusUnavailable,
		}
		return nil
	}

	summary := agginventory.LocalGovernanceSummary{
		ReferenceBasis: LocalGovernanceBasisApprovedTools,
		ReferencePath:  strings.TrimSpace(referencePath),
		Status:         LocalGovernanceStatusConfigured,
	}
	findings := make([]model.Finding, 0)
	for _, tool := range inv.Tools {
		switch strings.TrimSpace(tool.ApprovalClass) {
		case "approved":
			summary.SanctionedTools++
		case "unapproved":
			summary.UnsanctionedTools++
			findings = append(findings, model.Finding{
				FindingType: "local_governance_gap",
				Severity:    governanceGapSeverity(tool),
				ToolType:    tool.ToolType,
				Location:    primaryToolLocation(tool),
				Repo:        firstRepo(tool.Repos),
				Org:         strings.TrimSpace(tool.Org),
				Detector:    "approvedtools",
				Evidence: []model.Evidence{
					{Key: "governance_status", Value: "unsanctioned"},
					{Key: "reference_basis", Value: LocalGovernanceBasisApprovedTools},
					{Key: "reference_path", Value: strings.TrimSpace(referencePath)},
					{Key: "tool_id", Value: strings.TrimSpace(tool.ToolID)},
				},
				Remediation: "Compare this local AI tool or config against the approved-tools baseline and remove or approve unreviewed usage.",
			})
		default:
			summary.UnknownTools++
		}
	}
	inv.LocalGovernance = &summary
	model.SortFindings(findings)
	return findings
}

func governanceGapSeverity(tool agginventory.Tool) string {
	switch strings.TrimSpace(tool.PermissionTier) {
	case "admin":
		return model.SeverityHigh
	case "write":
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}

func primaryToolLocation(tool agginventory.Tool) string {
	if len(tool.Locations) == 0 {
		return ""
	}
	locations := append([]agginventory.ToolLocation(nil), tool.Locations...)
	sort.Slice(locations, func(i, j int) bool {
		if locations[i].Repo != locations[j].Repo {
			return locations[i].Repo < locations[j].Repo
		}
		return locations[i].Location < locations[j].Location
	})
	return strings.TrimSpace(locations[0].Location)
}

func firstRepo(repos []string) string {
	if len(repos) == 0 {
		return ""
	}
	out := append([]string(nil), repos...)
	sort.Strings(out)
	return strings.TrimSpace(out[0])
}
