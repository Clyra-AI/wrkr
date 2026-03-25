package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
)

type ActionPathSummary struct {
	TotalPaths                  int `json:"total_paths"`
	WriteCapablePaths           int `json:"write_capable_paths"`
	ProductionTargetBackedPaths int `json:"production_target_backed_paths"`
	GovernFirstPaths            int `json:"govern_first_paths"`
}

type ActionPath struct {
	PathID                   string   `json:"path_id"`
	Org                      string   `json:"org"`
	Repo                     string   `json:"repo"`
	AgentID                  string   `json:"agent_id,omitempty"`
	ToolType                 string   `json:"tool_type"`
	Location                 string   `json:"location,omitempty"`
	WriteCapable             bool     `json:"write_capable"`
	OperationalOwner         string   `json:"operational_owner,omitempty"`
	OwnerSource              string   `json:"owner_source,omitempty"`
	OwnershipStatus          string   `json:"ownership_status,omitempty"`
	ApprovalGapReasons       []string `json:"approval_gap_reasons,omitempty"`
	PullRequestWrite         bool     `json:"pull_request_write,omitempty"`
	MergeExecute             bool     `json:"merge_execute,omitempty"`
	DeployWrite              bool     `json:"deploy_write,omitempty"`
	DeliveryChainStatus      string   `json:"delivery_chain_status,omitempty"`
	ProductionTargetStatus   string   `json:"production_target_status,omitempty"`
	ProductionWrite          bool     `json:"production_write"`
	ApprovalGap              bool     `json:"approval_gap"`
	SecurityVisibilityStatus string   `json:"security_visibility_status,omitempty"`
	CredentialAccess         bool     `json:"credential_access"`
	DeploymentStatus         string   `json:"deployment_status,omitempty"`
	AttackPathScore          float64  `json:"attack_path_score"`
	RiskScore                float64  `json:"risk_score"`
	RecommendedAction        string   `json:"recommended_action"`
	MatchedProductionTargets []string `json:"matched_production_targets,omitempty"`
}

type ActionPathToControlFirst struct {
	Summary ActionPathSummary `json:"summary"`
	Path    ActionPath        `json:"path"`
}

func BuildActionPaths(attackPaths []riskattack.ScoredPath, inventory *agginventory.Inventory) ([]ActionPath, *ActionPathToControlFirst) {
	if inventory == nil || len(inventory.AgentPrivilegeMap) == 0 {
		return nil, nil
	}

	attackScoreByRepo := map[string]float64{}
	for _, path := range attackPaths {
		key := repoKey(path.Org, path.Repo)
		if path.PathScore > attackScoreByRepo[key] {
			attackScoreByRepo[key] = path.PathScore
		}
	}

	paths := make([]ActionPath, 0, len(inventory.AgentPrivilegeMap))
	summary := ActionPathSummary{}
	for _, entry := range inventory.AgentPrivilegeMap {
		if !shouldIncludeActionPath(entry) {
			continue
		}
		path := ActionPath{
			PathID:                   actionPathID(entry),
			Org:                      strings.TrimSpace(entry.Org),
			Repo:                     firstRepoFromEntry(entry),
			AgentID:                  strings.TrimSpace(entry.AgentID),
			ToolType:                 actionPathToolType(entry),
			Location:                 strings.TrimSpace(entry.Location),
			WriteCapable:             entry.WriteCapable,
			OperationalOwner:         strings.TrimSpace(entry.OperationalOwner),
			OwnerSource:              strings.TrimSpace(entry.OwnerSource),
			OwnershipStatus:          strings.TrimSpace(entry.OwnershipStatus),
			ApprovalGapReasons:       append([]string(nil), entry.ApprovalGapReasons...),
			PullRequestWrite:         entry.PullRequestWrite,
			MergeExecute:             entry.MergeExecute,
			DeployWrite:              entry.DeployWrite,
			DeliveryChainStatus:      strings.TrimSpace(entry.DeliveryChainStatus),
			ProductionTargetStatus:   strings.TrimSpace(entry.ProductionTargetStatus),
			ProductionWrite:          entry.ProductionWrite,
			ApprovalGap:              actionPathApprovalGap(entry.ApprovalClassification, entry.ApprovalGapReasons),
			SecurityVisibilityStatus: strings.TrimSpace(entry.SecurityVisibilityStatus),
			CredentialAccess:         entry.CredentialAccess,
			DeploymentStatus:         strings.TrimSpace(entry.DeploymentStatus),
			AttackPathScore:          attackScoreByRepo[repoKey(entry.Org, firstRepoFromEntry(entry))],
			RiskScore:                entry.RiskScore,
			RecommendedAction:        actionPathRecommendedAction(entry),
			MatchedProductionTargets: append([]string(nil), entry.MatchedProductionTargets...),
		}
		paths = append(paths, path)
		summary.TotalPaths++
		if path.WriteCapable {
			summary.WriteCapablePaths++
		}
		if path.ProductionWrite {
			summary.ProductionTargetBackedPaths++
		}
		if path.RecommendedAction != "control" {
			summary.GovernFirstPaths++
		}
	}
	if len(paths) == 0 {
		return nil, nil
	}

	sort.Slice(paths, func(i, j int) bool {
		pi := actionPriority(paths[i].RecommendedAction)
		pj := actionPriority(paths[j].RecommendedAction)
		if pi != pj {
			return pi < pj
		}
		ci := deliveryChainPriority(paths[i].DeliveryChainStatus)
		cj := deliveryChainPriority(paths[j].DeliveryChainStatus)
		if ci != cj {
			return ci < cj
		}
		if paths[i].RiskScore != paths[j].RiskScore {
			return paths[i].RiskScore > paths[j].RiskScore
		}
		if paths[i].AttackPathScore != paths[j].AttackPathScore {
			return paths[i].AttackPathScore > paths[j].AttackPathScore
		}
		if paths[i].Org != paths[j].Org {
			return paths[i].Org < paths[j].Org
		}
		if paths[i].Repo != paths[j].Repo {
			return paths[i].Repo < paths[j].Repo
		}
		if paths[i].Location != paths[j].Location {
			return paths[i].Location < paths[j].Location
		}
		return paths[i].PathID < paths[j].PathID
	})

	choice := &ActionPathToControlFirst{
		Summary: summary,
		Path:    paths[0],
	}
	return paths, choice
}

func shouldIncludeActionPath(entry agginventory.AgentPrivilegeMapEntry) bool {
	return entry.WriteCapable ||
		entry.CredentialAccess ||
		entry.ProductionWrite ||
		entry.PullRequestWrite ||
		entry.MergeExecute ||
		entry.DeployWrite ||
		actionPathApprovalGap(entry.ApprovalClassification, entry.ApprovalGapReasons)
}

func actionPathRecommendedAction(entry agginventory.AgentPrivilegeMapEntry) string {
	switch {
	case entry.ProductionWrite:
		return "control"
	case actionPathApprovalGap(entry.ApprovalClassification, entry.ApprovalGapReasons):
		return "approval"
	case entry.CredentialAccess ||
		strings.EqualFold(strings.TrimSpace(entry.DeploymentStatus), "deployed") ||
		entry.PullRequestWrite ||
		entry.MergeExecute ||
		entry.DeployWrite:
		return "proof"
	default:
		return "inventory"
	}
}

func actionPathApprovalGap(status string, reasons []string) bool {
	if len(reasons) > 0 {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "unknown", "unapproved":
		return true
	default:
		return false
	}
}

func actionPriority(action string) int {
	switch strings.TrimSpace(action) {
	case "control":
		return 0
	case "approval":
		return 1
	case "proof":
		return 2
	case "inventory":
		return 3
	default:
		return 99
	}
}

func deliveryChainPriority(status string) int {
	switch strings.TrimSpace(status) {
	case "pr_merge_deploy":
		return 0
	case "merge_deploy":
		return 1
	case "pr_merge":
		return 2
	case "deploy_only":
		return 3
	case "pr_only":
		return 4
	case "merge_only":
		return 5
	default:
		return 99
	}
}

func firstRepoFromEntry(entry agginventory.AgentPrivilegeMapEntry) string {
	if len(entry.Repos) == 0 {
		return ""
	}
	repos := append([]string(nil), entry.Repos...)
	sort.Strings(repos)
	return repos[0]
}

func actionPathToolType(entry agginventory.AgentPrivilegeMapEntry) string {
	if strings.TrimSpace(entry.Framework) != "" {
		return strings.TrimSpace(entry.Framework)
	}
	return strings.TrimSpace(entry.ToolType)
}

func actionPathID(entry agginventory.AgentPrivilegeMapEntry) string {
	parts := []string{
		strings.TrimSpace(entry.AgentID),
		strings.TrimSpace(entry.Org),
		firstRepoFromEntry(entry),
		strings.TrimSpace(entry.Location),
		actionPathRecommendedAction(entry),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return "apc-" + hex.EncodeToString(sum[:6])
}
