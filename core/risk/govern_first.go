package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/owners"
)

type OwnerlessExposure struct {
	ExplicitOwnerPaths   int `json:"explicit_owner_paths"`
	InferredOwnerPaths   int `json:"inferred_owner_paths"`
	UnresolvedOwnerPaths int `json:"unresolved_owner_paths"`
	ConflictOwnerPaths   int `json:"conflict_owner_paths"`
}

type IdentityExposureSummary struct {
	TotalNonHumanIdentitiesObserved      int `json:"total_non_human_identities_observed"`
	IdentitiesBackingWriteCapablePaths   int `json:"identities_backing_write_capable_paths"`
	IdentitiesBackingDeployCapablePaths  int `json:"identities_backing_deploy_capable_paths"`
	IdentitiesWithUnresolvedOwnership    int `json:"identities_with_unresolved_ownership"`
	IdentitiesWithUnknownExecutionLinked int `json:"identities_with_unknown_execution_correlation"`
}

type IdentityActionTarget struct {
	ExecutionIdentity            string   `json:"execution_identity,omitempty"`
	ExecutionIdentityType        string   `json:"execution_identity_type,omitempty"`
	ExecutionIdentitySource      string   `json:"execution_identity_source,omitempty"`
	RepoCount                    int      `json:"repo_count"`
	PathCount                    int      `json:"path_count"`
	WriteCapablePathCount        int      `json:"write_capable_path_count"`
	HighImpactPathCount          int      `json:"high_impact_path_count"`
	UnknownToSecurityPathCount   int      `json:"unknown_to_security_path_count"`
	UnresolvedOwnershipPathCount int      `json:"unresolved_ownership_path_count"`
	SharedExecutionIdentity      bool     `json:"shared_execution_identity"`
	StandingPrivilege            bool     `json:"standing_privilege"`
	Rationale                    []string `json:"rationale,omitempty"`
}

type ExposureGroup struct {
	GroupID                  string   `json:"group_id"`
	Org                      string   `json:"org"`
	Repos                    []string `json:"repos"`
	ToolTypes                []string `json:"tool_types"`
	ExecutionIdentity        string   `json:"execution_identity,omitempty"`
	ExecutionIdentityType    string   `json:"execution_identity_type,omitempty"`
	ExecutionIdentityStatus  string   `json:"execution_identity_status,omitempty"`
	DeliveryChainStatus      string   `json:"delivery_chain_status,omitempty"`
	WorkflowTriggerClass     string   `json:"workflow_trigger_class,omitempty"`
	BusinessStateSurface     string   `json:"business_state_surface,omitempty"`
	RecommendedAction        string   `json:"recommended_action"`
	SharedExecutionIdentity  bool     `json:"shared_execution_identity"`
	StandingPrivilege        bool     `json:"standing_privilege"`
	PathCount                int      `json:"path_count"`
	WriteCapablePathCount    int      `json:"write_capable_path_count"`
	ProductionWritePathCount int      `json:"production_write_path_count"`
	PathIDs                  []string `json:"path_ids"`
	ExampleRepo              string   `json:"example_repo,omitempty"`
	ExampleLocation          string   `json:"example_location,omitempty"`
}

func BuildOwnerlessExposure(paths []ActionPath) *OwnerlessExposure {
	if len(paths) == 0 {
		return nil
	}
	out := &OwnerlessExposure{}
	for _, path := range paths {
		switch {
		case strings.TrimSpace(path.OwnerSource) == owners.OwnerSourceConflict:
			out.ConflictOwnerPaths++
		case strings.TrimSpace(path.OwnershipStatus) == owners.OwnershipStatusExplicit:
			out.ExplicitOwnerPaths++
		case strings.TrimSpace(path.OwnershipStatus) == owners.OwnershipStatusInferred:
			out.InferredOwnerPaths++
		default:
			out.UnresolvedOwnerPaths++
		}
	}
	return out
}

func BuildIdentityExposureSummary(paths []ActionPath, inventory *agginventory.Inventory) *IdentityExposureSummary {
	totalIdentityKeys := map[string]struct{}{}
	if inventory != nil {
		for _, identity := range inventory.NonHumanIdentities {
			key := inventoryIdentityKey(identity)
			if key == "" {
				continue
			}
			totalIdentityKeys[key] = struct{}{}
		}
	}

	writeCapable := map[string]struct{}{}
	deployCapable := map[string]struct{}{}
	unresolvedOwnership := map[string]struct{}{}
	matched := map[string]struct{}{}
	for _, path := range paths {
		key := actionPathIdentitySummaryKey(path)
		if key == "" {
			continue
		}
		totalIdentityKeys[key] = struct{}{}
		matched[key] = struct{}{}
		if path.WriteCapable {
			writeCapable[key] = struct{}{}
		}
		if path.DeployWrite || path.ProductionWrite || strings.TrimSpace(path.BusinessStateSurface) == "deploy" {
			deployCapable[key] = struct{}{}
		}
		if actionPathHasWeakOwnership(path) {
			unresolvedOwnership[key] = struct{}{}
		}
	}
	if len(totalIdentityKeys) == 0 {
		return nil
	}

	return &IdentityExposureSummary{
		TotalNonHumanIdentitiesObserved:      len(totalIdentityKeys),
		IdentitiesBackingWriteCapablePaths:   len(writeCapable),
		IdentitiesBackingDeployCapablePaths:  len(deployCapable),
		IdentitiesWithUnresolvedOwnership:    len(unresolvedOwnership),
		IdentitiesWithUnknownExecutionLinked: len(totalIdentityKeys) - len(matched),
	}
}

func BuildIdentityActionTargets(paths []ActionPath) (*IdentityActionTarget, *IdentityActionTarget) {
	type rollup struct {
		subject           string
		identityType      string
		source            string
		repos             map[string]struct{}
		pathCount         int
		writeCapableCount int
		highImpactCount   int
		unknownCount      int
		unresolvedCount   int
	}

	rollups := map[string]*rollup{}
	for _, path := range paths {
		key := actionPathIdentitySummaryKey(path)
		if key == "" {
			continue
		}
		item := rollups[key]
		if item == nil {
			item = &rollup{
				subject:      strings.TrimSpace(path.ExecutionIdentity),
				identityType: strings.TrimSpace(path.ExecutionIdentityType),
				source:       strings.TrimSpace(path.ExecutionIdentitySource),
				repos:        map[string]struct{}{},
			}
			rollups[key] = item
		}
		item.pathCount++
		if strings.TrimSpace(path.Repo) != "" {
			item.repos[strings.TrimSpace(path.Repo)] = struct{}{}
		}
		if path.WriteCapable {
			item.writeCapableCount++
		}
		if actionPathHighImpact(path) {
			item.highImpactCount++
		}
		if strings.TrimSpace(path.SecurityVisibilityStatus) == agginventory.SecurityVisibilityUnknownToSecurity {
			item.unknownCount++
		}
		if actionPathHasWeakOwnership(path) {
			item.unresolvedCount++
		}
	}
	if len(rollups) == 0 {
		return nil, nil
	}

	targets := make([]IdentityActionTarget, 0, len(rollups))
	for _, item := range rollups {
		target := IdentityActionTarget{
			ExecutionIdentity:            item.subject,
			ExecutionIdentityType:        item.identityType,
			ExecutionIdentitySource:      item.source,
			RepoCount:                    len(item.repos),
			PathCount:                    item.pathCount,
			WriteCapablePathCount:        item.writeCapableCount,
			HighImpactPathCount:          item.highImpactCount,
			UnknownToSecurityPathCount:   item.unknownCount,
			UnresolvedOwnershipPathCount: item.unresolvedCount,
		}
		target.SharedExecutionIdentity = target.PathCount > 1 || target.RepoCount > 1
		target.StandingPrivilege = target.SharedExecutionIdentity && (target.WriteCapablePathCount > 0 || target.HighImpactPathCount > 0)
		target.Rationale = []string{
			fmt.Sprintf("path_count=%d", target.PathCount),
			fmt.Sprintf("write_capable_path_count=%d", target.WriteCapablePathCount),
			fmt.Sprintf("high_impact_path_count=%d", target.HighImpactPathCount),
			fmt.Sprintf("unknown_to_security_path_count=%d", target.UnknownToSecurityPathCount),
			fmt.Sprintf("unresolved_ownership_path_count=%d", target.UnresolvedOwnershipPathCount),
		}
		targets = append(targets, target)
	}

	reviewTargets := append([]IdentityActionTarget(nil), targets...)
	sort.Slice(reviewTargets, func(i, j int) bool {
		return compareIdentityTargets(reviewTargets[i], reviewTargets[j], false)
	})
	revokeTargets := append([]IdentityActionTarget(nil), targets...)
	sort.Slice(revokeTargets, func(i, j int) bool {
		return compareIdentityTargets(revokeTargets[i], revokeTargets[j], true)
	})

	return &reviewTargets[0], &revokeTargets[0]
}

func BuildExposureGroups(paths []ActionPath) []ExposureGroup {
	if len(paths) == 0 {
		return nil
	}

	type accumulator struct {
		group     ExposureGroup
		toolTypes map[string]struct{}
		repos     map[string]struct{}
		pathIDs   map[string]struct{}
	}

	accumulators := map[string]*accumulator{}
	for _, path := range paths {
		key := exposureGroupKey(path)
		item := accumulators[key]
		if item == nil {
			item = &accumulator{
				group: ExposureGroup{
					GroupID:                 hashGovernFirstKey("grp", key),
					Org:                     strings.TrimSpace(path.Org),
					ExecutionIdentity:       strings.TrimSpace(path.ExecutionIdentity),
					ExecutionIdentityType:   strings.TrimSpace(path.ExecutionIdentityType),
					ExecutionIdentityStatus: strings.TrimSpace(path.ExecutionIdentityStatus),
					DeliveryChainStatus:     strings.TrimSpace(path.DeliveryChainStatus),
					WorkflowTriggerClass:    strings.TrimSpace(path.WorkflowTriggerClass),
					BusinessStateSurface:    strings.TrimSpace(path.BusinessStateSurface),
					RecommendedAction:       strings.TrimSpace(path.RecommendedAction),
					SharedExecutionIdentity: path.SharedExecutionIdentity,
					StandingPrivilege:       path.StandingPrivilege,
					ExampleRepo:             strings.TrimSpace(path.Repo),
					ExampleLocation:         strings.TrimSpace(path.Location),
				},
				toolTypes: map[string]struct{}{},
				repos:     map[string]struct{}{},
				pathIDs:   map[string]struct{}{},
			}
			accumulators[key] = item
		}
		item.group.PathCount++
		if path.WriteCapable {
			item.group.WriteCapablePathCount++
		}
		if path.ProductionWrite {
			item.group.ProductionWritePathCount++
		}
		item.group.SharedExecutionIdentity = item.group.SharedExecutionIdentity || path.SharedExecutionIdentity
		item.group.StandingPrivilege = item.group.StandingPrivilege || path.StandingPrivilege
		item.toolTypes[strings.TrimSpace(path.ToolType)] = struct{}{}
		if strings.TrimSpace(path.Repo) != "" {
			item.repos[strings.TrimSpace(path.Repo)] = struct{}{}
		}
		if strings.TrimSpace(path.PathID) != "" {
			item.pathIDs[strings.TrimSpace(path.PathID)] = struct{}{}
		}
		if exposureGroupLocationRank(path.Location, item.group.ExampleLocation) < 0 {
			item.group.ExampleLocation = strings.TrimSpace(path.Location)
			item.group.ExampleRepo = strings.TrimSpace(path.Repo)
		}
	}

	groups := make([]ExposureGroup, 0, len(accumulators))
	for _, item := range accumulators {
		item.group.ToolTypes = sortedKeys(item.toolTypes)
		item.group.Repos = sortedKeys(item.repos)
		item.group.PathIDs = sortedKeys(item.pathIDs)
		groups = append(groups, item.group)
	}

	sort.Slice(groups, func(i, j int) bool {
		pi := actionPriority(groups[i].RecommendedAction)
		pj := actionPriority(groups[j].RecommendedAction)
		if pi != pj {
			return pi < pj
		}
		if groups[i].PathCount != groups[j].PathCount {
			return groups[i].PathCount > groups[j].PathCount
		}
		if groups[i].ProductionWritePathCount != groups[j].ProductionWritePathCount {
			return groups[i].ProductionWritePathCount > groups[j].ProductionWritePathCount
		}
		if groups[i].WriteCapablePathCount != groups[j].WriteCapablePathCount {
			return groups[i].WriteCapablePathCount > groups[j].WriteCapablePathCount
		}
		if groups[i].Org != groups[j].Org {
			return groups[i].Org < groups[j].Org
		}
		if groups[i].ExampleRepo != groups[j].ExampleRepo {
			return groups[i].ExampleRepo < groups[j].ExampleRepo
		}
		return groups[i].GroupID < groups[j].GroupID
	})

	return groups
}

func DecorateActionPaths(paths []ActionPath) []ActionPath {
	if len(paths) == 0 {
		return nil
	}
	type identityUsage struct {
		pathCount int
		repos     map[string]struct{}
	}
	usageByIdentity := map[string]*identityUsage{}
	for _, path := range paths {
		key := actionPathIdentitySummaryKey(path)
		if key == "" {
			continue
		}
		item := usageByIdentity[key]
		if item == nil {
			item = &identityUsage{repos: map[string]struct{}{}}
			usageByIdentity[key] = item
		}
		item.pathCount++
		if strings.TrimSpace(path.Repo) != "" {
			item.repos[strings.TrimSpace(path.Repo)] = struct{}{}
		}
	}

	out := append([]ActionPath(nil), paths...)
	for idx := range out {
		key := actionPathIdentitySummaryKey(out[idx])
		if key == "" {
			continue
		}
		usage := usageByIdentity[key]
		if usage == nil {
			continue
		}
		out[idx].SharedExecutionIdentity = usage.pathCount > 1 || len(usage.repos) > 1
		out[idx].StandingPrivilege = out[idx].SharedExecutionIdentity && (out[idx].WriteCapable || out[idx].ProductionWrite || actionPathHighImpact(out[idx]))
	}
	return out
}

func compareIdentityTargets(left, right IdentityActionTarget, revoke bool) bool {
	leftPrimary := left.UnknownToSecurityPathCount*5 + left.UnresolvedOwnershipPathCount*4 + left.PathCount*3 + left.RepoCount*2
	rightPrimary := right.UnknownToSecurityPathCount*5 + right.UnresolvedOwnershipPathCount*4 + right.PathCount*3 + right.RepoCount*2
	if revoke {
		leftPrimary = left.WriteCapablePathCount*5 + left.HighImpactPathCount*4 + ternaryInt(left.StandingPrivilege, 3, 0) + left.RepoCount*2 + left.PathCount
		rightPrimary = right.WriteCapablePathCount*5 + right.HighImpactPathCount*4 + ternaryInt(right.StandingPrivilege, 3, 0) + right.RepoCount*2 + right.PathCount
	}
	if leftPrimary != rightPrimary {
		return leftPrimary > rightPrimary
	}
	if left.ExecutionIdentityType != right.ExecutionIdentityType {
		return left.ExecutionIdentityType < right.ExecutionIdentityType
	}
	if left.ExecutionIdentity != right.ExecutionIdentity {
		return left.ExecutionIdentity < right.ExecutionIdentity
	}
	return left.ExecutionIdentitySource < right.ExecutionIdentitySource
}

func actionPathHighImpact(path ActionPath) bool {
	switch strings.TrimSpace(path.BusinessStateSurface) {
	case "deploy", "db", "admin_api", "saas_write":
		return true
	default:
		return path.ProductionWrite || path.DeployWrite
	}
}

func actionPathHasWeakOwnership(path ActionPath) bool {
	return strings.TrimSpace(path.OwnerSource) == owners.OwnerSourceConflict ||
		strings.TrimSpace(path.OwnershipState) == owners.OwnershipStateConflicting ||
		strings.TrimSpace(path.OwnershipState) == owners.OwnershipStateMissing ||
		strings.TrimSpace(path.OwnershipStatus) == "" ||
		strings.TrimSpace(path.OwnershipStatus) == owners.OwnershipStatusUnresolved
}

func actionPathIdentitySummaryKey(path ActionPath) string {
	if strings.TrimSpace(path.ExecutionIdentityStatus) != "known" {
		return ""
	}
	if strings.TrimSpace(path.ExecutionIdentity) == "" {
		return ""
	}
	return strings.Join([]string{
		strings.TrimSpace(path.Org),
		strings.TrimSpace(path.ExecutionIdentity),
		strings.TrimSpace(path.ExecutionIdentityType),
		strings.TrimSpace(path.ExecutionIdentitySource),
	}, "|")
}

func inventoryIdentityKey(identity agginventory.NonHumanIdentity) string {
	subject := strings.TrimSpace(identity.Subject)
	if subject == "" || strings.TrimSpace(identity.IdentityType) == "unknown" {
		return ""
	}
	return strings.Join([]string{
		strings.TrimSpace(identity.Org),
		subject,
		strings.TrimSpace(identity.IdentityType),
		strings.TrimSpace(identity.Source),
	}, "|")
}

func exposureGroupKey(path ActionPath) string {
	return strings.Join([]string{
		strings.TrimSpace(path.Org),
		strings.TrimSpace(path.Repo),
		strings.TrimSpace(path.ToolType),
		strings.TrimSpace(path.ExecutionIdentityStatus),
		strings.TrimSpace(path.ExecutionIdentity),
		strings.TrimSpace(path.ExecutionIdentityType),
		strings.TrimSpace(path.DeliveryChainStatus),
		strings.TrimSpace(path.WorkflowTriggerClass),
		strings.TrimSpace(path.BusinessStateSurface),
		strings.TrimSpace(path.RecommendedAction),
	}, "|")
}

func exposureGroupLocationRank(left, right string) int {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	switch {
	case right == "":
		return -1
	case left == "":
		return 1
	case left < right:
		return -1
	case left > right:
		return 1
	default:
		return 0
	}
}

func sortedKeys(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) == "" {
			continue
		}
		out = append(out, strings.TrimSpace(value))
	}
	sort.Strings(out)
	return out
}

func hashGovernFirstKey(prefix, key string) string {
	sum := sha256.Sum256([]byte(key))
	return prefix + "-" + hex.EncodeToString(sum[:6])
}

func ternaryInt(condition bool, whenTrue, whenFalse int) int {
	if condition {
		return whenTrue
	}
	return whenFalse
}
