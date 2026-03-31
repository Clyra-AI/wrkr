package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/model"
	riskattack "github.com/Clyra-AI/wrkr/core/risk/attackpath"
)

const actionPathIDPrefix = "apc-"

type ActionPathSummary struct {
	TotalPaths                  int `json:"total_paths"`
	WriteCapablePaths           int `json:"write_capable_paths"`
	ProductionTargetBackedPaths int `json:"production_target_backed_paths"`
	GovernFirstPaths            int `json:"govern_first_paths"`
}

type ActionPath struct {
	PathID                     string   `json:"path_id"`
	Org                        string   `json:"org"`
	Repo                       string   `json:"repo"`
	AgentID                    string   `json:"agent_id,omitempty"`
	ToolType                   string   `json:"tool_type"`
	Location                   string   `json:"location,omitempty"`
	WriteCapable               bool     `json:"write_capable"`
	OperationalOwner           string   `json:"operational_owner,omitempty"`
	OwnerSource                string   `json:"owner_source,omitempty"`
	OwnershipStatus            string   `json:"ownership_status,omitempty"`
	ApprovalGapReasons         []string `json:"approval_gap_reasons,omitempty"`
	PullRequestWrite           bool     `json:"pull_request_write,omitempty"`
	MergeExecute               bool     `json:"merge_execute,omitempty"`
	DeployWrite                bool     `json:"deploy_write,omitempty"`
	DeliveryChainStatus        string   `json:"delivery_chain_status,omitempty"`
	ProductionTargetStatus     string   `json:"production_target_status,omitempty"`
	ProductionWrite            bool     `json:"production_write"`
	ApprovalGap                bool     `json:"approval_gap"`
	SecurityVisibilityStatus   string   `json:"security_visibility_status,omitempty"`
	CredentialAccess           bool     `json:"credential_access"`
	DeploymentStatus           string   `json:"deployment_status,omitempty"`
	ExecutionIdentity          string   `json:"execution_identity,omitempty"`
	ExecutionIdentityType      string   `json:"execution_identity_type,omitempty"`
	ExecutionIdentitySource    string   `json:"execution_identity_source,omitempty"`
	ExecutionIdentityStatus    string   `json:"execution_identity_status,omitempty"`
	ExecutionIdentityRationale string   `json:"execution_identity_rationale,omitempty"`
	BusinessStateSurface       string   `json:"business_state_surface,omitempty"`
	SharedExecutionIdentity    bool     `json:"shared_execution_identity,omitempty"`
	StandingPrivilege          bool     `json:"standing_privilege,omitempty"`
	AttackPathScore            float64  `json:"attack_path_score"`
	RiskScore                  float64  `json:"risk_score"`
	RecommendedAction          string   `json:"recommended_action"`
	MatchedProductionTargets   []string `json:"matched_production_targets,omitempty"`
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
	pathIndexByKey := map[string]int{}
	for _, entry := range inventory.AgentPrivilegeMap {
		if !shouldIncludeActionPath(entry) {
			continue
		}
		key := actionPathIdentityKey(entry)
		path := buildActionPath(entry, attackScoreByRepo, inventory.NonHumanIdentities)
		if idx, ok := pathIndexByKey[key]; ok {
			paths[idx] = mergeActionPath(paths[idx], path)
			continue
		}
		pathIndexByKey[key] = len(paths)
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		return nil, nil
	}
	paths = DecorateActionPaths(paths)

	sort.Slice(paths, func(i, j int) bool {
		pi := actionPriority(paths[i].RecommendedAction)
		pj := actionPriority(paths[j].RecommendedAction)
		if pi != pj {
			return pi < pj
		}
		oi := governFirstOwnershipPriority(paths[i])
		oj := governFirstOwnershipPriority(paths[j])
		if oi != oj {
			return oi < oj
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

	summary := summarizeActionPaths(paths)
	choice := &ActionPathToControlFirst{
		Summary: summary,
		Path:    paths[0],
	}
	return paths, choice
}

func buildActionPath(
	entry agginventory.AgentPrivilegeMapEntry,
	attackScoreByRepo map[string]float64,
	identities []agginventory.NonHumanIdentity,
) ActionPath {
	executionIdentity, executionIdentityType, executionIdentitySource, executionIdentityStatus, executionIdentityRationale := correlateExecutionIdentity(entry, identities)
	path := ActionPath{
		PathID:                     actionPathID(entry),
		Org:                        strings.TrimSpace(entry.Org),
		Repo:                       firstRepoFromEntry(entry),
		AgentID:                    strings.TrimSpace(entry.AgentID),
		ToolType:                   actionPathToolType(entry),
		Location:                   strings.TrimSpace(entry.Location),
		WriteCapable:               entry.WriteCapable,
		OperationalOwner:           strings.TrimSpace(entry.OperationalOwner),
		OwnerSource:                strings.TrimSpace(entry.OwnerSource),
		OwnershipStatus:            strings.TrimSpace(entry.OwnershipStatus),
		ApprovalGapReasons:         dedupeSortedStrings(entry.ApprovalGapReasons),
		PullRequestWrite:           entry.PullRequestWrite,
		MergeExecute:               entry.MergeExecute,
		DeployWrite:                entry.DeployWrite,
		DeliveryChainStatus:        strings.TrimSpace(entry.DeliveryChainStatus),
		ProductionTargetStatus:     strings.TrimSpace(entry.ProductionTargetStatus),
		ProductionWrite:            entry.ProductionWrite,
		ApprovalGap:                actionPathApprovalGap(entry.ApprovalClassification, entry.ApprovalGapReasons),
		SecurityVisibilityStatus:   strings.TrimSpace(entry.SecurityVisibilityStatus),
		CredentialAccess:           entry.CredentialAccess,
		DeploymentStatus:           strings.TrimSpace(entry.DeploymentStatus),
		ExecutionIdentity:          executionIdentity,
		ExecutionIdentityType:      executionIdentityType,
		ExecutionIdentitySource:    executionIdentitySource,
		ExecutionIdentityStatus:    executionIdentityStatus,
		ExecutionIdentityRationale: executionIdentityRationale,
		BusinessStateSurface:       classifyBusinessStateSurface(entry),
		AttackPathScore:            attackScoreByRepo[repoKey(entry.Org, firstRepoFromEntry(entry))],
		RiskScore:                  entry.RiskScore,
		MatchedProductionTargets:   dedupeSortedStrings(entry.MatchedProductionTargets),
	}
	path.RecommendedAction = recommendedActionForPath(path)
	return path
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

func recommendedActionForPath(path ActionPath) string {
	weakIdentity := strings.TrimSpace(path.ExecutionIdentityStatus) == "" ||
		strings.TrimSpace(path.ExecutionIdentityStatus) == "unknown" ||
		strings.TrimSpace(path.ExecutionIdentityStatus) == "ambiguous"
	weakOwnership := strings.TrimSpace(path.OwnershipStatus) == "" ||
		strings.TrimSpace(path.OwnershipStatus) == "unresolved" ||
		strings.TrimSpace(path.OwnerSource) == "multi_repo_conflict"
	hasDeliveryPath := strings.TrimSpace(path.DeliveryChainStatus) != "" &&
		strings.TrimSpace(path.DeliveryChainStatus) != "none"
	unknownToSecurity := strings.TrimSpace(path.SecurityVisibilityStatus) == agginventory.SecurityVisibilityUnknownToSecurity

	switch {
	case path.ProductionWrite:
		return "control"
	case path.ApprovalGap && !weakIdentity && !weakOwnership && !unknownToSecurity:
		return "approval"
	case path.CredentialAccess ||
		strings.EqualFold(strings.TrimSpace(path.DeploymentStatus), "deployed") ||
		hasDeliveryPath ||
		unknownToSecurity ||
		weakIdentity ||
		weakOwnership:
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
	return hashActionPathIdentity(actionPathIdentityKey(entry))
}

func actionPathIdentityKey(entry agginventory.AgentPrivilegeMapEntry) string {
	parts := []string{
		strings.TrimSpace(entry.Org),
		strings.Join(dedupeSortedStrings(entry.Repos), ","),
		strings.TrimSpace(entry.AgentID),
		strings.TrimSpace(entry.AgentInstanceID),
		strings.TrimSpace(entry.ToolID),
		actionPathToolType(entry),
		strings.TrimSpace(entry.Symbol),
		strings.TrimSpace(entry.Location),
		locationRangeKey(entry.LocationRange),
	}
	return strings.Join(parts, "|")
}

func hashActionPathIdentity(identity string) string {
	sum := sha256.Sum256([]byte(identity))
	return actionPathIDPrefix + hex.EncodeToString(sum[:6])
}

func locationRangeKey(locationRange *model.LocationRange) string {
	if locationRange == nil {
		return ""
	}
	return strconv.Itoa(locationRange.StartLine) + ":" + strconv.Itoa(locationRange.EndLine)
}

func mergeActionPath(current, incoming ActionPath) ActionPath {
	merged := current
	merged.WriteCapable = current.WriteCapable || incoming.WriteCapable
	merged.PullRequestWrite = current.PullRequestWrite || incoming.PullRequestWrite
	merged.MergeExecute = current.MergeExecute || incoming.MergeExecute
	merged.DeployWrite = current.DeployWrite || incoming.DeployWrite
	merged.ProductionWrite = current.ProductionWrite || incoming.ProductionWrite
	merged.ApprovalGap = current.ApprovalGap || incoming.ApprovalGap
	merged.CredentialAccess = current.CredentialAccess || incoming.CredentialAccess
	merged.DeliveryChainStatus = actionPathDeliveryChainStatus(merged.PullRequestWrite, merged.MergeExecute, merged.DeployWrite)
	merged.AttackPathScore = maxFloat64(current.AttackPathScore, incoming.AttackPathScore)
	merged.RiskScore = maxFloat64(current.RiskScore, incoming.RiskScore)
	merged.ApprovalGapReasons = dedupeSortedStrings(append(append([]string(nil), current.ApprovalGapReasons...), incoming.ApprovalGapReasons...))
	merged.MatchedProductionTargets = dedupeSortedStrings(append(append([]string(nil), current.MatchedProductionTargets...), incoming.MatchedProductionTargets...))
	merged.ProductionTargetStatus = mergeProductionTargetStatus(current.ProductionTargetStatus, incoming.ProductionTargetStatus)
	merged.SecurityVisibilityStatus = mergeSecurityVisibilityStatus(current.SecurityVisibilityStatus, incoming.SecurityVisibilityStatus)
	merged.DeploymentStatus = mergeDeploymentStatus(current.DeploymentStatus, incoming.DeploymentStatus)
	merged.OperationalOwner, merged.OwnerSource, merged.OwnershipStatus = mergeOperationalOwner(current, incoming)
	merged.ExecutionIdentity, merged.ExecutionIdentityType, merged.ExecutionIdentitySource, merged.ExecutionIdentityStatus, merged.ExecutionIdentityRationale = mergeExecutionIdentity(current, incoming)
	merged.BusinessStateSurface = mergeBusinessStateSurface(current.BusinessStateSurface, incoming.BusinessStateSurface)
	merged.RecommendedAction = recommendedActionForPath(merged)
	return merged
}

func summarizeActionPaths(paths []ActionPath) ActionPathSummary {
	summary := ActionPathSummary{TotalPaths: len(paths)}
	for _, path := range paths {
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
	return summary
}

func ApplyGovernFirstProfile(profileName string, paths []ActionPath) ([]ActionPath, *ActionPathToControlFirst) {
	if len(paths) == 0 {
		return nil, nil
	}
	filtered := append([]ActionPath(nil), paths...)
	if strings.EqualFold(strings.TrimSpace(profileName), "assessment") {
		filtered = make([]ActionPath, 0, len(paths))
		for _, path := range paths {
			if assessmentSuppressesPath(path) {
				continue
			}
			filtered = append(filtered, path)
		}
	}
	return filtered, buildActionPathChoice(filtered)
}

func buildActionPathChoice(paths []ActionPath) *ActionPathToControlFirst {
	if len(paths) == 0 {
		return nil
	}
	return &ActionPathToControlFirst{
		Summary: summarizeActionPaths(paths),
		Path:    paths[0],
	}
}

func dedupeSortedStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func actionPathDeliveryChainStatus(pullRequestWrite, mergeExecute, deployWrite bool) string {
	switch {
	case pullRequestWrite && mergeExecute && deployWrite:
		return "pr_merge_deploy"
	case mergeExecute && deployWrite:
		return "merge_deploy"
	case pullRequestWrite && mergeExecute:
		return "pr_merge"
	case deployWrite:
		return "deploy_only"
	case pullRequestWrite:
		return "pr_only"
	case mergeExecute:
		return "merge_only"
	default:
		return "none"
	}
}

func assessmentSuppressesPath(path ActionPath) bool {
	for _, value := range []string{path.Repo, path.Location} {
		if value == "" {
			continue
		}
		for _, segment := range assessmentSegments(value) {
			if assessmentSuppressionToken(segment) {
				return true
			}
		}
	}
	return false
}

func assessmentSegments(value string) []string {
	raw := strings.ToLower(strings.TrimSpace(value))
	if raw == "" {
		return nil
	}

	segments := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	seen := map[string]struct{}{}
	out := make([]string, 0, len(segments)*4)
	for _, segment := range segments {
		for _, candidate := range assessmentSegmentCandidates(segment) {
			if _, ok := seen[candidate]; ok {
				continue
			}
			seen[candidate] = struct{}{}
			out = append(out, candidate)
		}
	}
	return out
}

func assessmentSegmentCandidates(segment string) []string {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return nil
	}

	candidates := []string{segment}
	trimmed := strings.Trim(segment, " ._-")
	if trimmed != "" && trimmed != segment {
		candidates = append(candidates, trimmed)
	}
	if trimmed != "" {
		parts := strings.FieldsFunc(trimmed, func(r rune) bool {
			return r == '-' || r == '_' || r == '.'
		})
		for _, part := range parts {
			if part == "" || part == trimmed {
				continue
			}
			candidates = append(candidates, part)
		}
		if dot := strings.LastIndex(trimmed, "."); dot > 0 {
			base := trimmed[:dot]
			if base != "" && base != trimmed {
				candidates = append(candidates, base)
			}
		}
	}
	return candidates
}

func assessmentSuppressionToken(value string) bool {
	switch value {
	case "examples", "example", "sample", "samples", "demo", "tests", "test", "testdata", "fixtures", "vendor", "node_modules", ".venv", "venv", "generated", "__generated__":
		return true
	default:
		return false
	}
}

func mergeProductionTargetStatus(current, incoming string) string {
	switch {
	case strings.TrimSpace(current) == agginventory.ProductionTargetsStatusInvalid || strings.TrimSpace(incoming) == agginventory.ProductionTargetsStatusInvalid:
		return agginventory.ProductionTargetsStatusInvalid
	case strings.TrimSpace(current) == agginventory.ProductionTargetsStatusConfigured || strings.TrimSpace(incoming) == agginventory.ProductionTargetsStatusConfigured:
		return agginventory.ProductionTargetsStatusConfigured
	case strings.TrimSpace(current) != "":
		return strings.TrimSpace(current)
	default:
		return strings.TrimSpace(incoming)
	}
}

func mergeSecurityVisibilityStatus(current, incoming string) string {
	if securityVisibilityPriority(incoming) < securityVisibilityPriority(current) {
		return strings.TrimSpace(incoming)
	}
	return strings.TrimSpace(current)
}

func securityVisibilityPriority(status string) int {
	switch strings.TrimSpace(status) {
	case agginventory.SecurityVisibilityUnknownToSecurity:
		return 0
	case agginventory.SecurityVisibilityKnownUnapproved:
		return 1
	case agginventory.SecurityVisibilityApproved:
		return 2
	case "":
		return 3
	default:
		return 4
	}
}

func mergeDeploymentStatus(current, incoming string) string {
	currentNormalized := strings.TrimSpace(current)
	incomingNormalized := strings.TrimSpace(incoming)
	switch {
	case strings.EqualFold(currentNormalized, "deployed") || strings.EqualFold(incomingNormalized, "deployed"):
		return "deployed"
	case currentNormalized == "" || strings.EqualFold(currentNormalized, "unknown"):
		return incomingNormalized
	case incomingNormalized == "" || strings.EqualFold(incomingNormalized, "unknown"):
		return currentNormalized
	case currentNormalized <= incomingNormalized:
		return currentNormalized
	default:
		return incomingNormalized
	}
}

func mergeOperationalOwner(current, incoming ActionPath) (string, string, string) {
	currentPriority := ownershipPriority(current.OwnershipStatus)
	incomingPriority := ownershipPriority(incoming.OwnershipStatus)
	switch {
	case incomingPriority < currentPriority:
		return incoming.OperationalOwner, incoming.OwnerSource, incoming.OwnershipStatus
	case currentPriority < incomingPriority:
		return current.OperationalOwner, current.OwnerSource, current.OwnershipStatus
	default:
		return canonicalString(current.OperationalOwner, incoming.OperationalOwner),
			canonicalString(current.OwnerSource, incoming.OwnerSource),
			canonicalString(current.OwnershipStatus, incoming.OwnershipStatus)
	}
}

func ownershipPriority(status string) int {
	switch strings.TrimSpace(status) {
	case "explicit":
		return 0
	case "inferred":
		return 1
	case "unresolved":
		return 2
	case "":
		return 3
	default:
		return 4
	}
}

func governFirstOwnershipPriority(path ActionPath) int {
	switch {
	case strings.TrimSpace(path.OwnerSource) == "multi_repo_conflict":
		return 0
	case strings.TrimSpace(path.OwnershipStatus) == "unresolved":
		return 1
	case strings.TrimSpace(path.OwnershipStatus) == "inferred":
		return 2
	case strings.TrimSpace(path.OwnershipStatus) == "explicit":
		return 3
	default:
		return 4
	}
}

func mergeExecutionIdentity(current, incoming ActionPath) (string, string, string, string, string) {
	currentStatus := strings.TrimSpace(current.ExecutionIdentityStatus)
	incomingStatus := strings.TrimSpace(incoming.ExecutionIdentityStatus)
	switch {
	case currentStatus == "ambiguous" || incomingStatus == "ambiguous":
		return "", "ambiguous", "", "ambiguous", "multiple non-human identity candidates matched this path"
	case currentStatus == "known" && incomingStatus == "known":
		if current.ExecutionIdentity == incoming.ExecutionIdentity &&
			current.ExecutionIdentityType == incoming.ExecutionIdentityType &&
			current.ExecutionIdentitySource == incoming.ExecutionIdentitySource {
			return current.ExecutionIdentity, current.ExecutionIdentityType, current.ExecutionIdentitySource, "known", current.ExecutionIdentityRationale
		}
		return "", "ambiguous", "", "ambiguous", "multiple non-human identity candidates matched this path"
	case currentStatus == "known":
		return current.ExecutionIdentity, current.ExecutionIdentityType, current.ExecutionIdentitySource, currentStatus, current.ExecutionIdentityRationale
	case incomingStatus == "known":
		return incoming.ExecutionIdentity, incoming.ExecutionIdentityType, incoming.ExecutionIdentitySource, incomingStatus, incoming.ExecutionIdentityRationale
	case currentStatus == "":
		return incoming.ExecutionIdentity, incoming.ExecutionIdentityType, incoming.ExecutionIdentitySource, incomingStatus, incoming.ExecutionIdentityRationale
	default:
		return current.ExecutionIdentity, current.ExecutionIdentityType, current.ExecutionIdentitySource, currentStatus, current.ExecutionIdentityRationale
	}
}

func canonicalString(current, incoming string) string {
	current = strings.TrimSpace(current)
	incoming = strings.TrimSpace(incoming)
	switch {
	case current == "":
		return incoming
	case incoming == "":
		return current
	case current <= incoming:
		return current
	default:
		return incoming
	}
}

func maxFloat64(current, incoming float64) float64 {
	if incoming > current {
		return incoming
	}
	return current
}

func correlateExecutionIdentity(entry agginventory.AgentPrivilegeMapEntry, identities []agginventory.NonHumanIdentity) (string, string, string, string, string) {
	if len(identities) == 0 {
		return "", "", "", "unknown", "no static non-human identity evidence matched this path"
	}
	matches := make([]agginventory.NonHumanIdentity, 0)
	for _, identity := range identities {
		if strings.TrimSpace(identity.Org) != strings.TrimSpace(entry.Org) {
			continue
		}
		if !entryContainsRepo(entry, identity.Repo) {
			continue
		}
		if strings.TrimSpace(identity.Location) != strings.TrimSpace(entry.Location) {
			continue
		}
		matches = append(matches, identity)
	}
	if len(matches) == 0 {
		return "", "", "", "unknown", "no static non-human identity evidence matched this path"
	}
	if len(matches) == 1 {
		if strings.TrimSpace(matches[0].IdentityType) == "unknown" {
			return "", "unknown", strings.TrimSpace(matches[0].Source), "unknown", "static identity evidence stayed ambiguous for this path"
		}
		return strings.TrimSpace(matches[0].Subject), strings.TrimSpace(matches[0].IdentityType), strings.TrimSpace(matches[0].Source), "known", "static workflow identity evidence matched this path"
	}
	unique := map[string]agginventory.NonHumanIdentity{}
	for _, item := range matches {
		key := strings.Join([]string{item.IdentityType, item.Subject, item.Source}, "|")
		unique[key] = item
	}
	if len(unique) == 1 {
		for _, item := range unique {
			if strings.TrimSpace(item.IdentityType) == "unknown" {
				return "", "unknown", strings.TrimSpace(item.Source), "unknown", "static identity evidence stayed ambiguous for this path"
			}
			return strings.TrimSpace(item.Subject), strings.TrimSpace(item.IdentityType), strings.TrimSpace(item.Source), "known", "static workflow identity evidence matched this path"
		}
	}
	return "", "ambiguous", "", "ambiguous", fmt.Sprintf("%d non-human identity candidates matched this path", len(unique))
}

func entryContainsRepo(entry agginventory.AgentPrivilegeMapEntry, repo string) bool {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return false
	}
	for _, candidate := range entry.Repos {
		if strings.TrimSpace(candidate) == repo {
			return true
		}
	}
	return firstRepoFromEntry(entry) == repo
}

func classifyBusinessStateSurface(entry agginventory.AgentPrivilegeMapEntry) string {
	permissions := normalizeGovernFirstTokens(entry.Permissions)
	boundTools := normalizeGovernFirstTokens(entry.BoundTools)
	dataClass := strings.TrimSpace(entry.DataClass)

	switch {
	case hasGovernFirstPrefix(permissions, "mcp.admin") || hasGovernFirstToken(permissions, "admin"):
		return "admin_api"
	case hasGovernFirstToken(permissions, "db.write") || strings.EqualFold(dataClass, "database"):
		return "db"
	case entry.DeployWrite || entry.ProductionWrite || hasGovernFirstToken(permissions, "deploy.write"):
		return "deploy"
	case hasTicketingSurface(permissions, boundTools):
		return "ticketing"
	case hasSaaSWriteSurface(permissions, boundTools):
		return "saas_write"
	case entry.MergeExecute:
		return "workflow_control"
	case hasGovernFirstToken(permissions, "repo.write"), hasGovernFirstToken(permissions, "pull_request.write"), hasGovernFirstToken(permissions, "iac.write"):
		return "code"
	default:
		return "code"
	}
}

func mergeBusinessStateSurface(current, incoming string) string {
	if businessStateSurfacePriority(incoming) < businessStateSurfacePriority(current) {
		return strings.TrimSpace(incoming)
	}
	return strings.TrimSpace(current)
}

func businessStateSurfacePriority(surface string) int {
	switch strings.TrimSpace(surface) {
	case "admin_api":
		return 0
	case "db":
		return 1
	case "deploy":
		return 2
	case "ticketing":
		return 3
	case "saas_write":
		return 4
	case "workflow_control":
		return 5
	case "code":
		return 6
	case "":
		return 7
	default:
		return 8
	}
}

func normalizeGovernFirstTokens(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.ToLower(strings.TrimSpace(value))
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return dedupeSortedStrings(out)
}

func hasGovernFirstToken(values []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func hasGovernFirstPrefix(values []string, prefix string) bool {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	for _, value := range values {
		if strings.HasPrefix(strings.TrimSpace(value), prefix) {
			return true
		}
	}
	return false
}

func hasTicketingSurface(permissions, boundTools []string) bool {
	for _, values := range [][]string{permissions, boundTools} {
		for _, value := range values {
			switch {
			case strings.Contains(value, "ticket.write"),
				strings.Contains(value, "jira"),
				strings.Contains(value, "linear"),
				strings.Contains(value, "issue.write"):
				return true
			}
		}
	}
	return false
}

func hasSaaSWriteSurface(permissions, boundTools []string) bool {
	for _, values := range [][]string{permissions, boundTools} {
		for _, value := range values {
			switch {
			case strings.HasPrefix(value, "mcp.write"),
				strings.HasPrefix(value, "crm."),
				strings.HasPrefix(value, "saas."),
				strings.HasSuffix(value, ".write") && !strings.HasPrefix(value, "repo.") && !strings.HasPrefix(value, "pull_request.") && !strings.HasPrefix(value, "deploy.") && !strings.HasPrefix(value, "db.") && !strings.HasPrefix(value, "ticket.") && !strings.HasPrefix(value, "iac."):
				return true
			}
		}
	}
	return false
}
