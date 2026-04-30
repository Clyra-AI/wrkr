package inventory

import (
	"sort"
	"strings"
)

const (
	WritePathRead                   = "read"
	WritePathWrite                  = "write"
	WritePathPullRequestWrite       = "pr_write"
	WritePathRepoWrite              = "repo_write"
	WritePathReleaseWrite           = "release_write"
	WritePathPackagePublish         = "package_publish"
	WritePathDeployWrite            = "deploy_write"
	WritePathInfraWrite             = "infra_write"
	WritePathSecretBearingExec      = "secret_bearing_execution"
	WritePathProductionAdjacent     = "production_adjacent_write"
	GovernanceControlOwnerAssigned  = "owner_assigned"
	GovernanceControlApproval       = "approval_recorded"
	GovernanceControlLeastPrivilege = "least_privilege_verified"
	GovernanceControlRotation       = "rotation_evidence_attached"
	GovernanceControlDeploymentGate = "deployment_gate_present"
	GovernanceControlProduction     = "production_access_classified"
	GovernanceControlProof          = "proof_artifact_generated"
	GovernanceControlReviewCadence  = "review_cadence_set"
	ControlStatusSatisfied          = "satisfied"
	ControlStatusGap                = "gap"
	ControlStatusNotApplicable      = "not_applicable"

	ActionClassRead             = "read"
	ActionClassWrite            = "write"
	ActionClassDeploy           = "deploy"
	ActionClassDelete           = "delete"
	ActionClassExecute          = "execute"
	ActionClassEgress           = "egress"
	ActionClassCredentialAccess = "credential_access"
)

type GovernanceControlMapping struct {
	Control  string   `json:"control" yaml:"control"`
	Status   string   `json:"status" yaml:"status"`
	Evidence []string `json:"evidence,omitempty" yaml:"evidence,omitempty"`
	Gaps     []string `json:"gaps,omitempty" yaml:"gaps,omitempty"`
}

type GovernanceControlInput struct {
	Owner                    string
	OwnershipStatus          string
	ApprovalStatus           string
	ApprovalClassification   string
	LifecycleState           string
	SecurityVisibilityStatus string
	DeploymentGate           string
	ProofRequirement         string
	ProductionTargetStatus   string
	WritePathClasses         []string
	CredentialAccess         bool
	ProductionWrite          bool
	EvidenceBasis            []string
}

type ActionClassInput struct {
	Permissions      []string
	WritePathClasses []string
	WriteCapable     bool
	CredentialAccess bool
	DeployWrite      bool
	ProductionWrite  bool
	MatchedTargets   []string
	ToolType         string
	Location         string
}

func DeriveWritePathClasses(permissions []string, writeCapable, pullRequestWrite, mergeExecute, deployWrite, credentialAccess, productionWrite bool, location, toolType string) []string {
	values := make([]string, 0)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			values = append(values, value)
		}
	}
	if writeCapable {
		add(WritePathWrite)
	}
	if pullRequestWrite {
		add(WritePathPullRequestWrite)
	}
	if mergeExecute {
		add(WritePathRepoWrite)
	}
	if deployWrite {
		add(WritePathDeployWrite)
	}
	if credentialAccess && (writeCapable || pullRequestWrite || mergeExecute || deployWrite || productionWrite) {
		add(WritePathSecretBearingExec)
	}
	if productionWrite {
		add(WritePathProductionAdjacent)
	}
	locationLower := strings.ToLower(strings.TrimSpace(location))
	toolLower := strings.ToLower(strings.TrimSpace(toolType))
	if strings.Contains(locationLower, "release") || strings.Contains(toolLower, "release") {
		add(WritePathReleaseWrite)
	}
	for _, permission := range permissions {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		switch {
		case normalized == "pull_request.write" || normalized == "pull-requests.write":
			add(WritePathPullRequestWrite)
		case normalized == "repo.write" || normalized == "repo.contents.write" || normalized == "filesystem.write" || normalized == "contents.write" || normalized == "merge.execute":
			add(WritePathRepoWrite)
		case normalized == "release.write":
			add(WritePathReleaseWrite)
		case normalized == "package.write" || normalized == "packages.write" || normalized == "package.publish":
			add(WritePathPackagePublish)
		case normalized == "deploy.write":
			add(WritePathDeployWrite)
		case normalized == "iac.write" || normalized == "infra.write" || normalized == "db.write":
			add(WritePathInfraWrite)
		case strings.Contains(normalized, "secret") || strings.Contains(normalized, "token") || strings.Contains(normalized, "credential"):
			if writeCapable || pullRequestWrite || mergeExecute || deployWrite || productionWrite {
				add(WritePathSecretBearingExec)
			}
		case strings.Contains(normalized, ".write") || strings.HasSuffix(normalized, "write"):
			add(WritePathWrite)
		}
	}
	out := sortedUnique(values)
	if len(out) == 0 {
		return []string{WritePathRead}
	}
	return out
}

func DeriveActionClasses(input ActionClassInput) ([]string, []string) {
	classes := make([]string, 0, 7)
	reasons := make([]string, 0, 16)
	add := func(className string, reason string) {
		className = strings.TrimSpace(className)
		reason = strings.TrimSpace(reason)
		if className != "" {
			classes = append(classes, className)
		}
		if reason != "" {
			reasons = append(reasons, reason)
		}
	}

	if len(input.Permissions) == 0 && len(input.WritePathClasses) == 0 && !input.WriteCapable && !input.CredentialAccess && !input.DeployWrite && !input.ProductionWrite {
		return nil, nil
	}

	add(ActionClassRead, "baseline:discovered_surface")
	if input.WriteCapable || hasAnyWriteClass(input.WritePathClasses) {
		add(ActionClassWrite, "write_path:write_capable")
	}
	if input.DeployWrite || input.ProductionWrite || contains(input.WritePathClasses, WritePathDeployWrite) || contains(input.WritePathClasses, WritePathReleaseWrite) || contains(input.WritePathClasses, WritePathProductionAdjacent) {
		add(ActionClassDeploy, "write_path:deploy")
	}
	if input.CredentialAccess || contains(input.WritePathClasses, WritePathSecretBearingExec) {
		add(ActionClassCredentialAccess, "credential_access:true")
	}

	for _, permission := range input.Permissions {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		switch {
		case strings.Contains(normalized, "exec"), strings.Contains(normalized, "run"), strings.Contains(normalized, "workflow_dispatch"):
			add(ActionClassExecute, "permission:"+normalized)
		case strings.Contains(normalized, "delete"), strings.Contains(normalized, "destroy"), strings.Contains(normalized, "remove"):
			add(ActionClassDelete, "permission:"+normalized)
		case strings.Contains(normalized, "deploy"):
			add(ActionClassDeploy, "permission:"+normalized)
		case strings.Contains(normalized, "write"), strings.Contains(normalized, "merge"):
			add(ActionClassWrite, "permission:"+normalized)
		case strings.Contains(normalized, "secret"), strings.Contains(normalized, "token"), strings.Contains(normalized, "credential"), strings.Contains(normalized, "oidc"), strings.Contains(normalized, "oauth"):
			add(ActionClassCredentialAccess, "permission:"+normalized)
		case strings.Contains(normalized, "mcp."), strings.Contains(normalized, "a2a"), strings.Contains(normalized, "http"), strings.Contains(normalized, "network"), strings.Contains(normalized, "api"):
			add(ActionClassEgress, "permission:"+normalized)
		}
	}

	for _, className := range input.WritePathClasses {
		switch strings.TrimSpace(className) {
		case WritePathPackagePublish, WritePathReleaseWrite, WritePathDeployWrite, WritePathProductionAdjacent:
			add(ActionClassDeploy, "write_path_class:"+strings.TrimSpace(className))
		case WritePathInfraWrite:
			add(ActionClassExecute, "write_path_class:"+strings.TrimSpace(className))
			add(ActionClassDeploy, "write_path_class:"+strings.TrimSpace(className))
		case WritePathSecretBearingExec:
			add(ActionClassExecute, "write_path_class:"+strings.TrimSpace(className))
			add(ActionClassCredentialAccess, "write_path_class:"+strings.TrimSpace(className))
		case WritePathPullRequestWrite, WritePathRepoWrite, WritePathWrite:
			add(ActionClassWrite, "write_path_class:"+strings.TrimSpace(className))
		}
	}

	toolType := strings.ToLower(strings.TrimSpace(input.ToolType))
	location := strings.ToLower(strings.TrimSpace(input.Location))
	if strings.Contains(toolType, "mcp") || strings.Contains(toolType, "a2a") || strings.Contains(location, "http") {
		add(ActionClassEgress, "tool_type:"+strings.TrimSpace(input.ToolType))
	}
	if strings.Contains(location, "delete") || strings.Contains(location, "destroy") {
		add(ActionClassDelete, "location:"+strings.TrimSpace(input.Location))
	}
	if len(input.MatchedTargets) > 0 {
		add(ActionClassDeploy, "matched_target:"+strings.TrimSpace(input.MatchedTargets[0]))
	}

	return sortedUnique(classes), sortedUnique(reasons)
}

func BuildGovernanceControls(input GovernanceControlInput) []GovernanceControlMapping {
	writeClasses := sortedUnique(input.WritePathClasses)
	hasWrite := hasAnyWriteClass(writeClasses)
	hasSecret := input.CredentialAccess || contains(writeClasses, WritePathSecretBearingExec)
	hasDelivery := input.ProductionWrite ||
		contains(writeClasses, WritePathDeployWrite) ||
		contains(writeClasses, WritePathReleaseWrite) ||
		contains(writeClasses, WritePathPackagePublish) ||
		contains(writeClasses, WritePathInfraWrite) ||
		contains(writeClasses, WritePathProductionAdjacent)

	controls := []GovernanceControlMapping{
		controlStatus(
			GovernanceControlOwnerAssigned,
			strings.TrimSpace(input.Owner) != "" && strings.TrimSpace(input.OwnershipStatus) != "unresolved",
			[]string{"owner=" + strings.TrimSpace(input.Owner), "ownership_status=" + fallback(input.OwnershipStatus, "unknown")},
			[]string{"owner_missing"},
		),
		controlStatus(
			GovernanceControlApproval,
			approvalSatisfied(input.ApprovalStatus, input.ApprovalClassification, input.SecurityVisibilityStatus),
			[]string{"approval_status=" + fallback(input.ApprovalStatus, input.ApprovalClassification)},
			[]string{"approval_evidence_missing"},
		),
	}

	if hasWrite {
		controls = append(controls, controlStatus(
			GovernanceControlLeastPrivilege,
			evidenceContains(input.EvidenceBasis, "least_privilege"),
			[]string{"write_path_classes=" + strings.Join(writeClasses, ",")},
			[]string{"least_privilege_evidence_missing"},
		))
	} else {
		controls = append(controls, notApplicable(GovernanceControlLeastPrivilege, "no_write_path_class"))
	}

	if hasSecret {
		controls = append(controls, controlStatus(
			GovernanceControlRotation,
			evidenceContains(input.EvidenceBasis, "rotation"),
			[]string{"credential_access=true"},
			[]string{"rotation_evidence_missing"},
		))
	} else {
		controls = append(controls, notApplicable(GovernanceControlRotation, "no_secret_bearing_execution"))
	}

	if hasDelivery {
		controls = append(controls, controlStatus(
			GovernanceControlDeploymentGate,
			strings.TrimSpace(input.DeploymentGate) == "approved",
			[]string{"deployment_gate=" + fallback(input.DeploymentGate, "unknown")},
			[]string{"deployment_gate_evidence_missing"},
		))
		controls = append(controls, controlStatus(
			GovernanceControlProduction,
			input.ProductionWrite || strings.TrimSpace(input.ProductionTargetStatus) == ProductionTargetsStatusConfigured,
			[]string{"production_target_status=" + fallback(input.ProductionTargetStatus, "unknown")},
			[]string{"production_access_classification_missing"},
		))
	} else {
		controls = append(controls,
			notApplicable(GovernanceControlDeploymentGate, "no_delivery_write_path"),
			notApplicable(GovernanceControlProduction, "no_production_adjacent_write_path"),
		)
	}

	if hasWrite || hasSecret || hasDelivery {
		controls = append(controls, controlStatus(
			GovernanceControlProof,
			proofSatisfied(input.ProofRequirement, input.EvidenceBasis),
			[]string{"proof_requirement=" + fallback(input.ProofRequirement, "unknown")},
			[]string{"proof_artifact_missing"},
		))
	} else {
		controls = append(controls, notApplicable(GovernanceControlProof, "read_only_path"))
	}

	controls = append(controls, controlStatus(
		GovernanceControlReviewCadence,
		evidenceContains(input.EvidenceBasis, "review_cadence") || strings.TrimSpace(input.ApprovalStatus) == "valid",
		[]string{"approval_status=" + fallback(input.ApprovalStatus, input.ApprovalClassification)},
		[]string{"review_cadence_missing"},
	))

	return controls
}

func hasCredentialAccess(tool Tool) bool {
	return hasCredentialAccessForSurface(tool.DataClass, tool.Permissions, nil)
}

func hasCredentialAccessForSurface(dataClass string, permissions []string, authSurfaces []string) bool {
	if strings.ToLower(strings.TrimSpace(dataClass)) == "credentials" {
		return true
	}
	for _, permission := range permissions {
		normalized := strings.ToLower(strings.TrimSpace(permission))
		if strings.Contains(normalized, "secret") ||
			strings.Contains(normalized, "token") ||
			strings.Contains(normalized, "credential") ||
			strings.Contains(normalized, "oauth") ||
			strings.Contains(normalized, "oidc") ||
			normalized == "id-token.write" {
			return true
		}
	}
	for _, authSurface := range authSurfaces {
		normalized := strings.ToLower(strings.TrimSpace(authSurface))
		if strings.Contains(normalized, "secret") ||
			strings.Contains(normalized, "token") ||
			strings.Contains(normalized, "credential") ||
			strings.HasSuffix(normalized, "_key") ||
			strings.Contains(normalized, "api_key") ||
			strings.Contains(normalized, "oauth") ||
			strings.Contains(normalized, "oidc") ||
			strings.Contains(normalized, "workload_identity") ||
			strings.Contains(normalized, "assume_role") ||
			strings.Contains(normalized, "sts") {
			return true
		}
	}
	return false
}

func GovernanceSecurityVisibilityStatus(status, approvalStatus, lifecycleState string) string {
	switch strings.ToLower(strings.TrimSpace(lifecycleState)) {
	case "revoked":
		return SecurityVisibilityRevoked
	case "deprecated":
		return SecurityVisibilityDeprecated
	}
	switch strings.ToLower(strings.TrimSpace(approvalStatus)) {
	case "expired", "invalid":
		return SecurityVisibilityNeedsReview
	case "accepted_risk", "risk_accepted":
		return SecurityVisibilityAcceptedRisk
	}
	switch strings.TrimSpace(status) {
	case SecurityVisibilityApproved, SecurityVisibilityKnownApproved:
		return SecurityVisibilityKnownApproved
	case SecurityVisibilityKnownUnapproved:
		return SecurityVisibilityKnownUnapproved
	case SecurityVisibilityAcceptedRisk:
		return SecurityVisibilityAcceptedRisk
	case SecurityVisibilityDeprecated:
		return SecurityVisibilityDeprecated
	case SecurityVisibilityRevoked:
		return SecurityVisibilityRevoked
	case SecurityVisibilityNeedsReview:
		return SecurityVisibilityNeedsReview
	default:
		return SecurityVisibilityUnknownToSecurity
	}
}

func controlStatus(control string, satisfied bool, evidence []string, gaps []string) GovernanceControlMapping {
	if satisfied {
		return GovernanceControlMapping{Control: control, Status: ControlStatusSatisfied, Evidence: cleanStrings(evidence)}
	}
	return GovernanceControlMapping{Control: control, Status: ControlStatusGap, Evidence: cleanStrings(evidence), Gaps: cleanStrings(gaps)}
}

func notApplicable(control, evidence string) GovernanceControlMapping {
	return GovernanceControlMapping{Control: control, Status: ControlStatusNotApplicable, Evidence: cleanStrings([]string{evidence})}
}

func approvalSatisfied(approvalStatus, approvalClass, securityVisibility string) bool {
	switch strings.TrimSpace(approvalStatus) {
	case "valid", "approved", "approved_list", "accepted_risk", "risk_accepted":
		return true
	}
	switch strings.TrimSpace(approvalClass) {
	case "approved":
		return true
	}
	switch strings.TrimSpace(securityVisibility) {
	case SecurityVisibilityApproved, SecurityVisibilityKnownApproved, SecurityVisibilityAcceptedRisk:
		return true
	default:
		return false
	}
}

func proofSatisfied(proofRequirement string, evidence []string) bool {
	switch strings.TrimSpace(proofRequirement) {
	case "evidence", "attestation":
		return true
	}
	return evidenceContains(evidence, "proof") || evidenceContains(evidence, "attestation")
}

func evidenceContains(values []string, needle string) bool {
	needle = strings.ToLower(strings.TrimSpace(needle))
	if needle == "" {
		return false
	}
	for _, value := range values {
		if strings.Contains(strings.ToLower(strings.TrimSpace(value)), needle) {
			return true
		}
	}
	return false
}

func hasAnyWriteClass(values []string) bool {
	for _, value := range values {
		switch strings.TrimSpace(value) {
		case WritePathWrite, WritePathPullRequestWrite, WritePathRepoWrite, WritePathReleaseWrite, WritePathPackagePublish, WritePathDeployWrite, WritePathInfraWrite, WritePathSecretBearingExec, WritePathProductionAdjacent:
			return true
		}
	}
	return false
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func sortedUnique(values []string) []string {
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

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.Trim(strings.TrimSpace(value), "=")
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}
