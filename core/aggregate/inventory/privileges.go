package inventory

import (
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
)

const (
	ProductionTargetsStatusConfigured    = "configured"
	ProductionTargetsStatusNotConfigured = "not_configured"
	ProductionTargetsStatusInvalid       = "invalid"

	CredentialProvenanceStaticSecret     = "static_secret"
	CredentialProvenanceWorkloadIdentity = "workload_identity"
	CredentialProvenanceInheritedHuman   = "inherited_human"
	CredentialProvenanceOAuthDelegation  = "oauth_delegation"
	CredentialProvenanceJIT              = "jit"
	CredentialProvenanceUnknown          = "unknown"

	CredentialScopeRepository  = "repository"
	CredentialScopeWorkflow    = "workflow"
	CredentialScopeTool        = "tool"
	CredentialScopeEnvironment = "environment"
	CredentialScopeOrg         = "organization"
	CredentialScopeUnknown     = "unknown"
)

type ProductionWriteBudget struct {
	Configured bool   `json:"configured" yaml:"configured"`
	Status     string `json:"status" yaml:"status"`
	Count      *int   `json:"count" yaml:"count"`
}

type CredentialProvenance struct {
	Type           string   `json:"type" yaml:"type"`
	Subject        string   `json:"subject,omitempty" yaml:"subject,omitempty"`
	Scope          string   `json:"scope" yaml:"scope"`
	Confidence     string   `json:"confidence" yaml:"confidence"`
	EvidenceBasis  []string `json:"evidence_basis,omitempty" yaml:"evidence_basis,omitempty"`
	RiskMultiplier float64  `json:"risk_multiplier" yaml:"risk_multiplier"`
}

type PrivilegeBudget struct {
	TotalTools            int                   `json:"total_tools" yaml:"total_tools"`
	WriteCapableTools     int                   `json:"write_capable_tools" yaml:"write_capable_tools"`
	CredentialAccessTools int                   `json:"credential_access_tools" yaml:"credential_access_tools"`
	ExecCapableTools      int                   `json:"exec_capable_tools" yaml:"exec_capable_tools"`
	ProductionWrite       ProductionWriteBudget `json:"production_write" yaml:"production_write"`
}

type AgentPrivilegeMapEntry struct {
	AgentID                  string                     `json:"agent_id" yaml:"agent_id"`
	AgentInstanceID          string                     `json:"agent_instance_id,omitempty" yaml:"agent_instance_id,omitempty"`
	ToolID                   string                     `json:"tool_id" yaml:"tool_id"`
	ToolType                 string                     `json:"tool_type" yaml:"tool_type"`
	Framework                string                     `json:"framework,omitempty" yaml:"framework,omitempty"`
	Symbol                   string                     `json:"symbol,omitempty" yaml:"symbol,omitempty"`
	Org                      string                     `json:"org" yaml:"org"`
	Repos                    []string                   `json:"repos" yaml:"repos"`
	Permissions              []string                   `json:"permissions" yaml:"permissions"`
	WritePathClasses         []string                   `json:"write_path_classes,omitempty" yaml:"write_path_classes,omitempty"`
	GovernanceControls       []GovernanceControlMapping `json:"governance_controls,omitempty" yaml:"governance_controls,omitempty"`
	Location                 string                     `json:"location,omitempty" yaml:"location,omitempty"`
	LocationRange            *model.LocationRange       `json:"location_range,omitempty" yaml:"location_range,omitempty"`
	EndpointClass            string                     `json:"endpoint_class" yaml:"endpoint_class"`
	DataClass                string                     `json:"data_class" yaml:"data_class"`
	AutonomyLevel            string                     `json:"autonomy_level" yaml:"autonomy_level"`
	RiskScore                float64                    `json:"risk_score" yaml:"risk_score"`
	ApprovalClassification   string                     `json:"approval_classification,omitempty" yaml:"approval_classification,omitempty"`
	SecurityVisibilityStatus string                     `json:"security_visibility_status,omitempty" yaml:"security_visibility_status,omitempty"`
	BoundTools               []string                   `json:"bound_tools,omitempty" yaml:"bound_tools,omitempty"`
	BoundDataSources         []string                   `json:"bound_data_sources,omitempty" yaml:"bound_data_sources,omitempty"`
	BoundAuthSurfaces        []string                   `json:"bound_auth_surfaces,omitempty" yaml:"bound_auth_surfaces,omitempty"`
	BindingEvidenceKeys      []string                   `json:"binding_evidence_keys,omitempty" yaml:"binding_evidence_keys,omitempty"`
	MissingBindings          []string                   `json:"missing_bindings,omitempty" yaml:"missing_bindings,omitempty"`
	DeploymentStatus         string                     `json:"deployment_status,omitempty" yaml:"deployment_status,omitempty"`
	DeploymentArtifacts      []string                   `json:"deployment_artifacts,omitempty" yaml:"deployment_artifacts,omitempty"`
	DeploymentEvidenceKeys   []string                   `json:"deployment_evidence_keys,omitempty" yaml:"deployment_evidence_keys,omitempty"`
	WorkflowTriggerClass     string                     `json:"workflow_trigger_class,omitempty" yaml:"workflow_trigger_class,omitempty"`
	OperationalOwner         string                     `json:"operational_owner,omitempty" yaml:"operational_owner,omitempty"`
	OwnerSource              string                     `json:"owner_source,omitempty" yaml:"owner_source,omitempty"`
	OwnershipStatus          string                     `json:"ownership_status,omitempty" yaml:"ownership_status,omitempty"`
	OwnershipState           string                     `json:"ownership_state,omitempty" yaml:"ownership_state,omitempty"`
	OwnershipConfidence      float64                    `json:"ownership_confidence,omitempty" yaml:"ownership_confidence,omitempty"`
	OwnershipEvidence        []string                   `json:"ownership_evidence_basis,omitempty" yaml:"ownership_evidence_basis,omitempty"`
	OwnershipConflicts       []string                   `json:"ownership_conflicts,omitempty" yaml:"ownership_conflicts,omitempty"`
	ApprovalGapReasons       []string                   `json:"approval_gap_reasons,omitempty" yaml:"approval_gap_reasons,omitempty"`
	TrustDepth               *TrustDepth                `json:"trust_depth,omitempty" yaml:"trust_depth,omitempty"`
	PullRequestWrite         bool                       `json:"pull_request_write,omitempty" yaml:"pull_request_write,omitempty"`
	MergeExecute             bool                       `json:"merge_execute,omitempty" yaml:"merge_execute,omitempty"`
	DeployWrite              bool                       `json:"deploy_write,omitempty" yaml:"deploy_write,omitempty"`
	DeliveryChainStatus      string                     `json:"delivery_chain_status,omitempty" yaml:"delivery_chain_status,omitempty"`
	ProductionTargetStatus   string                     `json:"production_target_status,omitempty" yaml:"production_target_status,omitempty"`
	WriteCapable             bool                       `json:"write_capable" yaml:"write_capable"`
	CredentialAccess         bool                       `json:"credential_access" yaml:"credential_access"`
	CredentialProvenance     *CredentialProvenance      `json:"credential_provenance,omitempty" yaml:"credential_provenance,omitempty"`
	ExecCapable              bool                       `json:"exec_capable" yaml:"exec_capable"`
	ProductionWrite          bool                       `json:"production_write" yaml:"production_write"`
	MatchedProductionTargets []string                   `json:"matched_production_targets,omitempty" yaml:"matched_production_targets,omitempty"`
}

func CloneCredentialProvenance(in *CredentialProvenance) *CredentialProvenance {
	if in == nil {
		return nil
	}
	out := *in
	out.Type = strings.TrimSpace(out.Type)
	out.Subject = strings.TrimSpace(out.Subject)
	out.Scope = strings.TrimSpace(out.Scope)
	out.Confidence = strings.TrimSpace(out.Confidence)
	out.EvidenceBasis = append([]string(nil), in.EvidenceBasis...)
	return &out
}

func NormalizeCredentialProvenance(in *CredentialProvenance) *CredentialProvenance {
	if in == nil {
		return nil
	}
	out := CloneCredentialProvenance(in)
	out.Type = normalizeCredentialProvenanceType(out.Type)
	out.Scope = normalizeCredentialScope(out.Scope)
	out.Confidence = normalizeCredentialConfidence(out.Confidence)
	if out.RiskMultiplier == 0 {
		out.RiskMultiplier = CredentialRiskMultiplier(out.Type)
	}
	out.EvidenceBasis = mergeCredentialEvidenceBasis(out.EvidenceBasis)
	return out
}

func CredentialRiskMultiplier(kind string) float64 {
	switch normalizeCredentialProvenanceType(kind) {
	case CredentialProvenanceStaticSecret:
		return 1.05
	case CredentialProvenanceInheritedHuman:
		return 1.10
	case CredentialProvenanceOAuthDelegation:
		return 1.05
	case CredentialProvenanceJIT:
		return 1.00
	case CredentialProvenanceWorkloadIdentity:
		return 1.00
	default:
		return 1.20
	}
}

func normalizeCredentialProvenanceType(value string) string {
	switch strings.TrimSpace(value) {
	case CredentialProvenanceStaticSecret,
		CredentialProvenanceWorkloadIdentity,
		CredentialProvenanceInheritedHuman,
		CredentialProvenanceOAuthDelegation,
		CredentialProvenanceJIT:
		return strings.TrimSpace(value)
	default:
		return CredentialProvenanceUnknown
	}
}

func normalizeCredentialScope(value string) string {
	switch strings.TrimSpace(value) {
	case CredentialScopeRepository,
		CredentialScopeWorkflow,
		CredentialScopeTool,
		CredentialScopeEnvironment,
		CredentialScopeOrg:
		return strings.TrimSpace(value)
	default:
		return CredentialScopeUnknown
	}
}

func normalizeCredentialConfidence(value string) string {
	switch strings.TrimSpace(value) {
	case "high", "medium", "low":
		return strings.TrimSpace(value)
	default:
		return "low"
	}
}

func mergeCredentialEvidenceBasis(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
