package inventory

import (
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"github.com/Clyra-AI/wrkr/core/model"
)

const (
	PathContextRuntimeSource    = "runtime_source"
	PathContextDeployableSource = "deployable_source"
	PathContextFunctionalTest   = "functional_test"
	PathContextUnitTest         = "unit_test"
	PathContextExample          = "example"
	PathContextDocs             = "docs"
	PathContextGeneratedCode    = "generated_code"
	PathContextPackageCache     = "package_cache"
	PathContextUnknown          = "unknown"

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

	CredentialKindGitHubPAT           = "github_pat"
	CredentialKindGitHubWorkflowToken = "github_workflow_token" // #nosec G101 -- Deterministic credential classification label, not a secret.
	CredentialKindGitHubAppKey        = "github_app_key"        // #nosec G101 -- Deterministic credential classification label, not a secret.
	CredentialKindDeployKey           = "deploy_key"
	CredentialKindCloudAdminKey       = "cloud_admin_key"
	CredentialKindCloudAccessKey      = "cloud_access_key"
	CredentialKindOIDCWorkloadID      = "oidc_workload_identity" // #nosec G101 -- Deterministic credential classification label, not a secret.
	CredentialKindDelegatedOAuth      = "delegated_oauth"        // #nosec G101 -- Deterministic credential classification label, not a secret.
	CredentialKindJITCredential       = "jit_credential"         // #nosec G101 -- Deterministic credential classification label, not a secret.
	CredentialKindInheritedHuman      = "inherited_human"
	CredentialKindStaticSecret        = "static_secret"
	CredentialKindUnknownDurable      = "unknown_durable"
	CredentialKindUnknown             = "unknown"

	CredentialAccessTypeStanding  = "standing"
	CredentialAccessTypeJIT       = "jit"
	CredentialAccessTypeDelegated = "delegated"
	CredentialAccessTypeWorkload  = "workload"
	CredentialAccessTypeInherited = "inherited"
	CredentialAccessTypeUnknown   = "unknown"
)

type ProductionWriteBudget struct {
	Configured bool   `json:"configured" yaml:"configured"`
	Status     string `json:"status" yaml:"status"`
	Count      *int   `json:"count" yaml:"count"`
}

type CredentialProvenance struct {
	Type                  string   `json:"type" yaml:"type"`
	Subject               string   `json:"subject,omitempty" yaml:"subject,omitempty"`
	Scope                 string   `json:"scope" yaml:"scope"`
	Confidence            string   `json:"confidence" yaml:"confidence"`
	TargetSystem          string   `json:"target_system,omitempty" yaml:"target_system,omitempty"`
	LikelyScope           string   `json:"likely_scope,omitempty" yaml:"likely_scope,omitempty"`
	ScopeConfidence       string   `json:"scope_confidence,omitempty" yaml:"scope_confidence,omitempty"`
	EvidenceBasis         []string `json:"evidence_basis,omitempty" yaml:"evidence_basis,omitempty"`
	CredentialKind        string   `json:"credential_kind,omitempty" yaml:"credential_kind,omitempty"`
	AccessType            string   `json:"access_type,omitempty" yaml:"access_type,omitempty"`
	StandingAccess        bool     `json:"standing_access" yaml:"standing_access"`
	LikelyJIT             bool     `json:"likely_jit" yaml:"likely_jit"`
	EvidenceLocation      string   `json:"evidence_location,omitempty" yaml:"evidence_location,omitempty"`
	ClassificationReasons []string `json:"classification_reasons,omitempty" yaml:"classification_reasons,omitempty"`
	RiskMultiplier        float64  `json:"risk_multiplier" yaml:"risk_multiplier"`
}

type PathContext struct {
	Kind       string   `json:"kind" yaml:"kind"`
	Confidence string   `json:"confidence" yaml:"confidence"`
	Reasons    []string `json:"reasons,omitempty" yaml:"reasons,omitempty"`
}

type PrivilegeBudget struct {
	TotalTools            int                   `json:"total_tools" yaml:"total_tools"`
	WriteCapableTools     int                   `json:"write_capable_tools" yaml:"write_capable_tools"`
	CredentialAccessTools int                   `json:"credential_access_tools" yaml:"credential_access_tools"`
	ExecCapableTools      int                   `json:"exec_capable_tools" yaml:"exec_capable_tools"`
	ProductionWrite       ProductionWriteBudget `json:"production_write" yaml:"production_write"`
}

type AgentPrivilegeMapEntry struct {
	AgentID                     string                     `json:"agent_id" yaml:"agent_id"`
	AgentInstanceID             string                     `json:"agent_instance_id,omitempty" yaml:"agent_instance_id,omitempty"`
	ToolFamilyID                string                     `json:"tool_family_id,omitempty" yaml:"tool_family_id,omitempty"`
	ToolInstanceID              string                     `json:"tool_instance_id,omitempty" yaml:"tool_instance_id,omitempty"`
	ToolID                      string                     `json:"tool_id" yaml:"tool_id"`
	ToolType                    string                     `json:"tool_type" yaml:"tool_type"`
	Framework                   string                     `json:"framework,omitempty" yaml:"framework,omitempty"`
	Symbol                      string                     `json:"symbol,omitempty" yaml:"symbol,omitempty"`
	Purpose                     string                     `json:"purpose,omitempty" yaml:"purpose,omitempty"`
	PurposeSource               string                     `json:"purpose_source,omitempty" yaml:"purpose_source,omitempty"`
	PurposeConfidence           string                     `json:"purpose_confidence,omitempty" yaml:"purpose_confidence,omitempty"`
	Version                     string                     `json:"version,omitempty" yaml:"version,omitempty"`
	VersionSource               string                     `json:"version_source,omitempty" yaml:"version_source,omitempty"`
	ConfigFingerprint           string                     `json:"config_fingerprint,omitempty" yaml:"config_fingerprint,omitempty"`
	ConfigSource                string                     `json:"config_source,omitempty" yaml:"config_source,omitempty"`
	Org                         string                     `json:"org" yaml:"org"`
	Repos                       []string                   `json:"repos" yaml:"repos"`
	MutableEndpointSemanticRefs []string                   `json:"mutable_endpoint_semantic_refs,omitempty" yaml:"mutable_endpoint_semantic_refs,omitempty"`
	CredentialAuthorityRef      string                     `json:"credential_authority_ref,omitempty" yaml:"credential_authority_ref,omitempty"`
	AuthorityBindingRefs        []string                   `json:"authority_binding_refs,omitempty" yaml:"authority_binding_refs,omitempty"`
	Permissions                 []string                   `json:"permissions" yaml:"permissions"`
	WritePathClasses            []string                   `json:"write_path_classes,omitempty" yaml:"write_path_classes,omitempty"`
	ActionClasses               []string                   `json:"action_classes,omitempty" yaml:"action_classes,omitempty"`
	ActionReasons               []string                   `json:"action_reasons,omitempty" yaml:"action_reasons,omitempty"`
	MutableEndpointSemantics    []MutableEndpointSemantic  `json:"mutable_endpoint_semantics,omitempty" yaml:"mutable_endpoint_semantics,omitempty"`
	GovernanceControls          []GovernanceControlMapping `json:"governance_controls,omitempty" yaml:"governance_controls,omitempty"`
	Location                    string                     `json:"location,omitempty" yaml:"location,omitempty"`
	LocationRange               *model.LocationRange       `json:"location_range,omitempty" yaml:"location_range,omitempty"`
	EndpointClass               string                     `json:"endpoint_class" yaml:"endpoint_class"`
	DataClass                   string                     `json:"data_class" yaml:"data_class"`
	AutonomyLevel               string                     `json:"autonomy_level" yaml:"autonomy_level"`
	RiskScore                   float64                    `json:"risk_score" yaml:"risk_score"`
	ApprovalClassification      string                     `json:"approval_classification,omitempty" yaml:"approval_classification,omitempty"`
	SecurityVisibilityStatus    string                     `json:"security_visibility_status,omitempty" yaml:"security_visibility_status,omitempty"`
	BoundTools                  []string                   `json:"bound_tools,omitempty" yaml:"bound_tools,omitempty"`
	BoundDataSources            []string                   `json:"bound_data_sources,omitempty" yaml:"bound_data_sources,omitempty"`
	BoundAuthSurfaces           []string                   `json:"bound_auth_surfaces,omitempty" yaml:"bound_auth_surfaces,omitempty"`
	BindingEvidenceKeys         []string                   `json:"binding_evidence_keys,omitempty" yaml:"binding_evidence_keys,omitempty"`
	MissingBindings             []string                   `json:"missing_bindings,omitempty" yaml:"missing_bindings,omitempty"`
	DeploymentStatus            string                     `json:"deployment_status,omitempty" yaml:"deployment_status,omitempty"`
	DeploymentArtifacts         []string                   `json:"deployment_artifacts,omitempty" yaml:"deployment_artifacts,omitempty"`
	DeploymentEvidenceKeys      []string                   `json:"deployment_evidence_keys,omitempty" yaml:"deployment_evidence_keys,omitempty"`
	WorkflowTriggerClass        string                     `json:"workflow_trigger_class,omitempty" yaml:"workflow_trigger_class,omitempty"`
	OperationalOwner            string                     `json:"operational_owner,omitempty" yaml:"operational_owner,omitempty"`
	OwnerSource                 string                     `json:"owner_source,omitempty" yaml:"owner_source,omitempty"`
	OwnershipStatus             string                     `json:"ownership_status,omitempty" yaml:"ownership_status,omitempty"`
	OwnershipState              string                     `json:"ownership_state,omitempty" yaml:"ownership_state,omitempty"`
	OwnershipConfidence         float64                    `json:"ownership_confidence,omitempty" yaml:"ownership_confidence,omitempty"`
	OwnershipEvidence           []string                   `json:"ownership_evidence_basis,omitempty" yaml:"ownership_evidence_basis,omitempty"`
	OwnershipConflicts          []string                   `json:"ownership_conflicts,omitempty" yaml:"ownership_conflicts,omitempty"`
	OwnershipDecision           *evidencepolicy.Decision   `json:"ownership_decision,omitempty" yaml:"ownership_decision,omitempty"`
	ApprovalGapReasons          []string                   `json:"approval_gap_reasons,omitempty" yaml:"approval_gap_reasons,omitempty"`
	TrustDepth                  *TrustDepth                `json:"trust_depth,omitempty" yaml:"trust_depth,omitempty"`
	PullRequestWrite            bool                       `json:"pull_request_write,omitempty" yaml:"pull_request_write,omitempty"`
	MergeExecute                bool                       `json:"merge_execute,omitempty" yaml:"merge_execute,omitempty"`
	DeployWrite                 bool                       `json:"deploy_write,omitempty" yaml:"deploy_write,omitempty"`
	DeliveryChainStatus         string                     `json:"delivery_chain_status,omitempty" yaml:"delivery_chain_status,omitempty"`
	ProductionTargetStatus      string                     `json:"production_target_status,omitempty" yaml:"production_target_status,omitempty"`
	WriteCapable                bool                       `json:"write_capable" yaml:"write_capable"`
	CredentialAccess            bool                       `json:"credential_access" yaml:"credential_access"`
	Credentials                 []*CredentialProvenance    `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	CredentialProvenance        *CredentialProvenance      `json:"credential_provenance,omitempty" yaml:"credential_provenance,omitempty"`
	CredentialAuthority         *CredentialAuthority       `json:"credential_authority,omitempty" yaml:"credential_authority,omitempty"`
	AuthorityBindings           []*AuthorityBinding        `json:"authority_bindings,omitempty" yaml:"authority_bindings,omitempty"`
	PathContext                 *PathContext               `json:"path_context,omitempty" yaml:"path_context,omitempty"`
	StandingPrivilege           bool                       `json:"standing_privilege,omitempty" yaml:"standing_privilege,omitempty"`
	StandingPrivilegeReasons    []string                   `json:"standing_privilege_reasons,omitempty" yaml:"standing_privilege_reasons,omitempty"`
	ExecCapable                 bool                       `json:"exec_capable" yaml:"exec_capable"`
	ProductionWrite             bool                       `json:"production_write" yaml:"production_write"`
	MatchedProductionTargets    []string                   `json:"matched_production_targets,omitempty" yaml:"matched_production_targets,omitempty"`
}

func ClonePathContext(in *PathContext) *PathContext {
	if in == nil {
		return nil
	}
	out := *in
	out.Kind = strings.TrimSpace(out.Kind)
	out.Confidence = strings.TrimSpace(out.Confidence)
	out.Reasons = mergeCredentialEvidenceBasis(out.Reasons)
	return &out
}

func ClassifyPathContext(location string) *PathContext {
	trimmed := strings.Trim(strings.TrimSpace(location), "/")
	if trimmed == "" {
		return &PathContext{Kind: PathContextUnknown, Confidence: "low", Reasons: []string{"location_missing"}}
	}
	lower := strings.ToLower(strings.ReplaceAll(trimmed, "\\", "/"))
	segments := strings.Split(lower, "/")
	segmentSet := map[string]struct{}{}
	for _, segment := range segments {
		if segment != "" {
			segmentSet[segment] = struct{}{}
		}
	}
	ext := ""
	if dot := strings.LastIndex(lower, "."); dot >= 0 {
		ext = lower[dot:]
	}
	switch {
	case hasAnySegment(segmentSet, "node_modules", ".pnpm", ".yarn", ".pnpm-store", "vendor") ||
		strings.Contains(lower, "/.yarn/cache/") || strings.Contains(lower, "/.vitepress/cache/"):
		return &PathContext{Kind: PathContextPackageCache, Confidence: "high", Reasons: []string{"package_or_docs_cache_path"}}
	case hasAnySegment(segmentSet, "dist", "build", "generated", "generated-sdks", "generated-sdk", "__generated__", ".next", ".nuxt", ".docusaurus") ||
		strings.HasSuffix(lower, ".min.js") || strings.Contains(lower, "/generated/"):
		return &PathContext{Kind: PathContextGeneratedCode, Confidence: "high", Reasons: []string{"generated_or_bundled_path"}}
	case hasAnySegment(segmentSet, "docs", "doc", "documentation", "site", "docs-site") || ext == ".md" || ext == ".mdx" || ext == ".rst":
		return &PathContext{Kind: PathContextDocs, Confidence: "medium", Reasons: []string{"documentation_path"}}
	case hasAnySegment(segmentSet, "examples", "example", "samples", "sample", "demo", "demos"):
		return &PathContext{Kind: PathContextExample, Confidence: "medium", Reasons: []string{"example_path"}}
	case hasAnySegment(segmentSet, "functional_tests", "functional-test", "functional-tests", "e2e", "integration", "integration_tests"):
		return &PathContext{Kind: PathContextFunctionalTest, Confidence: "high", Reasons: []string{"functional_or_integration_test_path"}}
	case hasAnySegment(segmentSet, "test", "tests", "__tests__", "spec", "specs", "testdata") ||
		strings.Contains(lower, "_test.") || strings.Contains(lower, ".test.") || strings.Contains(lower, ".spec."):
		return &PathContext{Kind: PathContextUnitTest, Confidence: "high", Reasons: []string{"unit_or_fixture_test_path"}}
	case hasAnySegment(segmentSet, ".github", "workflows", "deploy", "deployments", "helm", "k8s", "kubernetes") ||
		strings.Contains(lower, "dockerfile") || strings.Contains(lower, "jenkinsfile") ||
		strings.HasSuffix(lower, ".gitlab-ci.yml") || strings.HasSuffix(lower, ".gitlab-ci.yaml") ||
		strings.Contains(lower, "/.gitlab/ci/") || strings.HasSuffix(lower, "azure-pipelines.yml") ||
		strings.HasSuffix(lower, "azure-pipelines.yaml") || strings.Contains(lower, "/.azure/pipelines/"):
		return &PathContext{Kind: PathContextDeployableSource, Confidence: "high", Reasons: []string{"deployment_or_ci_path"}}
	case hasRuntimeExtension(ext):
		return &PathContext{Kind: PathContextRuntimeSource, Confidence: "medium", Reasons: []string{"runtime_source_extension"}}
	default:
		return &PathContext{Kind: PathContextUnknown, Confidence: "low", Reasons: []string{"unclassified_path"}}
	}
}

func hasAnySegment(segments map[string]struct{}, values ...string) bool {
	for _, value := range values {
		if _, ok := segments[value]; ok {
			return true
		}
	}
	return false
}

func hasRuntimeExtension(ext string) bool {
	switch strings.TrimSpace(ext) {
	case ".go", ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".rb", ".php", ".java", ".kt", ".rs":
		return true
	default:
		return false
	}
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
	out.TargetSystem = strings.TrimSpace(out.TargetSystem)
	out.LikelyScope = strings.TrimSpace(out.LikelyScope)
	out.ScopeConfidence = strings.TrimSpace(out.ScopeConfidence)
	out.CredentialKind = strings.TrimSpace(out.CredentialKind)
	out.AccessType = strings.TrimSpace(out.AccessType)
	out.EvidenceLocation = strings.TrimSpace(out.EvidenceLocation)
	out.EvidenceBasis = append([]string(nil), in.EvidenceBasis...)
	out.ClassificationReasons = append([]string(nil), in.ClassificationReasons...)
	return &out
}

func CloneCredentialProvenances(in []*CredentialProvenance) []*CredentialProvenance {
	if len(in) == 0 {
		return nil
	}
	out := make([]*CredentialProvenance, 0, len(in))
	for _, item := range in {
		if cloned := CloneCredentialProvenance(item); cloned != nil {
			out = append(out, cloned)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func NormalizeCredentialProvenance(in *CredentialProvenance) *CredentialProvenance {
	if in == nil {
		return nil
	}
	out := CloneCredentialProvenance(in)
	out.Type = normalizeCredentialProvenanceType(out.Type)
	out.Scope = normalizeCredentialScope(out.Scope)
	out.Confidence = normalizeCredentialConfidence(out.Confidence)
	out.ScopeConfidence = normalizeCredentialConfidence(out.ScopeConfidence)
	if out.ScopeConfidence == "" {
		out.ScopeConfidence = out.Confidence
	}
	out.CredentialKind = normalizeCredentialKind(out.CredentialKind, out.Type)
	out.AccessType = normalizeCredentialAccessType(out.AccessType, out.CredentialKind, out.Type)
	out.StandingAccess = inferStandingAccess(out.StandingAccess, out.AccessType, out.CredentialKind, out.Type)
	out.LikelyJIT = inferLikelyJIT(out.LikelyJIT, out.AccessType, out.CredentialKind, out.Type)
	if out.RiskMultiplier == 0 {
		out.RiskMultiplier = CredentialRiskMultiplierFor(out)
	}
	out.EvidenceBasis = mergeCredentialEvidenceBasis(out.EvidenceBasis)
	out.ClassificationReasons = mergeCredentialEvidenceBasis(out.ClassificationReasons)
	return out
}

func NormalizeCredentialProvenances(in []*CredentialProvenance) []*CredentialProvenance {
	if len(in) == 0 {
		return nil
	}
	out := make([]*CredentialProvenance, 0, len(in))
	seen := map[string]struct{}{}
	for _, item := range in {
		normalized := NormalizeCredentialProvenance(item)
		if normalized == nil {
			continue
		}
		key := strings.Join([]string{
			normalized.Type,
			normalized.CredentialKind,
			normalized.Scope,
			normalized.Subject,
			normalized.EvidenceLocation,
		}, "|")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, normalized)
	}
	sort.Slice(out, func(i, j int) bool {
		left := strings.Join([]string{out[i].Scope, out[i].CredentialKind, out[i].Subject, out[i].EvidenceLocation, out[i].Type}, "|")
		right := strings.Join([]string{out[j].Scope, out[j].CredentialKind, out[j].Subject, out[j].EvidenceLocation, out[j].Type}, "|")
		return left < right
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func CredentialRollup(credentials []*CredentialProvenance, fallback *CredentialProvenance) *CredentialProvenance {
	normalized := NormalizeCredentialProvenances(credentials)
	if len(normalized) == 0 {
		return NormalizeCredentialProvenance(fallback)
	}
	choice := normalized[0]
	for _, item := range normalized[1:] {
		if credentialRiskSortKey(item) > credentialRiskSortKey(choice) {
			choice = item
		}
	}
	return CloneCredentialProvenance(choice)
}

func credentialRiskSortKey(item *CredentialProvenance) float64 {
	if item == nil {
		return 0
	}
	return item.RiskMultiplier
}

func CredentialRiskMultiplier(kind string) float64 {
	return CredentialRiskMultiplierFor(&CredentialProvenance{Type: kind})
}

func CredentialRiskMultiplierFor(in *CredentialProvenance) float64 {
	if in == nil {
		return 1.0
	}
	normalized := CloneCredentialProvenance(in)
	normalized.Type = normalizeCredentialProvenanceType(normalized.Type)
	normalized.CredentialKind = normalizeCredentialKind(normalized.CredentialKind, normalized.Type)
	normalized.AccessType = normalizeCredentialAccessType(normalized.AccessType, normalized.CredentialKind, normalized.Type)
	normalized.StandingAccess = inferStandingAccess(normalized.StandingAccess, normalized.AccessType, normalized.CredentialKind, normalized.Type)
	switch normalized.CredentialKind {
	case CredentialKindCloudAdminKey:
		return 1.30
	case CredentialKindGitHubPAT, CredentialKindUnknownDurable:
		return 1.20
	case CredentialKindGitHubWorkflowToken:
		if normalized.StandingAccess {
			return 1.08
		}
		return 1.03
	case CredentialKindInheritedHuman:
		return 1.15
	case CredentialKindGitHubAppKey, CredentialKindDeployKey, CredentialKindCloudAccessKey, CredentialKindStaticSecret:
		if normalized.StandingAccess {
			return 1.10
		}
		return 1.05
	case CredentialKindDelegatedOAuth:
		return 1.05
	case CredentialKindOIDCWorkloadID, CredentialKindJITCredential:
		return 1.00
	default:
		switch normalized.Type {
		case CredentialProvenanceInheritedHuman:
			return 1.10
		case CredentialProvenanceStaticSecret:
			return 1.05
		case CredentialProvenanceOAuthDelegation:
			return 1.05
		case CredentialProvenanceWorkloadIdentity, CredentialProvenanceJIT:
			return 1.00
		default:
			if normalized.StandingAccess {
				return 1.20
			}
			return 1.10
		}
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

func normalizeCredentialKind(value string, provenanceType string) string {
	switch strings.TrimSpace(value) {
	case CredentialKindGitHubPAT,
		CredentialKindGitHubWorkflowToken,
		CredentialKindGitHubAppKey,
		CredentialKindDeployKey,
		CredentialKindCloudAdminKey,
		CredentialKindCloudAccessKey,
		CredentialKindOIDCWorkloadID,
		CredentialKindDelegatedOAuth,
		CredentialKindJITCredential,
		CredentialKindInheritedHuman,
		CredentialKindStaticSecret,
		CredentialKindUnknownDurable:
		return strings.TrimSpace(value)
	}

	switch normalizeCredentialProvenanceType(provenanceType) {
	case CredentialProvenanceStaticSecret:
		return CredentialKindStaticSecret
	case CredentialProvenanceWorkloadIdentity:
		return CredentialKindOIDCWorkloadID
	case CredentialProvenanceInheritedHuman:
		return CredentialKindInheritedHuman
	case CredentialProvenanceOAuthDelegation:
		return CredentialKindDelegatedOAuth
	case CredentialProvenanceJIT:
		return CredentialKindJITCredential
	default:
		return CredentialKindUnknown
	}
}

func normalizeCredentialAccessType(value string, credentialKind string, provenanceType string) string {
	switch strings.TrimSpace(value) {
	case CredentialAccessTypeStanding,
		CredentialAccessTypeJIT,
		CredentialAccessTypeDelegated,
		CredentialAccessTypeWorkload,
		CredentialAccessTypeInherited:
		return strings.TrimSpace(value)
	}

	switch normalizeCredentialKind(credentialKind, provenanceType) {
	case CredentialKindGitHubPAT,
		CredentialKindGitHubAppKey,
		CredentialKindDeployKey,
		CredentialKindCloudAdminKey,
		CredentialKindCloudAccessKey,
		CredentialKindStaticSecret,
		CredentialKindUnknownDurable:
		return CredentialAccessTypeStanding
	case CredentialKindGitHubWorkflowToken:
		return CredentialAccessTypeJIT
	case CredentialKindOIDCWorkloadID:
		return CredentialAccessTypeWorkload
	case CredentialKindDelegatedOAuth:
		return CredentialAccessTypeDelegated
	case CredentialKindJITCredential:
		return CredentialAccessTypeJIT
	case CredentialKindInheritedHuman:
		return CredentialAccessTypeInherited
	default:
		switch normalizeCredentialProvenanceType(provenanceType) {
		case CredentialProvenanceWorkloadIdentity:
			return CredentialAccessTypeWorkload
		case CredentialProvenanceOAuthDelegation:
			return CredentialAccessTypeDelegated
		case CredentialProvenanceJIT:
			return CredentialAccessTypeJIT
		case CredentialProvenanceInheritedHuman:
			return CredentialAccessTypeInherited
		default:
			return CredentialAccessTypeUnknown
		}
	}
}

func inferStandingAccess(current bool, accessType string, credentialKind string, provenanceType string) bool {
	if current {
		return true
	}
	switch normalizeCredentialAccessType(accessType, credentialKind, provenanceType) {
	case CredentialAccessTypeStanding, CredentialAccessTypeInherited:
		return true
	default:
		return false
	}
}

func inferLikelyJIT(current bool, accessType string, credentialKind string, provenanceType string) bool {
	if current {
		return true
	}
	switch normalizeCredentialAccessType(accessType, credentialKind, provenanceType) {
	case CredentialAccessTypeJIT, CredentialAccessTypeWorkload:
		return true
	default:
		return false
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

func StandingPrivilegeFromProvenance(in *CredentialProvenance) (bool, []string) {
	normalized := NormalizeCredentialProvenance(in)
	if normalized == nil {
		return false, nil
	}

	reasons := make([]string, 0, 8)
	switch normalized.AccessType {
	case CredentialAccessTypeStanding:
		reasons = append(reasons, "access_type:standing")
	case CredentialAccessTypeInherited:
		reasons = append(reasons, "access_type:inherited")
	case CredentialAccessTypeJIT:
		reasons = append(reasons, "access_type:jit")
	case CredentialAccessTypeWorkload:
		reasons = append(reasons, "access_type:workload")
	case CredentialAccessTypeDelegated:
		reasons = append(reasons, "access_type:delegated")
	}
	if normalized.CredentialKind != "" && normalized.CredentialKind != CredentialKindUnknown {
		reasons = append(reasons, "credential_kind:"+normalized.CredentialKind)
	}
	for _, item := range normalized.ClassificationReasons {
		reasons = append(reasons, "classification:"+strings.TrimSpace(item))
	}
	for _, item := range normalized.EvidenceBasis {
		if strings.TrimSpace(item) != "" {
			reasons = append(reasons, "evidence:"+strings.TrimSpace(item))
		}
	}

	standing := normalized.StandingAccess
	if !standing {
		switch normalized.CredentialKind {
		case CredentialKindGitHubPAT,
			CredentialKindGitHubAppKey,
			CredentialKindDeployKey,
			CredentialKindCloudAdminKey,
			CredentialKindCloudAccessKey,
			CredentialKindUnknownDurable,
			CredentialKindInheritedHuman,
			CredentialKindStaticSecret:
			standing = true
		}
	}
	return standing, mergeCredentialEvidenceBasis(reasons)
}
