package inventory

import "github.com/Clyra-AI/wrkr/core/model"

const (
	ProductionTargetsStatusConfigured    = "configured"
	ProductionTargetsStatusNotConfigured = "not_configured"
	ProductionTargetsStatusInvalid       = "invalid"
)

type ProductionWriteBudget struct {
	Configured bool   `json:"configured" yaml:"configured"`
	Status     string `json:"status" yaml:"status"`
	Count      *int   `json:"count" yaml:"count"`
}

type PrivilegeBudget struct {
	TotalTools            int                   `json:"total_tools" yaml:"total_tools"`
	WriteCapableTools     int                   `json:"write_capable_tools" yaml:"write_capable_tools"`
	CredentialAccessTools int                   `json:"credential_access_tools" yaml:"credential_access_tools"`
	ExecCapableTools      int                   `json:"exec_capable_tools" yaml:"exec_capable_tools"`
	ProductionWrite       ProductionWriteBudget `json:"production_write" yaml:"production_write"`
}

type AgentPrivilegeMapEntry struct {
	AgentID                  string               `json:"agent_id" yaml:"agent_id"`
	AgentInstanceID          string               `json:"agent_instance_id,omitempty" yaml:"agent_instance_id,omitempty"`
	ToolID                   string               `json:"tool_id" yaml:"tool_id"`
	ToolType                 string               `json:"tool_type" yaml:"tool_type"`
	Framework                string               `json:"framework,omitempty" yaml:"framework,omitempty"`
	Symbol                   string               `json:"symbol,omitempty" yaml:"symbol,omitempty"`
	Org                      string               `json:"org" yaml:"org"`
	Repos                    []string             `json:"repos" yaml:"repos"`
	Permissions              []string             `json:"permissions" yaml:"permissions"`
	Location                 string               `json:"location,omitempty" yaml:"location,omitempty"`
	LocationRange            *model.LocationRange `json:"location_range,omitempty" yaml:"location_range,omitempty"`
	EndpointClass            string               `json:"endpoint_class" yaml:"endpoint_class"`
	DataClass                string               `json:"data_class" yaml:"data_class"`
	AutonomyLevel            string               `json:"autonomy_level" yaml:"autonomy_level"`
	RiskScore                float64              `json:"risk_score" yaml:"risk_score"`
	ApprovalClassification   string               `json:"approval_classification,omitempty" yaml:"approval_classification,omitempty"`
	SecurityVisibilityStatus string               `json:"security_visibility_status,omitempty" yaml:"security_visibility_status,omitempty"`
	BoundTools               []string             `json:"bound_tools,omitempty" yaml:"bound_tools,omitempty"`
	BoundDataSources         []string             `json:"bound_data_sources,omitempty" yaml:"bound_data_sources,omitempty"`
	BoundAuthSurfaces        []string             `json:"bound_auth_surfaces,omitempty" yaml:"bound_auth_surfaces,omitempty"`
	BindingEvidenceKeys      []string             `json:"binding_evidence_keys,omitempty" yaml:"binding_evidence_keys,omitempty"`
	MissingBindings          []string             `json:"missing_bindings,omitempty" yaml:"missing_bindings,omitempty"`
	DeploymentStatus         string               `json:"deployment_status,omitempty" yaml:"deployment_status,omitempty"`
	DeploymentArtifacts      []string             `json:"deployment_artifacts,omitempty" yaml:"deployment_artifacts,omitempty"`
	DeploymentEvidenceKeys   []string             `json:"deployment_evidence_keys,omitempty" yaml:"deployment_evidence_keys,omitempty"`
	WriteCapable             bool                 `json:"write_capable" yaml:"write_capable"`
	CredentialAccess         bool                 `json:"credential_access" yaml:"credential_access"`
	ExecCapable              bool                 `json:"exec_capable" yaml:"exec_capable"`
	ProductionWrite          bool                 `json:"production_write" yaml:"production_write"`
	MatchedProductionTargets []string             `json:"matched_production_targets,omitempty" yaml:"matched_production_targets,omitempty"`
}
