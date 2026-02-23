package inventory

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
	AgentID                  string   `json:"agent_id" yaml:"agent_id"`
	ToolID                   string   `json:"tool_id" yaml:"tool_id"`
	ToolType                 string   `json:"tool_type" yaml:"tool_type"`
	Org                      string   `json:"org" yaml:"org"`
	Repos                    []string `json:"repos" yaml:"repos"`
	Permissions              []string `json:"permissions" yaml:"permissions"`
	EndpointClass            string   `json:"endpoint_class" yaml:"endpoint_class"`
	DataClass                string   `json:"data_class" yaml:"data_class"`
	AutonomyLevel            string   `json:"autonomy_level" yaml:"autonomy_level"`
	RiskScore                float64  `json:"risk_score" yaml:"risk_score"`
	WriteCapable             bool     `json:"write_capable" yaml:"write_capable"`
	CredentialAccess         bool     `json:"credential_access" yaml:"credential_access"`
	ExecCapable              bool     `json:"exec_capable" yaml:"exec_capable"`
	ProductionWrite          bool     `json:"production_write" yaml:"production_write"`
	MatchedProductionTargets []string `json:"matched_production_targets,omitempty" yaml:"matched_production_targets,omitempty"`
}
