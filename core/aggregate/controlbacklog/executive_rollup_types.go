package controlbacklog

type ExecutiveRollup struct {
	TotalGroups int                    `json:"total_groups"`
	TotalPaths  int                    `json:"total_paths"`
	Groups      []ExecutiveRollupGroup `json:"groups,omitempty"`
}

type ExecutiveRollupGroup struct {
	GroupID               string                             `json:"group_id"`
	Count                 int                                `json:"count"`
	HighestSeverity       string                             `json:"highest_severity,omitempty"`
	HighestPriority       string                             `json:"highest_priority,omitempty"`
	ClosureRecommendation string                             `json:"closure_recommendation,omitempty"`
	TopExampleRefs        []string                           `json:"top_example_refs,omitempty"`
	EvidenceStateSummary  ExecutiveRollupEvidenceStateCounts `json:"evidence_state_summary"`
	Rationale             []string                           `json:"rationale,omitempty"`
	Dimensions            ExecutiveRollupDimensions          `json:"dimensions"`
}

type ExecutiveRollupDimensions struct {
	ActionClass         string `json:"action_class,omitempty"`
	TargetClass         string `json:"target_class,omitempty"`
	RiskZone            string `json:"risk_zone,omitempty"`
	CredentialAuthority string `json:"credential_authority,omitempty"`
	ProductionTarget    string `json:"production_target,omitempty"`
	EvidenceState       string `json:"evidence_state,omitempty"`
	OwnerState          string `json:"owner_state,omitempty"`
	RepoCluster         string `json:"repo_cluster,omitempty"`
	DetectorConfidence  string `json:"detector_confidence,omitempty"`
	ContradictionState  string `json:"contradiction_state,omitempty"`
	ClosureAction       string `json:"closure_action,omitempty"`
}

type ExecutiveRollupEvidenceStateCounts struct {
	Verified      int `json:"verified"`
	Declared      int `json:"declared"`
	Inferred      int `json:"inferred"`
	Unknown       int `json:"unknown"`
	Contradictory int `json:"contradictory"`
}

type GovernedUsageMetrics struct {
	ActiveMonitoredActionPaths int `json:"active_monitored_action_paths"`
	GovernedPaths              int `json:"governed_paths"`
	EvidencePacks              int `json:"evidence_packs"`
	AuditExports               int `json:"audit_exports"`
	ApprovalDecisions          int `json:"approval_decisions"`
	ConnectedRuntimes          int `json:"connected_runtimes"`
	GovernedAgentsWorkflows    int `json:"governed_agents_workflows"`
	VerifiedControlPaths       int `json:"verified_control_paths"`
	UnknownControlPaths        int `json:"unknown_control_paths"`
	ContradictoryPaths         int `json:"contradictory_paths"`
}
