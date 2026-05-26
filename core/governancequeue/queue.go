package governancequeue

const (
	CredentialStatusPresent = "credential_access_present"
	CredentialStatusNone    = "no_credential_access"
)

type Item struct {
	QueueID            string   `json:"queue_id" yaml:"queue_id"`
	GapID              string   `json:"gap_id" yaml:"gap_id"`
	AgentID            string   `json:"agent_id,omitempty" yaml:"agent_id,omitempty"`
	Repo               string   `json:"repo,omitempty" yaml:"repo,omitempty"`
	Path               string   `json:"path,omitempty" yaml:"path,omitempty"`
	ReasonCode         string   `json:"reason_code" yaml:"reason_code"`
	Severity           string   `json:"severity" yaml:"severity"`
	Owner              string   `json:"owner,omitempty" yaml:"owner,omitempty"`
	OwnerEvidenceState string   `json:"owner_evidence_state,omitempty" yaml:"owner_evidence_state,omitempty"`
	CredentialStatus   string   `json:"credential_status,omitempty" yaml:"credential_status,omitempty"`
	LifecycleStatus    string   `json:"lifecycle_status,omitempty" yaml:"lifecycle_status,omitempty"`
	RecommendedAction  string   `json:"recommended_action" yaml:"recommended_action"`
	SLA                string   `json:"sla" yaml:"sla"`
	ClosureCriteria    string   `json:"closure_criteria" yaml:"closure_criteria"`
	EvidenceRefs       []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
	SourceConflicts    []string `json:"source_conflicts,omitempty" yaml:"source_conflicts,omitempty"`
}
