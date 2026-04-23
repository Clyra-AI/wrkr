package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/internal/atomicwrite"
	"gopkg.in/yaml.v3"
)

const Version = "v1"
const ApprovalInventoryVersion = "1"

type Approval struct {
	Approver        string `yaml:"approver,omitempty" json:"approver,omitempty"`
	Owner           string `yaml:"owner,omitempty" json:"owner,omitempty"`
	Scope           string `yaml:"scope,omitempty" json:"scope,omitempty"`
	EvidenceURL     string `yaml:"evidence_url,omitempty" json:"evidence_url,omitempty"`
	ControlID       string `yaml:"control_id,omitempty" json:"control_id,omitempty"`
	Approved        string `yaml:"approved,omitempty" json:"approved,omitempty"`
	Expires         string `yaml:"expires,omitempty" json:"expires,omitempty"`
	ReviewCadence   string `yaml:"review_cadence,omitempty" json:"review_cadence,omitempty"`
	LastReviewed    string `yaml:"last_reviewed,omitempty" json:"last_reviewed,omitempty"`
	RenewalState    string `yaml:"renewal_state,omitempty" json:"renewal_state,omitempty"`
	AcceptedRisk    bool   `yaml:"accepted_risk,omitempty" json:"accepted_risk,omitempty"`
	DecisionReason  string `yaml:"decision_reason,omitempty" json:"decision_reason,omitempty"`
	ExclusionReason string `yaml:"exclusion_reason,omitempty" json:"exclusion_reason,omitempty"`
}

type IdentityRecord struct {
	AgentID       string   `yaml:"agent_id" json:"agent_id"`
	ToolID        string   `yaml:"tool_id" json:"tool_id"`
	ToolType      string   `yaml:"tool_type" json:"tool_type"`
	Org           string   `yaml:"org" json:"org"`
	Repo          string   `yaml:"repo" json:"repo"`
	Location      string   `yaml:"location" json:"location"`
	Status        string   `yaml:"status" json:"status"`
	Approval      Approval `yaml:"approval,omitempty" json:"approval,omitempty"`
	ApprovalState string   `yaml:"approval_status" json:"approval_status"`
	FirstSeen     string   `yaml:"first_seen" json:"first_seen"`
	LastSeen      string   `yaml:"last_seen" json:"last_seen"`
	Present       bool     `yaml:"present" json:"present"`
	DataClass     string   `yaml:"data_class" json:"data_class"`
	EndpointClass string   `yaml:"endpoint_class" json:"endpoint_class"`
	AutonomyLevel string   `yaml:"autonomy_level" json:"autonomy_level"`
	RiskScore     float64  `yaml:"risk_score" json:"risk_score"`
}

type Manifest struct {
	Version                  string           `yaml:"version" json:"version"`
	ApprovalInventoryVersion string           `yaml:"approval_inventory_version,omitempty" json:"approval_inventory_version,omitempty"`
	UpdatedAt                string           `yaml:"updated_at" json:"updated_at"`
	Identities               []IdentityRecord `yaml:"identities" json:"identities"`
}

func ResolvePath(statePath string) string {
	trimmed := strings.TrimSpace(statePath)
	if trimmed == "" {
		trimmed = filepath.Join(".wrkr", "last-scan.json")
	}
	dir := filepath.Dir(trimmed)
	return filepath.Join(dir, "wrkr-manifest.yaml")
}

func Load(path string) (Manifest, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- path is an explicit local manifest/state location controlled by CLI arguments.
	if err != nil {
		return Manifest{}, err
	}
	var out Manifest
	if err := yaml.Unmarshal(payload, &out); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	if strings.TrimSpace(out.Version) == "" {
		out.Version = Version
	}
	if strings.TrimSpace(out.ApprovalInventoryVersion) == "" {
		out.ApprovalInventoryVersion = ApprovalInventoryVersion
	}
	sortRecords(out.Identities)
	return out, nil
}

func Save(path string, m Manifest) error {
	m.Version = Version
	m.ApprovalInventoryVersion = ApprovalInventoryVersion
	if strings.TrimSpace(m.UpdatedAt) == "" {
		m.UpdatedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	sortRecords(m.Identities)
	payload, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	payload = append(payload, '\n')
	if err := atomicwrite.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}
	return nil
}

func sortRecords(items []IdentityRecord) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].AgentID != items[j].AgentID {
			return items[i].AgentID < items[j].AgentID
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		return items[i].Location < items[j].Location
	})
}
