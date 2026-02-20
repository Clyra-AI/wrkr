package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const Version = "v1"

type Approval struct {
	Approver string `yaml:"approver,omitempty" json:"approver,omitempty"`
	Scope    string `yaml:"scope,omitempty" json:"scope,omitempty"`
	Approved string `yaml:"approved,omitempty" json:"approved,omitempty"`
	Expires  string `yaml:"expires,omitempty" json:"expires,omitempty"`
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
	Version    string           `yaml:"version" json:"version"`
	UpdatedAt  string           `yaml:"updated_at" json:"updated_at"`
	Identities []IdentityRecord `yaml:"identities" json:"identities"`
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
	sortRecords(out.Identities)
	return out, nil
}

func Save(path string, m Manifest) error {
	m.Version = Version
	if strings.TrimSpace(m.UpdatedAt) == "" {
		m.UpdatedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	}
	sortRecords(m.Identities)
	payload, err := yaml.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir manifest dir: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "manifest-*.yaml")
	if err != nil {
		return fmt.Errorf("create manifest temp: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()
	if _, err := tmp.Write(payload); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write manifest temp: %w", err)
	}
	if _, err := tmp.Write([]byte("\n")); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write manifest newline: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod manifest temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close manifest temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("commit manifest: %w", err)
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
