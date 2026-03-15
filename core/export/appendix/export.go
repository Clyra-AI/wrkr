package appendix

import (
	"crypto/sha256"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
)

type Snapshot struct {
	ExportVersion   string                `json:"export_version" yaml:"export_version"`
	SchemaVersion   string                `json:"schema_version" yaml:"schema_version"`
	ExportedAt      string                `json:"exported_at" yaml:"exported_at"`
	Org             string                `json:"org" yaml:"org"`
	InventoryRows   []InventoryRow        `json:"inventory_rows" yaml:"inventory_rows"`
	PrivilegeRows   []PrivilegeRow        `json:"privilege_rows" yaml:"privilege_rows"`
	ApprovalGapRows []ApprovalGapRow      `json:"approval_gap_rows" yaml:"approval_gap_rows"`
	RegulatoryRows  []RegulatoryMatrixRow `json:"regulatory_rows" yaml:"regulatory_rows"`
}

type InventoryRow struct {
	ToolID          string  `json:"tool_id" yaml:"tool_id"`
	AgentID         string  `json:"agent_id" yaml:"agent_id"`
	ToolType        string  `json:"tool_type" yaml:"tool_type"`
	ToolCategory    string  `json:"tool_category" yaml:"tool_category"`
	ConfidenceScore float64 `json:"confidence_score" yaml:"confidence_score"`
	Org             string  `json:"org" yaml:"org"`
	RepoCount       int     `json:"repo_count" yaml:"repo_count"`
	PermissionTier  string  `json:"permission_tier" yaml:"permission_tier"`
	RiskTier        string  `json:"risk_tier" yaml:"risk_tier"`
	AdoptionPattern string  `json:"adoption_pattern" yaml:"adoption_pattern"`
	ApprovalClass   string  `json:"approval_classification" yaml:"approval_classification"`
	LifecycleState  string  `json:"lifecycle_state" yaml:"lifecycle_state"`
}

type PrivilegeRow struct {
	AgentInstanceID    string  `json:"agent_instance_id" yaml:"agent_instance_id"`
	AgentID            string  `json:"agent_id" yaml:"agent_id"`
	ToolID             string  `json:"tool_id" yaml:"tool_id"`
	ToolType           string  `json:"tool_type" yaml:"tool_type"`
	Org                string  `json:"org" yaml:"org"`
	RepoCount          int     `json:"repo_count" yaml:"repo_count"`
	PermissionCount    int     `json:"permission_count" yaml:"permission_count"`
	EndpointClass      string  `json:"endpoint_class" yaml:"endpoint_class"`
	DataClass          string  `json:"data_class" yaml:"data_class"`
	AutonomyLevel      string  `json:"autonomy_level" yaml:"autonomy_level"`
	RiskScore          float64 `json:"risk_score" yaml:"risk_score"`
	WriteCapable       bool    `json:"write_capable" yaml:"write_capable"`
	CredentialAccess   bool    `json:"credential_access" yaml:"credential_access"`
	ExecCapable        bool    `json:"exec_capable" yaml:"exec_capable"`
	ProductionWrite    bool    `json:"production_write" yaml:"production_write"`
	MatchedTargetCount int     `json:"matched_production_targets" yaml:"matched_production_targets"`
}

type ApprovalGapRow struct {
	ToolID          string `json:"tool_id" yaml:"tool_id"`
	AgentID         string `json:"agent_id" yaml:"agent_id"`
	ToolType        string `json:"tool_type" yaml:"tool_type"`
	Org             string `json:"org" yaml:"org"`
	ApprovalClass   string `json:"approval_classification" yaml:"approval_classification"`
	AdoptionPattern string `json:"adoption_pattern" yaml:"adoption_pattern"`
	RiskTier        string `json:"risk_tier" yaml:"risk_tier"`
}

type RegulatoryMatrixRow struct {
	ToolID         string `json:"tool_id" yaml:"tool_id"`
	AgentID        string `json:"agent_id" yaml:"agent_id"`
	ToolType       string `json:"tool_type" yaml:"tool_type"`
	Org            string `json:"org" yaml:"org"`
	Regulation     string `json:"regulation" yaml:"regulation"`
	ControlID      string `json:"control_id" yaml:"control_id"`
	Status         string `json:"status" yaml:"status"`
	RiskTier       string `json:"risk_tier" yaml:"risk_tier"`
	PermissionTier string `json:"permission_tier" yaml:"permission_tier"`
}

type BuildOptions struct {
	Anonymize bool
}

func Build(inv agginventory.Inventory, now time.Time) Snapshot {
	return BuildWithOptions(inv, now, BuildOptions{})
}

func BuildWithOptions(inv agginventory.Inventory, now time.Time, opts BuildOptions) Snapshot {
	exportedAt := now.UTC()
	if exportedAt.IsZero() {
		exportedAt = time.Now().UTC().Truncate(time.Second)
	}
	org := strings.TrimSpace(inv.Org)
	if opts.Anonymize {
		org = redact("org", org, 8)
	}

	out := Snapshot{
		ExportVersion: "1",
		SchemaVersion: "v1",
		ExportedAt:    exportedAt.Format(time.RFC3339),
		Org:           org,
	}

	inventoryRows := make([]InventoryRow, 0, len(inv.Tools))
	approvalRows := make([]ApprovalGapRow, 0, len(inv.Tools))
	regulatoryRows := make([]RegulatoryMatrixRow, 0, len(inv.Tools)*4)
	for _, tool := range inv.Tools {
		row := InventoryRow{
			ToolID:          tool.ToolID,
			AgentID:         tool.AgentID,
			ToolType:        tool.ToolType,
			ToolCategory:    tool.ToolCategory,
			ConfidenceScore: tool.ConfidenceScore,
			Org:             tool.Org,
			RepoCount:       len(tool.Repos),
			PermissionTier:  tool.PermissionTier,
			RiskTier:        tool.RiskTier,
			AdoptionPattern: tool.AdoptionPattern,
			ApprovalClass:   tool.ApprovalClass,
			LifecycleState:  tool.LifecycleState,
		}
		approval := ApprovalGapRow{
			ToolID:          tool.ToolID,
			AgentID:         tool.AgentID,
			ToolType:        tool.ToolType,
			Org:             tool.Org,
			ApprovalClass:   tool.ApprovalClass,
			AdoptionPattern: tool.AdoptionPattern,
			RiskTier:        tool.RiskTier,
		}
		if opts.Anonymize {
			row.ToolID = redact("tool", row.ToolID, 12)
			row.AgentID = redact("agent", row.AgentID, 12)
			row.Org = redact("org", row.Org, 8)
			approval.ToolID = redact("tool", approval.ToolID, 12)
			approval.AgentID = redact("agent", approval.AgentID, 12)
			approval.Org = redact("org", approval.Org, 8)
		}
		inventoryRows = append(inventoryRows, row)
		approvalRows = append(approvalRows, approval)

		for _, mapping := range tool.RegulatoryMapping {
			regulatory := RegulatoryMatrixRow{
				ToolID:         tool.ToolID,
				AgentID:        tool.AgentID,
				ToolType:       tool.ToolType,
				Org:            tool.Org,
				Regulation:     mapping.Regulation,
				ControlID:      mapping.ControlID,
				Status:         mapping.Status,
				RiskTier:       tool.RiskTier,
				PermissionTier: tool.PermissionTier,
			}
			if opts.Anonymize {
				regulatory.ToolID = redact("tool", regulatory.ToolID, 12)
				regulatory.AgentID = redact("agent", regulatory.AgentID, 12)
				regulatory.Org = redact("org", regulatory.Org, 8)
			}
			regulatoryRows = append(regulatoryRows, regulatory)
		}
	}

	sort.Slice(inventoryRows, func(i, j int) bool {
		if inventoryRows[i].Org != inventoryRows[j].Org {
			return inventoryRows[i].Org < inventoryRows[j].Org
		}
		if inventoryRows[i].ToolType != inventoryRows[j].ToolType {
			return inventoryRows[i].ToolType < inventoryRows[j].ToolType
		}
		return inventoryRows[i].ToolID < inventoryRows[j].ToolID
	})
	sort.Slice(approvalRows, func(i, j int) bool {
		if approvalRows[i].Org != approvalRows[j].Org {
			return approvalRows[i].Org < approvalRows[j].Org
		}
		if approvalRows[i].ApprovalClass != approvalRows[j].ApprovalClass {
			return approvalRows[i].ApprovalClass < approvalRows[j].ApprovalClass
		}
		return approvalRows[i].ToolID < approvalRows[j].ToolID
	})
	sort.Slice(regulatoryRows, func(i, j int) bool {
		if regulatoryRows[i].Regulation != regulatoryRows[j].Regulation {
			return regulatoryRows[i].Regulation < regulatoryRows[j].Regulation
		}
		if regulatoryRows[i].ControlID != regulatoryRows[j].ControlID {
			return regulatoryRows[i].ControlID < regulatoryRows[j].ControlID
		}
		if regulatoryRows[i].Org != regulatoryRows[j].Org {
			return regulatoryRows[i].Org < regulatoryRows[j].Org
		}
		return regulatoryRows[i].ToolID < regulatoryRows[j].ToolID
	})

	privilegeRows := make([]PrivilegeRow, 0, len(inv.AgentPrivilegeMap))
	for _, entry := range inv.AgentPrivilegeMap {
		row := PrivilegeRow{
			AgentInstanceID:    entry.AgentInstanceID,
			AgentID:            entry.AgentID,
			ToolID:             entry.ToolID,
			ToolType:           entry.ToolType,
			Org:                entry.Org,
			RepoCount:          len(entry.Repos),
			PermissionCount:    len(entry.Permissions),
			EndpointClass:      entry.EndpointClass,
			DataClass:          entry.DataClass,
			AutonomyLevel:      entry.AutonomyLevel,
			RiskScore:          entry.RiskScore,
			WriteCapable:       entry.WriteCapable,
			CredentialAccess:   entry.CredentialAccess,
			ExecCapable:        entry.ExecCapable,
			ProductionWrite:    entry.ProductionWrite,
			MatchedTargetCount: len(entry.MatchedProductionTargets),
		}
		if opts.Anonymize {
			row.AgentInstanceID = redact("agent-instance", row.AgentInstanceID, 12)
			row.AgentID = redact("agent", row.AgentID, 12)
			row.ToolID = redact("tool", row.ToolID, 12)
			row.Org = redact("org", row.Org, 8)
		}
		privilegeRows = append(privilegeRows, row)
	}
	sort.Slice(privilegeRows, func(i, j int) bool {
		if privilegeRows[i].Org != privilegeRows[j].Org {
			return privilegeRows[i].Org < privilegeRows[j].Org
		}
		if privilegeRows[i].ToolType != privilegeRows[j].ToolType {
			return privilegeRows[i].ToolType < privilegeRows[j].ToolType
		}
		if privilegeRows[i].AgentInstanceID != privilegeRows[j].AgentInstanceID {
			return privilegeRows[i].AgentInstanceID < privilegeRows[j].AgentInstanceID
		}
		return privilegeRows[i].AgentID < privilegeRows[j].AgentID
	})

	out.InventoryRows = inventoryRows
	out.PrivilegeRows = privilegeRows
	out.ApprovalGapRows = approvalRows
	out.RegulatoryRows = regulatoryRows
	return out
}

func WriteCSV(snapshot Snapshot, dir string) (map[string]string, error) {
	trimmed := strings.TrimSpace(dir)
	if trimmed == "" {
		return nil, fmt.Errorf("csv output directory must not be empty")
	}
	cleanDir := filepath.Clean(trimmed)
	if err := os.MkdirAll(cleanDir, 0o750); err != nil {
		return nil, fmt.Errorf("create csv output directory: %w", err)
	}

	out := map[string]string{}
	if path, err := writeInventoryCSV(cleanDir, snapshot.InventoryRows); err != nil {
		return nil, err
	} else {
		out["inventory"] = path
	}
	if path, err := writePrivilegeCSV(cleanDir, snapshot.PrivilegeRows); err != nil {
		return nil, err
	} else {
		out["privilege_map"] = path
	}
	if path, err := writeApprovalCSV(cleanDir, snapshot.ApprovalGapRows); err != nil {
		return nil, err
	} else {
		out["approval_gap"] = path
	}
	if path, err := writeRegulatoryCSV(cleanDir, snapshot.RegulatoryRows); err != nil {
		return nil, err
	} else {
		out["regulatory_matrix"] = path
	}
	return out, nil
}

func writeInventoryCSV(dir string, rows []InventoryRow) (string, error) {
	path := filepath.Join(dir, "inventory.csv")
	header := []string{"tool_id", "agent_id", "tool_type", "tool_category", "confidence_score", "org", "repo_count", "permission_tier", "risk_tier", "adoption_pattern", "approval_classification", "lifecycle_state"}
	records := make([][]string, 0, len(rows)+1)
	records = append(records, header)
	for _, row := range rows {
		records = append(records, []string{
			row.ToolID,
			row.AgentID,
			row.ToolType,
			row.ToolCategory,
			strconv.FormatFloat(row.ConfidenceScore, 'f', 2, 64),
			row.Org,
			strconv.Itoa(row.RepoCount),
			row.PermissionTier,
			row.RiskTier,
			row.AdoptionPattern,
			row.ApprovalClass,
			row.LifecycleState,
		})
	}
	return path, writeCSV(path, records)
}

func writePrivilegeCSV(dir string, rows []PrivilegeRow) (string, error) {
	path := filepath.Join(dir, "privilege_map.csv")
	header := []string{"agent_instance_id", "agent_id", "tool_id", "tool_type", "org", "repo_count", "permission_count", "endpoint_class", "data_class", "autonomy_level", "risk_score", "write_capable", "credential_access", "exec_capable", "production_write", "matched_production_targets"}
	records := make([][]string, 0, len(rows)+1)
	records = append(records, header)
	for _, row := range rows {
		records = append(records, []string{
			row.AgentInstanceID,
			row.AgentID,
			row.ToolID,
			row.ToolType,
			row.Org,
			strconv.Itoa(row.RepoCount),
			strconv.Itoa(row.PermissionCount),
			row.EndpointClass,
			row.DataClass,
			row.AutonomyLevel,
			strconv.FormatFloat(row.RiskScore, 'f', 2, 64),
			strconv.FormatBool(row.WriteCapable),
			strconv.FormatBool(row.CredentialAccess),
			strconv.FormatBool(row.ExecCapable),
			strconv.FormatBool(row.ProductionWrite),
			strconv.Itoa(row.MatchedTargetCount),
		})
	}
	return path, writeCSV(path, records)
}

func writeApprovalCSV(dir string, rows []ApprovalGapRow) (string, error) {
	path := filepath.Join(dir, "approval_gap.csv")
	header := []string{"tool_id", "agent_id", "tool_type", "org", "approval_classification", "adoption_pattern", "risk_tier"}
	records := make([][]string, 0, len(rows)+1)
	records = append(records, header)
	for _, row := range rows {
		records = append(records, []string{
			row.ToolID,
			row.AgentID,
			row.ToolType,
			row.Org,
			row.ApprovalClass,
			row.AdoptionPattern,
			row.RiskTier,
		})
	}
	return path, writeCSV(path, records)
}

func writeRegulatoryCSV(dir string, rows []RegulatoryMatrixRow) (string, error) {
	path := filepath.Join(dir, "regulatory_matrix.csv")
	header := []string{"tool_id", "agent_id", "tool_type", "org", "regulation", "control_id", "status", "risk_tier", "permission_tier"}
	records := make([][]string, 0, len(rows)+1)
	records = append(records, header)
	for _, row := range rows {
		records = append(records, []string{
			row.ToolID,
			row.AgentID,
			row.ToolType,
			row.Org,
			row.Regulation,
			row.ControlID,
			row.Status,
			row.RiskTier,
			row.PermissionTier,
		})
	}
	return path, writeCSV(path, records)
}

func writeCSV(path string, records [][]string) (err error) {
	// #nosec G304 -- path is constrained to a validated csv output directory and fixed filenames.
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create csv %s: %w", path, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("close csv %s: %w", path, closeErr)
		}
	}()

	writer := csv.NewWriter(file)
	if err := writer.WriteAll(records); err != nil {
		return fmt.Errorf("write csv %s: %w", path, err)
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("flush csv %s: %w", path, err)
	}
	return nil
}

func redact(prefix, value string, width int) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	hex := fmt.Sprintf("%x", sum)
	if width <= 0 || width > len(hex) {
		width = len(hex)
	}
	return fmt.Sprintf("%s-%s", prefix, hex[:width])
}
