package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
	"gopkg.in/yaml.v3"
)

const (
	MCPTrustTrusted     = "trusted"
	MCPTrustBlocked     = "blocked"
	MCPTrustUnreviewed  = "unreviewed"
	MCPTrustUnavailable = "unavailable"
)

type MCPList struct {
	Status      string       `json:"status"`
	GeneratedAt string       `json:"generated_at"`
	Rows        []MCPListRow `json:"rows"`
	Warnings    []string     `json:"warnings,omitempty"`
}

type MCPListRow struct {
	ServerName           string   `json:"server_name"`
	Org                  string   `json:"org"`
	Repo                 string   `json:"repo"`
	Location             string   `json:"location"`
	Transport            string   `json:"transport"`
	RequestedPermissions []string `json:"requested_permissions,omitempty"`
	PrivilegeSurface     []string `json:"privilege_surface,omitempty"`
	GatewayCoverage      string   `json:"gateway_coverage"`
	TrustStatus          string   `json:"trust_status"`
	RiskNote             string   `json:"risk_note"`
}

type mcpTrustOverlay struct {
	Servers map[string]mcpTrustEntry `yaml:"servers"`
}

type mcpTrustEntry struct {
	TrustStatus string `yaml:"trust_status"`
}

func BuildMCPList(snapshot state.Snapshot, generatedAt time.Time, overlayPath string, allowAmbientOverlay bool) MCPList {
	overlay, warnings := loadMCPTrustOverlay(strings.TrimSpace(overlayPath), allowAmbientOverlay)
	warnings = append(warnings, MCPVisibilityWarnings(snapshot.Findings)...)
	toolSurfaces := buildMCPToolSurfaceIndex(snapshot.Inventory)
	gatewayCoverage := buildMCPGatewayCoverageIndex(snapshot.Findings)

	rows := make([]MCPListRow, 0)
	for _, finding := range snapshot.Findings {
		if strings.TrimSpace(finding.FindingType) != "mcp_server" {
			continue
		}
		evidence := evidenceMap(finding.Evidence)
		serverName := fallbackString(evidence["server"], strings.TrimSpace(finding.Location))
		rowKey := mcpRowKey(finding.Org, finding.Repo, finding.Location, serverName)
		toolKey := mcpToolKey(finding.Org, finding.Repo, finding.Location)
		privilegeSurface := append([]string(nil), toolSurfaces[toolKey]...)
		trustStatus := overlay[strings.ToLower(strings.TrimSpace(serverName))]
		if trustStatus == "" {
			trustStatus = MCPTrustUnavailable
		}

		row := MCPListRow{
			ServerName:           strings.TrimSpace(serverName),
			Org:                  fallbackString(strings.TrimSpace(finding.Org), "local"),
			Repo:                 strings.TrimSpace(finding.Repo),
			Location:             strings.TrimSpace(finding.Location),
			Transport:            fallbackString(evidence["transport"], "unknown"),
			RequestedPermissions: append([]string(nil), finding.Permissions...),
			PrivilegeSurface:     privilegeSurface,
			GatewayCoverage:      fallbackString(gatewayCoverage[rowKey], "unknown"),
			TrustStatus:          trustStatus,
			RiskNote:             buildMCPRiskNote(finding, trustStatus, fallbackString(gatewayCoverage[rowKey], "unknown")),
		}
		rows = append(rows, row)
	}

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Org != rows[j].Org {
			return rows[i].Org < rows[j].Org
		}
		if rows[i].Repo != rows[j].Repo {
			return rows[i].Repo < rows[j].Repo
		}
		if rows[i].ServerName != rows[j].ServerName {
			return rows[i].ServerName < rows[j].ServerName
		}
		return rows[i].Location < rows[j].Location
	})

	return MCPList{
		Status:      "ok",
		GeneratedAt: ResolveGeneratedAtForCLI(snapshot, generatedAt).Format(time.RFC3339),
		Rows:        rows,
		Warnings:    warnings,
	}
}

func MCPVisibilityWarnings(findings []source.Finding) []string {
	locations := map[string]struct{}{}
	hasMCPRows := false
	for _, finding := range findings {
		if strings.TrimSpace(finding.FindingType) == "mcp_server" {
			hasMCPRows = true
			continue
		}
		if strings.TrimSpace(finding.FindingType) != "parse_error" {
			continue
		}
		location := strings.TrimSpace(finding.Location)
		if !isKnownMCPDeclarationPath(location) {
			continue
		}
		locations[location] = struct{}{}
	}
	if len(locations) == 0 {
		return nil
	}

	ordered := make([]string, 0, len(locations))
	for location := range locations {
		ordered = append(ordered, location)
	}
	sort.Strings(ordered)

	prefix := "MCP visibility may be incomplete because these declaration files failed to parse: "
	if !hasMCPRows {
		prefix = "MCP visibility incomplete: no MCP rows were emitted because these declaration files failed to parse: "
	}
	return []string{prefix + strings.Join(ordered, ", ")}
}

func isKnownMCPDeclarationPath(location string) bool {
	switch strings.TrimSpace(location) {
	case ".mcp.json",
		".cursor/mcp.json",
		".vscode/mcp.json",
		"mcp.json",
		"managed-mcp.json",
		".claude/settings.json",
		".claude/settings.local.json",
		".codex/config.toml",
		".codex/config.yaml",
		".codex/config.yml":
		return true
	default:
		return false
	}
}

func ResolveGeneratedAtForCLI(snapshot state.Snapshot, generatedAt time.Time) time.Time {
	if !generatedAt.IsZero() {
		return generatedAt.UTC().Truncate(time.Second)
	}
	if snapshot.Inventory != nil {
		if parsed, ok := parseRFC3339(strings.TrimSpace(snapshot.Inventory.GeneratedAt)); ok {
			return parsed
		}
	}
	if snapshot.RiskReport != nil {
		if parsed, ok := parseRFC3339(strings.TrimSpace(snapshot.RiskReport.GeneratedAt)); ok {
			return parsed
		}
	}
	return time.Now().UTC().Truncate(time.Second)
}

func parseRFC3339(raw string) (time.Time, bool) {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}, false
	}
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err != nil {
		return time.Time{}, false
	}
	return parsed.UTC().Truncate(time.Second), true
}

func buildMCPToolSurfaceIndex(inv *agginventory.Inventory) map[string][]string {
	out := map[string][]string{}
	if inv == nil {
		return out
	}
	for _, tool := range inv.Tools {
		if strings.TrimSpace(tool.ToolType) != "mcp" {
			continue
		}
		surface := privilegeSurfaceList(tool.PermissionSurface, tool.Permissions)
		for _, loc := range tool.Locations {
			out[mcpToolKey(tool.Org, loc.Repo, loc.Location)] = append([]string(nil), surface...)
		}
	}
	return out
}

func buildMCPGatewayCoverageIndex(findings []model.Finding) map[string]string {
	out := map[string]string{}
	for _, finding := range findings {
		if strings.TrimSpace(finding.FindingType) != "mcp_gateway_posture" {
			continue
		}
		evidence := evidenceMap(finding.Evidence)
		name := strings.TrimSpace(evidence["declaration_name"])
		if name == "" {
			continue
		}
		out[mcpRowKey(finding.Org, finding.Repo, finding.Location, name)] = fallbackString(strings.TrimSpace(evidence["coverage"]), "unknown")
	}
	return out
}

func evidenceMap(in []model.Evidence) map[string]string {
	out := make(map[string]string, len(in))
	for _, item := range in {
		key := strings.TrimSpace(item.Key)
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(item.Value)
	}
	return out
}

func mcpRowKey(org, repo, location, server string) string {
	return strings.Join([]string{
		fallbackString(strings.TrimSpace(org), "local"),
		strings.TrimSpace(repo),
		strings.TrimSpace(location),
		strings.ToLower(strings.TrimSpace(server)),
	}, "::")
}

func mcpToolKey(org, repo, location string) string {
	return strings.Join([]string{
		fallbackString(strings.TrimSpace(org), "local"),
		strings.TrimSpace(repo),
		strings.TrimSpace(location),
	}, "::")
}

func privilegeSurfaceList(surface agginventory.PermissionSurface, permissions []string) []string {
	items := make([]string, 0, 4)
	if surface.Read {
		items = append(items, "read")
	}
	if surface.Write {
		items = append(items, "write")
	}
	if surface.Admin {
		items = append(items, "admin")
	}
	if len(items) == 0 && len(permissions) > 0 {
		items = append(items, "access")
	}
	return items
}

func buildMCPRiskNote(finding model.Finding, trustStatus, gatewayCoverage string) string {
	switch trustStatus {
	case MCPTrustBlocked:
		return "Gait trust overlay marks this server blocked."
	case MCPTrustUnavailable:
		if gatewayCoverage == "unprotected" {
			return "No local Gait trust overlay; gateway posture is unprotected."
		}
		return "No local Gait trust overlay; static discovery only."
	}

	switch gatewayCoverage {
	case "unprotected":
		return "Gateway posture is unprotected; review least-privilege controls."
	case "unknown":
		return "Gateway posture is unknown; verify transport and access scope."
	}

	switch strings.ToLower(strings.TrimSpace(finding.Severity)) {
	case model.SeverityCritical, model.SeverityHigh:
		return "Static MCP declaration carries elevated trust or privilege risk."
	case model.SeverityMedium:
		return "Review transport, pinning, and credential references."
	default:
		return "Static MCP declaration discovered; verify package pinning and trust."
	}
}

func loadMCPTrustOverlay(rawPath string, allowAmbientOverlay bool) (map[string]string, []string) {
	path, explicit := resolveMCPTrustOverlayPath(rawPath, allowAmbientOverlay)
	if path == "" {
		return map[string]string{}, nil
	}

	payload, err := os.ReadFile(path) // #nosec G304 -- caller-selected local overlay path is intentionally readable.
	if err != nil {
		if os.IsNotExist(err) && !explicit {
			return map[string]string{}, nil
		}
		return map[string]string{}, []string{fmt.Sprintf("gait trust overlay unavailable: %s", filepath.Clean(path))}
	}

	var overlay mcpTrustOverlay
	if err := yaml.Unmarshal(payload, &overlay); err != nil {
		return map[string]string{}, []string{fmt.Sprintf("gait trust overlay unavailable: %s", filepath.Clean(path))}
	}

	out := map[string]string{}
	for name, item := range overlay.Servers {
		normalizedName := strings.ToLower(strings.TrimSpace(name))
		if normalizedName == "" {
			continue
		}
		out[normalizedName] = normalizeMCPTrustStatus(item.TrustStatus)
	}
	return out, nil
}

func resolveMCPTrustOverlayPath(rawPath string, allowAmbientOverlay bool) (string, bool) {
	if strings.TrimSpace(rawPath) != "" {
		return strings.TrimSpace(rawPath), true
	}
	if !allowAmbientOverlay {
		return "", false
	}
	if fromEnv := strings.TrimSpace(os.Getenv("WRKR_GAIT_TRUST_PATH")); fromEnv != "" {
		return fromEnv, true
	}

	candidates := make([]string, 0, 4)
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates,
			filepath.Join(cwd, ".gait", "trust-registry.yaml"),
			filepath.Join(cwd, ".gait", "trust-registry.yml"),
		)
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".gait", "trust-registry.yaml"),
			filepath.Join(home, ".gait", "trust-registry.yml"),
		)
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, false
		}
	}
	return "", false
}

func normalizeMCPTrustStatus(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case MCPTrustTrusted:
		return MCPTrustTrusted
	case MCPTrustBlocked:
		return MCPTrustBlocked
	case MCPTrustUnreviewed:
		return MCPTrustUnreviewed
	default:
		return MCPTrustUnavailable
	}
}

func fallbackString(value, fallbackValue string) string {
	if strings.TrimSpace(value) == "" {
		return fallbackValue
	}
	return strings.TrimSpace(value)
}
