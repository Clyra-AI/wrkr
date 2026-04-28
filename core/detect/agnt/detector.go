package agnt

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "agnt"

type Detector struct{}

type manifestDoc struct {
	Name        string        `yaml:"name"`
	File        string        `yaml:"file"`
	Tools       []string      `yaml:"tools"`
	MCPRefs     []string      `yaml:"mcp_refs"`
	Permissions []string      `yaml:"permissions"`
	PolicyRefs  []string      `yaml:"policy_refs"`
	OwnerRefs   []string      `yaml:"owner_refs"`
	Lifecycle   manifestState `yaml:"lifecycle"`
}

type manifestState struct {
	State          string `yaml:"state"`
	ApprovalStatus string `yaml:"approval_status"`
}

type declaration struct {
	finding          model.Finding
	name             string
	manifestPath     string
	declaredTools    []string
	declaredMCPRefs  []string
	declaredPerms    []string
	declaredPolicies []string
}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

func (Detector) Detect(_ context.Context, scope detect.Scope, options detect.Options) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}

	files, err := detect.WalkFilesWithOptions(scope.Root, options)
	if err != nil {
		return nil, err
	}
	findings := make([]model.Finding, 0)
	for _, rel := range files {
		if !isAgntManifestPath(rel) {
			continue
		}
		var parsed manifestDoc
		if parseErr := detect.ParseYAMLFileAllowUnknownFields(detectorID, scope.Root, rel, &parsed); parseErr != nil {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "agnt_agent",
				Location:    rel,
				Repo:        strings.TrimSpace(scope.Repo),
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  parseErr,
				Remediation: "Fix malformed Agnt manifest and preserve deterministic YAML compatibility.",
			})
			continue
		}
		name := strings.TrimSpace(parsed.Name)
		if name == "" {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "agnt_agent",
				Location:    rel,
				Repo:        strings.TrimSpace(scope.Repo),
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError: &model.ParseError{
					Kind:     "schema_validation_error",
					Format:   "yaml",
					Path:     rel,
					Detector: detectorID,
					Message:  "agnt manifest field name is required",
				},
				Remediation: "Add a non-empty agent name to the Agnt manifest.",
			})
			continue
		}
		location := strings.TrimSpace(parsed.File)
		if location == "" {
			location = rel
		}
		evidence := []model.Evidence{
			{Key: "manifest_name", Value: name},
			{Key: "manifest_path", Value: rel},
			{Key: "declared_tools", Value: strings.Join(normalizeList(parsed.Tools), ",")},
			{Key: "declared_mcp_refs", Value: strings.Join(normalizeList(parsed.MCPRefs), ",")},
			{Key: "declared_permissions", Value: strings.Join(normalizeList(parsed.Permissions), ",")},
			{Key: "declared_policy_refs", Value: strings.Join(normalizeList(parsed.PolicyRefs), ",")},
			{Key: "declared_owner_refs", Value: strings.Join(normalizeList(parsed.OwnerRefs), ",")},
			{Key: "declared_lifecycle_state", Value: strings.TrimSpace(parsed.Lifecycle.State)},
			{Key: "declared_approval_status", Value: strings.TrimSpace(parsed.Lifecycle.ApprovalStatus)},
		}
		severity := model.SeverityLow
		if containsHighRiskPermission(parsed.Permissions) || len(parsed.MCPRefs) > 0 {
			severity = model.SeverityMedium
		}
		findings = append(findings, model.Finding{
			FindingType: "agnt_manifest",
			Severity:    severity,
			ToolType:    "agnt_agent",
			Location:    location,
			Repo:        strings.TrimSpace(scope.Repo),
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Permissions: normalizeList(parsed.Permissions),
			Evidence:    evidence,
			Remediation: "Keep governed Agnt manifests aligned with the agent's declared permissions, tools, and policy references.",
		})
	}
	model.SortFindings(findings)
	return findings, nil
}

func SynthesizeDrift(findings []model.Finding) []model.Finding {
	declared := make([]declaration, 0)
	for _, finding := range findings {
		if strings.TrimSpace(finding.FindingType) != "agnt_manifest" {
			continue
		}
		evidence := evidenceMap(finding.Evidence)
		declared = append(declared, declaration{
			finding:          finding,
			name:             strings.ToLower(strings.TrimSpace(firstNonEmpty(evidence["manifest_name"], evidence["agent_name"]))),
			manifestPath:     strings.TrimSpace(evidence["manifest_path"]),
			declaredTools:    splitCSV(evidence["declared_tools"]),
			declaredMCPRefs:  splitCSV(evidence["declared_mcp_refs"]),
			declaredPerms:    splitCSV(evidence["declared_permissions"]),
			declaredPolicies: splitCSV(evidence["declared_policy_refs"]),
		})
	}
	if len(declared) == 0 {
		return nil
	}

	drift := make([]model.Finding, 0)
	for _, decl := range declared {
		observedPerms := make([]string, 0)
		observedTools := make([]string, 0)
		observedMCPRefs := make([]string, 0)
		for _, finding := range findings {
			if strings.TrimSpace(finding.FindingType) == "agnt_manifest" || strings.TrimSpace(finding.FindingType) == "agnt_declared_observed_drift" {
				continue
			}
			if !sameRepoOrg(finding, decl.finding) {
				continue
			}
			if !matchesAgntDeclaration(finding, decl) {
				continue
			}
			observedPerms = append(observedPerms, finding.Permissions...)
			evidence := evidenceMap(finding.Evidence)
			observedTools = append(observedTools, splitCSV(evidence["bound_tools"])...)
			observedTools = append(observedTools, splitCSV(evidence["capability_exposure"])...)
			if server := strings.TrimSpace(evidence["server"]); server != "" {
				observedMCPRefs = append(observedMCPRefs, server)
			}
		}
		missingPerms := diffValues(observedPerms, decl.declaredPerms)
		missingTools := diffValues(observedTools, decl.declaredTools)
		missingMCPRefs := diffValues(observedMCPRefs, decl.declaredMCPRefs)
		if len(missingPerms) == 0 && len(missingTools) == 0 && len(missingMCPRefs) == 0 {
			continue
		}
		severity := model.SeverityMedium
		if containsHighRiskPermission(missingPerms) || len(missingMCPRefs) > 0 {
			severity = model.SeverityHigh
		}
		drift = append(drift, model.Finding{
			FindingType: "agnt_declared_observed_drift",
			Severity:    severity,
			ToolType:    "agnt_agent",
			Location:    strings.TrimSpace(decl.finding.Location),
			Repo:        strings.TrimSpace(decl.finding.Repo),
			Org:         strings.TrimSpace(decl.finding.Org),
			Detector:    detectorID,
			Permissions: missingPerms,
			Evidence: []model.Evidence{
				{Key: "agent_name", Value: decl.name},
				{Key: "declared_permissions", Value: strings.Join(decl.declaredPerms, ",")},
				{Key: "observed_excess_permissions", Value: strings.Join(missingPerms, ",")},
				{Key: "declared_tools", Value: strings.Join(decl.declaredTools, ",")},
				{Key: "observed_excess_tools", Value: strings.Join(missingTools, ",")},
				{Key: "declared_mcp_refs", Value: strings.Join(decl.declaredMCPRefs, ",")},
				{Key: "observed_excess_mcp_refs", Value: strings.Join(missingMCPRefs, ",")},
				{Key: "declared_policy_refs", Value: strings.Join(decl.declaredPolicies, ",")},
			},
			Remediation: "Tighten the Agnt manifest so declared permissions, tools, and MCP references cover the observed execution envelope.",
		})
	}
	model.SortFindings(drift)
	return drift
}

func isAgntManifestPath(rel string) bool {
	lower := strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(lower)
	if base != "agent.yaml" && base != "agent.yml" {
		return false
	}
	for _, blocked := range []string{"/vendor/", "/node_modules/", "/dist/", "/build/", "/.github/workflows/"} {
		if strings.Contains(lower, blocked) {
			return false
		}
	}
	switch {
	case lower == "agent.yaml", lower == "agent.yml":
		return true
	case strings.HasSuffix(lower, "/.well-known/agent.yaml"), strings.HasSuffix(lower, "/.well-known/agent.yml"):
		return true
	case strings.HasSuffix(lower, "/.wrkr/agents/agent.yaml"), strings.HasSuffix(lower, "/.wrkr/agents/agent.yml"):
		return true
	default:
		return false
	}
}

func normalizeList(values []string) []string {
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := set[trimmed]; ok {
			continue
		}
		set[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func splitCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	return normalizeList(strings.Split(raw, ","))
}

func evidenceMap(evidence []model.Evidence) map[string]string {
	out := make(map[string]string, len(evidence))
	for _, item := range evidence {
		key := strings.ToLower(strings.TrimSpace(item.Key))
		if key == "" {
			continue
		}
		out[key] = strings.TrimSpace(item.Value)
	}
	return out
}

func matchesAgntDeclaration(finding model.Finding, decl declaration) bool {
	if strings.TrimSpace(decl.finding.Location) != "" && strings.TrimSpace(finding.Location) == strings.TrimSpace(decl.finding.Location) {
		return true
	}
	evidence := evidenceMap(finding.Evidence)
	for _, key := range []string{"name", "agent_name", "symbol"} {
		if strings.ToLower(strings.TrimSpace(evidence[key])) == decl.name && decl.name != "" {
			return true
		}
	}
	return false
}

func diffValues(observed []string, declared []string) []string {
	allowed := map[string]struct{}{}
	for _, value := range normalizeList(declared) {
		allowed[strings.TrimSpace(value)] = struct{}{}
	}
	out := make([]string, 0)
	for _, value := range normalizeList(observed) {
		if _, ok := allowed[strings.TrimSpace(value)]; ok {
			continue
		}
		out = append(out, strings.TrimSpace(value))
	}
	return normalizeList(out)
}

func containsHighRiskPermission(values []string) bool {
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if strings.Contains(normalized, "write") || strings.Contains(normalized, "deploy") || strings.Contains(normalized, "exec") || strings.Contains(normalized, "admin") {
			return true
		}
	}
	return false
}

func sameRepoOrg(a, b model.Finding) bool {
	return strings.TrimSpace(a.Repo) == strings.TrimSpace(b.Repo) && fallbackOrg(a.Org) == fallbackOrg(b.Org)
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return strings.TrimSpace(org)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
