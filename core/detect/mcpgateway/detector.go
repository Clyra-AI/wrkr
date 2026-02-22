package mcpgateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "mcpgateway"

const (
	CoverageProtected   = "protected"
	CoverageUnprotected = "unprotected"
	CoverageUnknown     = "unknown"
)

const (
	PolicyPostureAllow   = "allow"
	PolicyPostureDeny    = "deny"
	PolicyPostureUnknown = "unknown"
)

const (
	reasonExplicitAllow   = "gateway_rule_allow"
	reasonExplicitDeny    = "gateway_rule_deny"
	reasonDefaultAllow    = "gateway_default_allow"
	reasonDefaultDeny     = "gateway_default_deny"
	reasonNoContext       = "gateway_context_missing"
	reasonNoMatchingRule  = "gateway_rule_missing"
	reasonPolicyAmbiguous = "gateway_policy_ambiguous"
)

// Policy is the normalized repo-level gateway policy posture.
type Policy struct {
	Detected      bool
	DefaultAction string
	Rules         map[string]string
	SourceFiles   []string
	Ambiguous     bool
}

// Result is a normalized gateway coverage decision for one declaration.
type Result struct {
	Coverage       string
	PolicyPosture  string
	DefaultAction  string
	ReasonCode     string
	GatewaySources []string
}

type declaration struct {
	name     string
	toolType string
	location string
}

type fileParseError struct {
	rel string
	err *model.ParseError
}

type filePolicy struct {
	defaultAction string
	rules         map[string]string
}

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	policy, parseErrors, err := LoadPolicy(scope.Root)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0, len(parseErrors)+8)
	for _, item := range parseErrors {
		if item.err == nil {
			continue
		}
		errCopy := *item.err
		errCopy.Detector = detectorID
		if errCopy.Path == "" {
			errCopy.Path = item.rel
		}
		if errCopy.Format == "" {
			errCopy.Format = formatFromPath(item.rel)
		}
		if errCopy.Kind == "" {
			errCopy.Kind = "parse_error"
		}
		findings = append(findings, model.Finding{
			FindingType: "parse_error",
			Severity:    model.SeverityHigh,
			ToolType:    "mcp_gateway",
			Location:    item.rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			ParseError:  &errCopy,
		})
	}

	declarations, declErr := discoverDeclarations(scope.Root)
	if declErr != nil {
		return nil, declErr
	}
	for _, item := range declarations {
		result := EvaluateCoverage(policy, item.name)
		severity := severityFromCoverage(result.Coverage)
		remediation := remediationFromCoverage(result.Coverage)
		findings = append(findings, model.Finding{
			FindingType: "mcp_gateway_posture",
			Severity:    severity,
			ToolType:    item.toolType,
			Location:    item.location,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Evidence: []model.Evidence{
				{Key: "declaration_name", Value: item.name},
				{Key: "coverage", Value: result.Coverage},
				{Key: "policy_posture", Value: result.PolicyPosture},
				{Key: "default_behavior", Value: result.DefaultAction},
				{Key: "trust_score", Value: trustScoreFromCoverage(result.Coverage)},
				{Key: "reason_code", Value: result.ReasonCode},
				{Key: "gateway_sources", Value: strings.Join(result.GatewaySources, ",")},
			},
			Remediation: remediation,
		})
	}

	model.SortFindings(findings)
	return findings, nil
}

// LoadPolicy parses all recognized gateway config files in root and returns one normalized policy.
func LoadPolicy(root string) (Policy, []fileParseError, error) {
	files, err := detect.WalkFiles(root)
	if err != nil {
		return Policy{}, nil, err
	}

	policy := Policy{Rules: map[string]string{}}
	parseErrors := make([]fileParseError, 0)

	for _, rel := range files {
		if !isGatewayCandidate(rel) {
			continue
		}
		parsed, parseErr := parseGatewayFile(root, rel)
		if parseErr != nil {
			parseErrors = append(parseErrors, fileParseError{rel: rel, err: parseErr})
			policy.Ambiguous = true
			continue
		}
		if parsed == nil {
			continue
		}
		if parsed.defaultAction == "" && len(parsed.rules) == 0 {
			continue
		}
		policy.Detected = true
		policy.SourceFiles = append(policy.SourceFiles, rel)

		if parsed.defaultAction != "" {
			if policy.DefaultAction == "" {
				policy.DefaultAction = parsed.defaultAction
			} else if policy.DefaultAction != parsed.defaultAction {
				policy.Ambiguous = true
				parseErrors = append(parseErrors, fileParseError{
					rel: rel,
					err: &model.ParseError{
						Kind:     reasonPolicyAmbiguous,
						Format:   formatFromPath(rel),
						Path:     rel,
						Detector: detectorID,
						Message:  fmt.Sprintf("conflicting default_action values: %q vs %q", policy.DefaultAction, parsed.defaultAction),
					},
				})
			}
		}
		for name, action := range parsed.rules {
			existing, exists := policy.Rules[name]
			if exists && existing != action {
				policy.Ambiguous = true
				parseErrors = append(parseErrors, fileParseError{
					rel: rel,
					err: &model.ParseError{
						Kind:     reasonPolicyAmbiguous,
						Format:   formatFromPath(rel),
						Path:     rel,
						Detector: detectorID,
						Message:  fmt.Sprintf("conflicting rule action for %q: %q vs %q", name, existing, action),
					},
				})
				continue
			}
			policy.Rules[name] = action
		}
	}

	if policy.DefaultAction == "" {
		policy.DefaultAction = PolicyPostureUnknown
	}
	sort.Strings(policy.SourceFiles)
	if len(policy.SourceFiles) == 0 {
		policy.SourceFiles = nil
	}
	return policy, parseErrors, nil
}

// EvaluateCoverage determines coverage posture for one declaration using normalized policy.
func EvaluateCoverage(policy Policy, declarationName string) Result {
	name := strings.ToLower(strings.TrimSpace(declarationName))
	result := Result{
		Coverage:       CoverageUnknown,
		PolicyPosture:  PolicyPostureUnknown,
		DefaultAction:  normalizeAction(policy.DefaultAction),
		ReasonCode:     reasonNoContext,
		GatewaySources: append([]string(nil), policy.SourceFiles...),
	}
	if !policy.Detected {
		return result
	}
	if policy.Ambiguous {
		result.ReasonCode = reasonPolicyAmbiguous
		return result
	}
	if action, ok := policy.Rules[name]; ok {
		normalized := normalizeAction(action)
		result.PolicyPosture = normalized
		result.Coverage = CoverageProtected
		if normalized == PolicyPostureAllow {
			result.ReasonCode = reasonExplicitAllow
		} else {
			result.ReasonCode = reasonExplicitDeny
		}
		return result
	}
	switch normalizeAction(policy.DefaultAction) {
	case PolicyPostureAllow:
		result.PolicyPosture = PolicyPostureAllow
		result.Coverage = CoverageUnprotected
		result.ReasonCode = reasonDefaultAllow
		return result
	case PolicyPostureDeny:
		result.PolicyPosture = PolicyPostureDeny
		result.Coverage = CoverageProtected
		result.ReasonCode = reasonDefaultDeny
		return result
	default:
		result.ReasonCode = reasonNoMatchingRule
		return result
	}
}

func discoverDeclarations(root string) ([]declaration, error) {
	files, err := detect.WalkFiles(root)
	if err != nil {
		return nil, err
	}

	type key struct {
		name     string
		toolType string
		location string
	}
	set := map[key]declaration{}
	for _, rel := range files {
		lower := strings.ToLower(rel)
		base := strings.ToLower(filepath.Base(rel))

		if isMCPConfigPath(lower) {
			names, parseErr := parseMCPServerNames(root, rel)
			if parseErr == nil {
				for _, name := range names {
					item := declaration{name: name, toolType: "mcp", location: rel}
					set[key(item)] = item
				}
			}
		}

		if isAgentCardPath(lower, base) {
			name, parseErr := parseAgentCardName(root, rel)
			if parseErr == nil && name != "" {
				item := declaration{name: name, toolType: "a2a_agent", location: rel}
				set[key(item)] = item
			}
		}

		if lower == ".well-known/webmcp" ||
			lower == ".well-known/webmcp.json" ||
			lower == ".well-known/webmcp.yaml" ||
			lower == ".well-known/webmcp.yml" ||
			strings.HasSuffix(lower, "/.well-known/webmcp") ||
			strings.HasSuffix(lower, "/.well-known/webmcp.json") ||
			strings.HasSuffix(lower, "/.well-known/webmcp.yaml") ||
			strings.HasSuffix(lower, "/.well-known/webmcp.yml") {
			item := declaration{name: "webmcp", toolType: "webmcp", location: rel}
			set[key(item)] = item
		}
	}

	out := make([]declaration, 0, len(set))
	for _, item := range set {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].toolType != out[j].toolType {
			return out[i].toolType < out[j].toolType
		}
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		return out[i].location < out[j].location
	})
	return out, nil
}

func parseGatewayFile(root, rel string) (*filePolicy, *model.ParseError) {
	doc, parseErr := parseLooseDocument(root, rel)
	if parseErr != nil {
		return nil, parseErr
	}
	if len(doc) == 0 {
		return nil, nil
	}

	result := &filePolicy{rules: map[string]string{}}

	for _, gatewayKey := range []string{"gateway", "mcp_gateway", "mcpgateway"} {
		if section, ok := mapAt(doc, gatewayKey); ok {
			mergeSectionPolicy(result, section)
		}
	}
	mergeKongPolicy(result, doc)
	mergeMintPolicy(result, doc)
	mergeDockerPolicy(result, doc)

	if result.defaultAction != "" {
		result.defaultAction = normalizeAction(result.defaultAction)
	}
	if result.defaultAction != "" && result.defaultAction == PolicyPostureUnknown {
		return nil, &model.ParseError{
			Kind:     reasonPolicyAmbiguous,
			Format:   formatFromPath(rel),
			Path:     rel,
			Detector: detectorID,
			Message:  "invalid gateway default_action; expected allow or deny",
		}
	}
	for name, action := range result.rules {
		normalized := normalizeAction(action)
		if normalized == PolicyPostureUnknown {
			return nil, &model.ParseError{
				Kind:     reasonPolicyAmbiguous,
				Format:   formatFromPath(rel),
				Path:     rel,
				Detector: detectorID,
				Message:  fmt.Sprintf("invalid gateway action for %q; expected allow or deny", name),
			}
		}
		result.rules[name] = normalized
	}
	return result, nil
}

func parseLooseDocument(root, rel string) (map[string]any, *model.ParseError) {
	doc := map[string]any{}
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".json":
		if parseErr := detect.ParseJSONFile(detectorID, root, rel, &doc); parseErr != nil {
			return nil, parseErr
		}
	case ".yaml", ".yml":
		if parseErr := detect.ParseYAMLFile(detectorID, root, rel, &doc); parseErr != nil {
			return nil, parseErr
		}
	case ".toml":
		if parseErr := detect.ParseTOMLFile(detectorID, root, rel, &doc); parseErr != nil {
			return nil, parseErr
		}
	default:
		return nil, nil
	}
	return doc, nil
}

func mergeSectionPolicy(target *filePolicy, section map[string]any) {
	if target == nil {
		return
	}
	if value := firstString(section, "default_action", "default", "policy_default"); value != "" {
		target.defaultAction = value
	}

	for _, key := range []string{"allow", "allow_tools", "allowed", "protected"} {
		for _, name := range splitCSV(listAsStrings(section[key])) {
			target.rules[strings.ToLower(name)] = PolicyPostureAllow
		}
	}
	for _, key := range []string{"deny", "deny_tools", "denied", "blocked"} {
		for _, name := range splitCSV(listAsStrings(section[key])) {
			target.rules[strings.ToLower(name)] = PolicyPostureDeny
		}
	}

	for _, item := range listAsMaps(section["rules"]) {
		name := strings.TrimSpace(firstString(item, "name", "tool", "target", "surface"))
		action := strings.TrimSpace(firstString(item, "action", "effect", "policy"))
		if name == "" || action == "" {
			continue
		}
		target.rules[strings.ToLower(name)] = action
	}
}

func mergeKongPolicy(target *filePolicy, doc map[string]any) {
	for _, plugin := range listAsMaps(doc["plugins"]) {
		name := strings.ToLower(strings.TrimSpace(firstString(plugin, "name")))
		if !strings.Contains(name, "mcp") {
			continue
		}
		if configMap, ok := mapAt(plugin, "config"); ok {
			mergeSectionPolicy(target, configMap)
		}
	}
}

func mergeMintPolicy(target *filePolicy, doc map[string]any) {
	for _, key := range []string{"mintmcp", "mint_mcp", "registry"} {
		section, ok := mapAt(doc, key)
		if !ok {
			continue
		}
		if registry, ok := mapAt(section, "registry"); ok {
			mergeSectionPolicy(target, registry)
			continue
		}
		mergeSectionPolicy(target, section)
	}
}

func mergeDockerPolicy(target *filePolicy, doc map[string]any) {
	services, ok := mapAt(doc, "services")
	if !ok {
		return
	}
	for _, service := range mapValuesAsMaps(services) {
		for _, labelsKey := range []string{"labels", "environment"} {
			entries := mapValuesAsStrings(service[labelsKey])
			if len(entries) == 0 {
				continue
			}
			if value := strings.TrimSpace(entries["wrkr.mcp_gateway.default_action"]); value != "" {
				target.defaultAction = value
			}
			for _, name := range splitCSV([]string{entries["wrkr.mcp_gateway.allow_tools"], entries["WRKR_MCP_GATEWAY_ALLOW_TOOLS"]}) {
				target.rules[strings.ToLower(name)] = PolicyPostureAllow
			}
			for _, name := range splitCSV([]string{entries["wrkr.mcp_gateway.deny_tools"], entries["WRKR_MCP_GATEWAY_DENY_TOOLS"]}) {
				target.rules[strings.ToLower(name)] = PolicyPostureDeny
			}
		}
	}
}

func parseMCPServerNames(root, rel string) ([]string, *model.ParseError) {
	doc, parseErr := parseLooseDocument(root, rel)
	if parseErr != nil {
		return nil, parseErr
	}
	servers, ok := mapAt(doc, "mcpServers")
	if !ok {
		servers, ok = mapAt(doc, "mcp_servers")
		if !ok {
			return nil, nil
		}
	}
	names := make([]string, 0, len(servers))
	for key := range servers {
		trimmed := strings.ToLower(strings.TrimSpace(key))
		if trimmed == "" {
			continue
		}
		names = append(names, trimmed)
	}
	sort.Strings(names)
	return names, nil
}

func parseAgentCardName(root, rel string) (string, *model.ParseError) {
	type card struct {
		Name string `json:"name"`
	}
	var parsed card
	if parseErr := detect.ParseJSONFile(detectorID, root, rel, &parsed); parseErr != nil {
		return "", parseErr
	}
	name := strings.ToLower(strings.TrimSpace(parsed.Name))
	if name == "" {
		name = strings.TrimSuffix(strings.ToLower(filepath.Base(rel)), filepath.Ext(rel))
	}
	return name, nil
}

func isGatewayCandidate(rel string) bool {
	lower := strings.ToLower(rel)
	ext := strings.ToLower(filepath.Ext(lower))
	if ext != ".json" && ext != ".yaml" && ext != ".yml" && ext != ".toml" {
		return false
	}
	base := strings.ToLower(filepath.Base(lower))
	switch {
	case strings.Contains(base, "mcp-gateway"), strings.Contains(base, "mcpgateway"), strings.Contains(base, "mintmcp"):
		return true
	case strings.HasPrefix(base, "docker-compose"):
		return true
	case strings.Contains(base, "kong") && strings.Contains(lower, "mcp"):
		return true
	case strings.Contains(base, "docker") && strings.Contains(lower, "mcp"):
		return true
	default:
		return false
	}
}

func isMCPConfigPath(lowerRel string) bool {
	switch lowerRel {
	case ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", "mcp.json", "managed-mcp.json", ".claude/settings.json", ".claude/settings.local.json", ".codex/config.toml", ".codex/config.yaml", ".codex/config.yml":
		return true
	default:
		return false
	}
}

func isAgentCardPath(lowerRel, base string) bool {
	if base != "agent.json" && base != "agent-card.json" {
		return false
	}
	return strings.HasSuffix(lowerRel, "/.well-known/agent.json") || strings.HasSuffix(lowerRel, "/agent.json") || strings.HasSuffix(lowerRel, "/agent-card.json")
}

func severityFromCoverage(coverage string) string {
	switch coverage {
	case CoverageProtected:
		return model.SeverityLow
	case CoverageUnprotected:
		return model.SeverityHigh
	default:
		return model.SeverityMedium
	}
}

func remediationFromCoverage(coverage string) string {
	switch coverage {
	case CoverageProtected:
		return "Gateway policy is present for this declaration. Keep explicit allow/deny controls pinned and audited."
	case CoverageUnprotected:
		return "Add explicit deny-by-default gateway controls for this declaration and avoid wildcard allow behavior."
	default:
		return "Add deterministic gateway policy context to classify this declaration as protected or unprotected."
	}
}

func trustScoreFromCoverage(coverage string) string {
	switch coverage {
	case CoverageProtected:
		return "8.0"
	case CoverageUnprotected:
		return "2.0"
	default:
		return "5.0"
	}
}

func formatFromPath(rel string) string {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".yaml", ".yml":
		return "yaml"
	case ".toml":
		return "toml"
	default:
		return "json"
	}
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return strings.TrimSpace(org)
}

func normalizeAction(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case PolicyPostureAllow:
		return PolicyPostureAllow
	case PolicyPostureDeny:
		return PolicyPostureDeny
	default:
		return PolicyPostureUnknown
	}
}

func mapAt(in map[string]any, key string) (map[string]any, bool) {
	if len(in) == 0 {
		return nil, false
	}
	value, ok := in[key]
	if !ok {
		return nil, false
	}
	typed, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	return typed, true
}

func mapValuesAsMaps(in map[string]any) []map[string]any {
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		typed, ok := in[key].(map[string]any)
		if !ok {
			continue
		}
		out = append(out, typed)
	}
	return out
}

func mapValuesAsStrings(in any) map[string]string {
	out := map[string]string{}
	switch typed := in.(type) {
	case map[string]any:
		for key, value := range typed {
			if str, ok := value.(string); ok {
				out[key] = str
			}
		}
	case map[string]string:
		for key, value := range typed {
			out[key] = value
		}
	case []any:
		for _, item := range typed {
			entry, ok := item.(string)
			if !ok {
				continue
			}
			parts := strings.SplitN(entry, "=", 2)
			if len(parts) != 2 {
				continue
			}
			out[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return out
}

func listAsMaps(in any) []map[string]any {
	items, ok := in.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		typed, ok := item.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, typed)
	}
	return out
}

func listAsStrings(in any) []string {
	items, ok := in.([]any)
	if !ok {
		switch typed := in.(type) {
		case []string:
			return append([]string(nil), typed...)
		default:
			return nil
		}
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		str, ok := item.(string)
		if !ok {
			continue
		}
		trimmed := strings.TrimSpace(str)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func splitCSV(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		for _, item := range strings.Split(value, ",") {
			trimmed := strings.TrimSpace(strings.ToLower(item))
			if trimmed == "" {
				continue
			}
			set[trimmed] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func firstString(in map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := in[key].(string); ok {
			trimmed := strings.TrimSpace(value)
			if trimmed != "" {
				return trimmed
			}
		}
	}
	return ""
}
