package mcp

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/mcp/enrich"
	"github.com/Clyra-AI/wrkr/core/detect/mcpgateway"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/supplychain"
)

const detectorID = "mcp"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

type serverDef struct {
	Command          string            `json:"command" yaml:"command" toml:"command"`
	Args             []string          `json:"args" yaml:"args" toml:"args"`
	URL              string            `json:"url" yaml:"url" toml:"url"`
	Transport        string            `json:"transport" yaml:"transport" toml:"transport"`
	Auth             string            `json:"auth" yaml:"auth" toml:"auth"`
	AuthStrength     string            `json:"auth_strength" yaml:"auth_strength" toml:"auth_strength"`
	Delegation       string            `json:"delegation" yaml:"delegation" toml:"delegation"`
	Exposure         string            `json:"exposure" yaml:"exposure" toml:"exposure"`
	PolicyRefs       []string          `json:"policy_refs" yaml:"policy_refs" toml:"policy_refs"`
	Sanitization     []string          `json:"sanitization_claims" yaml:"sanitization_claims" toml:"sanitization_claims"`
	Env              map[string]string `json:"env" yaml:"env" toml:"env"`
	Permissions      []string          `json:"permissions" yaml:"permissions" toml:"permissions"`
	PrivilegeSurface []string          `json:"privilegeSurface" yaml:"privilegeSurface" toml:"privilege_surface"`
	Access           string            `json:"access" yaml:"access" toml:"access"`
	Mode             string            `json:"mode" yaml:"mode" toml:"mode"`
}

type mcpDoc struct {
	MCPServers map[string]serverDef `json:"mcpServers" yaml:"mcpServers" toml:"mcp_servers"`
}

var pinRE = regexp.MustCompile(`@[0-9]+`)
var packageRE = regexp.MustCompile(`(@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+|[A-Za-z0-9._-]+)(?:@([A-Za-z0-9._-]+))?`)

func (Detector) Detect(ctx context.Context, scope detect.Scope, options detect.Options) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}

	var enrichService enrich.Service
	if options.Enrich {
		enrichService = enrich.NewDefault()
	}

	lockfilePresent := hasLockfile(scope.Root)
	policy, _, policyErr := mcpgateway.LoadPolicyWithOptions(scope.Root, options)
	if policyErr != nil {
		return nil, policyErr
	}
	findings := make([]model.Finding, 0)
	paths := []string{
		".mcp.json",
		".cursor/mcp.json",
		".vscode/mcp.json",
		"mcp.json",
		"managed-mcp.json",
		".claude/settings.json",
		".claude/settings.local.json",
		".codex/config.toml",
		".codex/config.yaml",
	}
	for _, rel := range paths {
		exists, fileErr := detect.FileExistsWithinRoot(detectorID, scope.Root, rel)
		if fileErr != nil {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "mcp",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  fileErr,
			})
			continue
		}
		if !exists {
			continue
		}
		doc, parseErr := parseMCPDocument(scope.Root, rel)
		if parseErr != nil {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "mcp",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  parseErr,
			})
			continue
		}
		for _, name := range sortedServerNames(doc.MCPServers) {
			server := doc.MCPServers[name]
			transport := inferTransport(server)
			credentialRefs := countCredentialRefs(server)
			pinned := isPinned(server)
			actionSurface := deriveDeclaredActionSurface(server)
			gateway := mcpgateway.EvaluateCoverage(policy, name)
			trustDepth := buildMCPTrustDepth(server, transport, credentialRefs, actionSurface, gateway)
			trustScore := supplychain.ScoreMCP(supplychain.MCPInput{
				Transport:      transport,
				Pinned:         pinned,
				HasLockfile:    lockfilePresent,
				CredentialRefs: credentialRefs,
			})
			if trustDepth != nil && trustDepth.TrustDepthScore > 0 && trustDepth.TrustDepthScore < trustScore {
				trustScore = trustDepth.TrustDepthScore
			}
			severity := supplychain.SeverityFromTrust(trustScore)
			if trustDepthRequiresHighSeverity(trustDepth) {
				severity = model.SeverityHigh
			} else if trustDepthRequiresMediumSeverity(trustDepth) && severity == model.SeverityLow {
				severity = model.SeverityMedium
			}
			evidence := []model.Evidence{
				{Key: "server", Value: name},
				{Key: "transport", Value: transport},
				{Key: "pinned", Value: fmt.Sprintf("%t", pinned)},
				{Key: "lockfile", Value: fmt.Sprintf("%t", lockfilePresent)},
				{Key: "credential_refs", Value: fmt.Sprintf("%d", credentialRefs)},
				{Key: "trust_score", Value: fmt.Sprintf("%.1f", trustScore)},
				{Key: "declared_action_surface", Value: fallbackValue(strings.Join(actionSurface, ","), "unknown")},
			}
			evidence = append(evidence, trustDepthEvidence(trustDepth)...)
			if options.Enrich {
				pkg, version := extractPackageVersion(server)
				enrichResult := enrichService.Lookup(ctx, pkg, version)
				enrichErrors := "none"
				if len(enrichResult.Errors) > 0 {
					enrichErrors = strings.Join(enrichResult.Errors, ",")
				}
				evidence = append(evidence,
					model.Evidence{Key: "enrich_mode", Value: "true"},
					model.Evidence{Key: "enrich_quality", Value: enrichResult.Quality},
					model.Evidence{Key: "enrich_errors", Value: enrichErrors},
					model.Evidence{Key: "source", Value: enrichResult.Source},
					model.Evidence{Key: "as_of", Value: enrichResult.AsOf},
					model.Evidence{Key: "advisory_schema", Value: enrichResult.AdvisorySchema},
					model.Evidence{Key: "registry_schema", Value: enrichResult.RegistrySchema},
					model.Evidence{Key: "package", Value: fallbackValue(enrichResult.Package, "unknown")},
					model.Evidence{Key: "version", Value: fallbackValue(enrichResult.Version, "unknown")},
					model.Evidence{Key: "advisory_count", Value: fmt.Sprintf("%d", enrichResult.AdvisoryCount)},
					model.Evidence{Key: "registry_status", Value: enrichResult.RegistryStatus},
				)
			}
			permissions := []string{"mcp.access"}
			permissions = append(permissions, actionSurfacePermissions(actionSurface)...)
			findings = append(findings, model.Finding{
				FindingType: "mcp_server",
				Severity:    severity,
				ToolType:    "mcp",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				Permissions: permissions,
				Evidence:    evidence,
				Remediation: "Pin MCP server package versions and remove credential-bearing transports where possible.",
			})
		}
	}

	model.SortFindings(findings)
	return findings, nil
}

func parseMCPDocument(root, rel string) (mcpDoc, *model.ParseError) {
	var parsed mcpDoc
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".json":
		if parseErr := detect.ParseJSONFileAllowUnknownFields(detectorID, root, rel, &parsed); parseErr != nil {
			return mcpDoc{}, parseErr
		}
	case ".toml":
		if parseErr := detect.ParseTOMLFileAllowUnknownFields(detectorID, root, rel, &parsed); parseErr != nil {
			return mcpDoc{}, parseErr
		}
	case ".yaml", ".yml":
		if parseErr := detect.ParseYAMLFileAllowUnknownFields(detectorID, root, rel, &parsed); parseErr != nil {
			return mcpDoc{}, parseErr
		}
	default:
		return mcpDoc{}, nil
	}
	return parsed, nil
}

func inferTransport(server serverDef) string {
	if strings.TrimSpace(server.Transport) != "" {
		return strings.ToLower(strings.TrimSpace(server.Transport))
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(server.URL)), "http") {
		return "http"
	}
	if strings.TrimSpace(server.Command) != "" {
		return "stdio"
	}
	return "unknown"
}

func countCredentialRefs(server serverDef) int {
	count := 0
	for _, field := range []string{server.Command, server.URL} {
		if containsCredentialRef(field) {
			count++
		}
	}
	for _, arg := range server.Args {
		if containsCredentialRef(arg) {
			count++
		}
	}
	for key, value := range server.Env {
		if containsCredentialRef(key) || containsCredentialRef(value) {
			count++
		}
	}
	return count
}

func containsCredentialRef(in string) bool {
	trimmed := strings.ToLower(strings.TrimSpace(in))
	if trimmed == "" {
		return false
	}
	return strings.Contains(trimmed, "secrets.") || strings.Contains(trimmed, "${") || strings.Contains(trimmed, "token") || strings.Contains(trimmed, "api_key")
}

func isPinned(server serverDef) bool {
	if pinRE.MatchString(server.Command) || pinRE.MatchString(server.URL) {
		return true
	}
	for _, arg := range server.Args {
		if pinRE.MatchString(arg) {
			return true
		}
	}
	return false
}

func hasLockfile(root string) bool {
	lockfiles := []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.sum", "poetry.lock", "uv.lock"}
	for _, rel := range lockfiles {
		if detect.FileExists(root, rel) {
			return true
		}
	}
	return false
}

func extractPackageVersion(server serverDef) (string, string) {
	fields := append([]string{}, server.Args...)
	fields = append(fields, server.Command, server.URL)
	fallbackPkg := ""
	fallbackVersion := ""
	for _, field := range fields {
		for _, match := range packageRE.FindAllStringSubmatch(field, -1) {
			if len(match) < 2 {
				continue
			}
			pkg := strings.TrimSpace(match[1])
			version := ""
			if len(match) > 2 {
				version = strings.TrimSpace(match[2])
			}
			if pkg == "" || strings.HasPrefix(pkg, "-") {
				continue
			}
			if fallbackPkg == "" {
				fallbackPkg = pkg
				fallbackVersion = version
			}
			if isLauncherPackage(pkg) {
				continue
			}
			return pkg, version
		}
	}
	return fallbackPkg, fallbackVersion
}

func isLauncherPackage(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "npx", "pnpm", "yarn", "bunx", "node", "python", "python3", "pipx", "uv", "uvx":
		return true
	default:
		return false
	}
}

func fallbackValue(value string, fallback string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return fallback
	}
	return trimmed
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}

func deriveDeclaredActionSurface(server serverDef) []string {
	set := map[string]struct{}{}
	addActionSurfaceTokens(set, server.Permissions)
	addActionSurfaceTokens(set, server.PrivilegeSurface)
	addActionSurfaceTokens(set, []string{server.Access, server.Mode})
	if len(set) == 0 {
		return nil
	}
	if _, ok := set["admin"]; ok {
		set["read"] = struct{}{}
		set["write"] = struct{}{}
	}
	if _, ok := set["write"]; ok {
		set["read"] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for _, item := range []string{"read", "write", "admin"} {
		if _, ok := set[item]; ok {
			out = append(out, item)
		}
	}
	return out
}

func addActionSurfaceTokens(out map[string]struct{}, values []string) {
	for _, value := range values {
		if token := normalizeActionSurfaceToken(value); token != "" {
			out[token] = struct{}{}
		}
	}
}

func normalizeActionSurfaceToken(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch {
	case normalized == "":
		return ""
	case strings.Contains(normalized, "admin"),
		strings.Contains(normalized, "root"),
		strings.Contains(normalized, "owner"),
		strings.Contains(normalized, "manage"),
		strings.Contains(normalized, "configure"):
		return "admin"
	case strings.Contains(normalized, "write"),
		strings.Contains(normalized, "edit"),
		strings.Contains(normalized, "delete"),
		strings.Contains(normalized, "shell"),
		strings.Contains(normalized, "exec"),
		strings.Contains(normalized, "run"),
		strings.Contains(normalized, "deploy"):
		return "write"
	case strings.Contains(normalized, "read"),
		strings.Contains(normalized, "list"),
		strings.Contains(normalized, "query"),
		strings.Contains(normalized, "search"),
		strings.Contains(normalized, "fetch"),
		strings.Contains(normalized, "browse"):
		return "read"
	default:
		return ""
	}
}

func actionSurfacePermissions(surface []string) []string {
	if len(surface) == 0 {
		return nil
	}
	out := make([]string, 0, len(surface))
	for _, item := range surface {
		out = append(out, "mcp."+item)
	}
	return out
}

func buildMCPTrustDepth(
	server serverDef,
	transport string,
	credentialRefs int,
	actionSurface []string,
	gateway mcpgateway.Result,
) *agginventory.TrustDepth {
	return mcpTrustDepth(server, transport, credentialRefs, actionSurface, gateway)
}

func mcpTrustDepth(
	server serverDef,
	transport string,
	credentialRefs int,
	actionSurface []string,
	gateway mcpgateway.Result,
) *agginventory.TrustDepth {
	authStrength := inferMCPAuthStrength(server, transport, credentialRefs)
	delegation := inferMCPDelegation(server)
	exposure := inferMCPExposure(server, transport)
	policyRefs := normalizeTrustValues(server.PolicyRefs)
	sanitization := normalizeTrustValues(server.Sanitization)
	gaps := make([]string, 0, 8)
	if exposure == agginventory.TrustExposurePublic {
		gaps = append(gaps, "public_exposure")
	}
	switch gateway.Coverage {
	case mcpgateway.CoverageUnprotected:
		gaps = append(gaps, "gateway_unprotected")
	case mcpgateway.CoverageUnknown:
		gaps = append(gaps, "gateway_unknown")
	}
	if delegation == agginventory.TrustDelegationAgent && len(policyRefs) == 0 {
		gaps = append(gaps, "delegation_without_policy")
	}
	if len(policyRefs) == 0 && (delegation != agginventory.TrustDelegationNone || exposure == agginventory.TrustExposurePublic || containsActionSurface(actionSurface, "write") || containsActionSurface(actionSurface, "admin")) {
		gaps = append(gaps, "policy_ref_missing")
	}
	if len(sanitization) == 0 && (exposure == agginventory.TrustExposurePublic || containsActionSurface(actionSurface, "write") || containsActionSurface(actionSurface, "admin")) {
		gaps = append(gaps, "sanitization_unspecified")
	}
	if authStrength == agginventory.TrustAuthStaticSecret || authStrength == agginventory.TrustAuthInheritedHuman {
		gaps = append(gaps, "static_secret_auth")
	}
	if containsActionSurface(actionSurface, "write") || containsActionSurface(actionSurface, "admin") {
		gaps = append(gaps, "destructive_capability")
	}
	return agginventory.NormalizeTrustDepth(&agginventory.TrustDepth{
		Surface:            agginventory.TrustSurfaceMCP,
		AuthStrength:       authStrength,
		DelegationModel:    delegation,
		Exposure:           exposure,
		PolicyRefs:         policyRefs,
		GatewayCoverage:    normalizeGatewayCoverage(gateway.Coverage),
		SanitizationClaims: sanitization,
		CapabilityExposure: normalizeTrustValues(actionSurface),
		TrustGaps:          normalizeTrustValues(gaps),
	})
}

func trustDepthEvidence(depth *agginventory.TrustDepth) []model.Evidence {
	normalized := agginventory.NormalizeTrustDepth(depth)
	if normalized == nil {
		return nil
	}
	return []model.Evidence{
		{Key: "trust_surface", Value: normalized.Surface},
		{Key: "auth_strength", Value: normalized.AuthStrength},
		{Key: "delegation_model", Value: normalized.DelegationModel},
		{Key: "exposure", Value: normalized.Exposure},
		{Key: "policy_binding", Value: normalized.PolicyBinding},
		{Key: "policy_refs", Value: strings.Join(normalized.PolicyRefs, ",")},
		{Key: "gateway_binding", Value: normalized.GatewayBinding},
		{Key: "gateway_coverage", Value: normalized.GatewayCoverage},
		{Key: "sanitization_claims", Value: strings.Join(normalized.SanitizationClaims, ",")},
		{Key: "capability_exposure", Value: strings.Join(normalized.CapabilityExposure, ",")},
		{Key: "trust_gaps", Value: strings.Join(normalized.TrustGaps, ",")},
		{Key: "trust_depth_score", Value: fmt.Sprintf("%.2f", normalized.TrustDepthScore)},
	}
}

func inferMCPAuthStrength(server serverDef, transport string, credentialRefs int) string {
	for _, raw := range []string{server.AuthStrength, server.Auth, strings.Join(keysAndValues(server.Env), ","), strings.Join(server.Args, ","), server.Command, server.URL} {
		normalized := strings.ToLower(strings.TrimSpace(raw))
		switch {
		case normalized == "" || normalized == "unknown":
		case strings.Contains(normalized, "static_secret"), strings.Contains(normalized, "static-secret"):
			return agginventory.TrustAuthStaticSecret
		case strings.Contains(normalized, "oauth"):
			return agginventory.TrustAuthOAuthDelegation
		case strings.Contains(normalized, "workload"), strings.Contains(normalized, "oidc"):
			return agginventory.TrustAuthWorkloadIdentity
		case strings.Contains(normalized, "jit"), strings.Contains(normalized, "just-in-time"):
			return agginventory.TrustAuthJIT
		case strings.Contains(normalized, "human"), strings.Contains(normalized, "user"):
			return agginventory.TrustAuthInheritedHuman
		case strings.Contains(normalized, "none"), strings.Contains(normalized, "anonymous"):
			return agginventory.TrustAuthNone
		}
	}
	if credentialRefs > 0 {
		return agginventory.TrustAuthStaticSecret
	}
	if transport == "stdio" {
		return agginventory.TrustAuthNone
	}
	return agginventory.TrustAuthUnknown
}

func inferMCPDelegation(server serverDef) string {
	for _, raw := range []string{server.Delegation, server.Mode, server.Access, strings.Join(server.Args, ","), server.Command} {
		normalized := strings.ToLower(strings.TrimSpace(raw))
		switch {
		case normalized == "":
		case strings.Contains(normalized, "delegate"), strings.Contains(normalized, "handoff"):
			return agginventory.TrustDelegationAgent
		case strings.Contains(normalized, "proxy"), strings.Contains(normalized, "router"), strings.Contains(normalized, "toolhub"):
			return agginventory.TrustDelegationToolProxy
		case strings.Contains(normalized, "none"), strings.Contains(normalized, "local"):
			return agginventory.TrustDelegationNone
		}
	}
	return agginventory.TrustDelegationNone
}

func inferMCPExposure(server serverDef, transport string) string {
	if explicit := normalizeExplicitExposure(server.Exposure); explicit != "" {
		return explicit
	}
	if transport == "stdio" {
		return agginventory.TrustExposureLocal
	}
	rawURL := strings.TrimSpace(server.URL)
	if rawURL == "" {
		return agginventory.TrustExposureUnknown
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return agginventory.TrustExposureUnknown
	}
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return agginventory.TrustExposureUnknown
	}
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return agginventory.TrustExposureLocal
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsPrivate() {
		return agginventory.TrustExposurePrivate
	}
	if strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".corp") || strings.HasSuffix(host, ".local") {
		return agginventory.TrustExposurePrivate
	}
	return agginventory.TrustExposurePublic
}

func normalizeExplicitExposure(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case agginventory.TrustExposureLocal:
		return agginventory.TrustExposureLocal
	case agginventory.TrustExposurePrivate:
		return agginventory.TrustExposurePrivate
	case agginventory.TrustExposurePublic:
		return agginventory.TrustExposurePublic
	default:
		return ""
	}
}

func normalizeGatewayCoverage(value string) string {
	switch strings.TrimSpace(value) {
	case mcpgateway.CoverageProtected:
		return agginventory.TrustCoverageProtected
	case mcpgateway.CoverageUnprotected:
		return agginventory.TrustCoverageUnprotected
	default:
		return agginventory.TrustCoverageUnknown
	}
}

func normalizeTrustValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
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

func containsActionSurface(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func keysAndValues(values map[string]string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values)*2)
	for key, value := range values {
		out = append(out, key, value)
	}
	sort.Strings(out)
	return out
}

func trustDepthRequiresHighSeverity(depth *agginventory.TrustDepth) bool {
	normalized := agginventory.NormalizeTrustDepth(depth)
	if normalized == nil {
		return false
	}
	if normalized.Exposure == agginventory.TrustExposurePublic && normalized.GatewayCoverage == agginventory.TrustCoverageUnprotected {
		return true
	}
	for _, gap := range normalized.TrustGaps {
		switch strings.TrimSpace(gap) {
		case "destructive_capability", "delegation_without_policy", "gateway_unprotected":
			return true
		}
	}
	return false
}

func trustDepthRequiresMediumSeverity(depth *agginventory.TrustDepth) bool {
	normalized := agginventory.NormalizeTrustDepth(depth)
	return normalized != nil && len(normalized.TrustGaps) > 0
}

func sortedServerNames(in map[string]serverDef) []string {
	if len(in) == 0 {
		return nil
	}
	keys := make([]string, 0, len(in))
	for key := range in {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
