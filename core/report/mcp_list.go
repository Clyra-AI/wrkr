package report

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/aggregate/scanquality"
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
	Status         string              `json:"status"`
	GeneratedAt    string              `json:"generated_at"`
	RepoFilter     string              `json:"repo_filter,omitempty"`
	Rows           []MCPListRow        `json:"rows"`
	Candidates     []MCPCandidate      `json:"candidates,omitempty"`
	Diagnostics    []MCPMissDiagnostic `json:"diagnostics,omitempty"`
	Warnings       []string            `json:"warnings,omitempty"`
	AbsenceStatus  string              `json:"absence_status,omitempty"`
	AbsenceReasons []string            `json:"absence_reasons,omitempty"`
	AbsenceImpact  string              `json:"absence_impact,omitempty"`
}

type MCPListRow struct {
	ServerName           string                   `json:"server_name"`
	Org                  string                   `json:"org"`
	Repo                 string                   `json:"repo"`
	Location             string                   `json:"location"`
	Transport            string                   `json:"transport"`
	RequestedPermissions []string                 `json:"requested_permissions,omitempty"`
	PrivilegeSurface     []string                 `json:"privilege_surface,omitempty"`
	GatewayCoverage      string                   `json:"gateway_coverage"`
	TrustDepth           *agginventory.TrustDepth `json:"trust_depth,omitempty"`
	TrustStatus          string                   `json:"trust_status"`
	RiskNote             string                   `json:"risk_note"`
}

type MCPCandidate struct {
	CandidateName     string   `json:"candidate_name"`
	Org               string   `json:"org"`
	Repo              string   `json:"repo"`
	Location          string   `json:"location"`
	EvidenceType      string   `json:"evidence_type"`
	Confidence        string   `json:"confidence"`
	DeclarationType   string   `json:"declaration_type"`
	TransportHint     string   `json:"transport_hint"`
	CredentialRefs    []string `json:"credential_refs,omitempty"`
	UnsupportedReason string   `json:"unsupported_reason,omitempty"`
}

type MCPMissDiagnostic struct {
	Org                     string   `json:"org"`
	Repo                    string   `json:"repo"`
	ExpectedServer          string   `json:"expected_server,omitempty"`
	Status                  string   `json:"status"`
	AbsenceStatus           string   `json:"absence_status,omitempty"`
	CandidateFilesScanned   []string `json:"candidate_files_scanned,omitempty"`
	ParsedConfigs           []string `json:"parsed_configs,omitempty"`
	CandidatesFound         []string `json:"candidates_found,omitempty"`
	ParseFailures           []string `json:"parse_failures,omitempty"`
	GeneratedSuppressions   []string `json:"generated_suppressions,omitempty"`
	UnsupportedDeclarations []string `json:"unsupported_declarations,omitempty"`
	Explanation             []string `json:"explanation,omitempty"`
	AbsenceImpact           string   `json:"absence_impact,omitempty"`
}

type MCPListOptions struct {
	GeneratedAt         time.Time
	OverlayPath         string
	AllowAmbientOverlay bool
	RepoFilter          string
	ExpectedServers     []string
}

type mcpTrustOverlay struct {
	Servers map[string]mcpTrustEntry `yaml:"servers"`
}

type mcpTrustEntry struct {
	TrustStatus string `yaml:"trust_status"`
}

func BuildMCPList(snapshot state.Snapshot, generatedAt time.Time, overlayPath string, allowAmbientOverlay bool) MCPList {
	return BuildMCPListWithOptions(snapshot, MCPListOptions{
		GeneratedAt:         generatedAt,
		OverlayPath:         overlayPath,
		AllowAmbientOverlay: allowAmbientOverlay,
	})
}

func BuildMCPListWithOptions(snapshot state.Snapshot, opts MCPListOptions) MCPList {
	overlay, warnings := loadMCPTrustOverlay(strings.TrimSpace(opts.OverlayPath), opts.AllowAmbientOverlay)
	warnings = append(warnings, MCPVisibilityWarnings(snapshot.Findings)...)
	toolSurfaces := buildMCPToolSurfaceIndex(snapshot.Inventory)
	gatewayCoverage := buildMCPGatewayCoverageIndex(snapshot.Findings)
	repoFilter := strings.TrimSpace(opts.RepoFilter)

	rows := make([]MCPListRow, 0)
	for _, finding := range snapshot.Findings {
		if strings.TrimSpace(finding.FindingType) != "mcp_server" {
			continue
		}
		if repoFilter != "" && strings.TrimSpace(finding.Repo) != repoFilter {
			continue
		}
		evidence := evidenceMap(finding.Evidence)
		serverName := fallbackString(evidence["server"], strings.TrimSpace(finding.Location))
		rowKey := mcpRowKey(finding.Org, finding.Repo, finding.Location, serverName)
		toolKey := mcpToolKey(finding.Org, finding.Repo, finding.Location)
		privilegeSurface := declaredActionSurface(evidence["declared_action_surface"])
		if len(privilegeSurface) == 0 {
			privilegeSurface = append([]string(nil), toolSurfaces[toolKey]...)
		}
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
			TrustDepth:           agginventory.TrustDepthFromFinding(finding),
			TrustStatus:          trustStatus,
			RiskNote:             buildMCPRiskNote(finding, trustStatus, fallbackString(gatewayCoverage[rowKey], "unknown"), privilegeSurface),
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

	candidates := buildMCPCandidates(snapshot, repoFilter)
	diagnostics := buildMCPMissDiagnostics(snapshot, repoFilter, rows, candidates, opts.ExpectedServers)
	absenceStatus, absenceReasons, absenceImpact := mcpAbsenceSummary(snapshot.ScanQuality, repoFilter, rows, candidates, diagnostics)

	return MCPList{
		Status:         "ok",
		GeneratedAt:    ResolveGeneratedAtForCLI(snapshot, opts.GeneratedAt).Format(time.RFC3339),
		RepoFilter:     repoFilter,
		Rows:           rows,
		Candidates:     candidates,
		Diagnostics:    diagnostics,
		Warnings:       warnings,
		AbsenceStatus:  absenceStatus,
		AbsenceReasons: absenceReasons,
		AbsenceImpact:  absenceImpact,
	}
}

func buildMCPCandidates(snapshot state.Snapshot, repoFilter string) []MCPCandidate {
	items := make([]MCPCandidate, 0)
	for _, finding := range snapshot.Findings {
		switch strings.TrimSpace(finding.FindingType) {
		case "mcp_server_candidate":
			if repoFilter != "" && strings.TrimSpace(finding.Repo) != repoFilter {
				continue
			}
			evidence := evidenceMap(finding.Evidence)
			items = append(items, MCPCandidate{
				CandidateName:     fallbackString(evidence["candidate_name"], strings.TrimSpace(finding.Location)),
				Org:               fallbackString(strings.TrimSpace(finding.Org), "local"),
				Repo:              strings.TrimSpace(finding.Repo),
				Location:          strings.TrimSpace(finding.Location),
				EvidenceType:      fallbackString(evidence["evidence_type"], "unknown"),
				Confidence:        fallbackString(evidence["confidence"], "low"),
				DeclarationType:   fallbackString(evidence["declaration_type"], "unknown"),
				TransportHint:     fallbackString(evidence["transport_hint"], "unknown"),
				CredentialRefs:    splitMCPListCSV(evidence["credential_refs"]),
				UnsupportedReason: strings.TrimSpace(evidence["unsupported_declaration_reason"]),
			})
		case "webmcp_declaration":
			if repoFilter != "" && strings.TrimSpace(finding.Repo) != repoFilter {
				continue
			}
			evidence := evidenceMap(finding.Evidence)
			items = append(items, MCPCandidate{
				CandidateName:   fallbackString(evidence["declaration_name"], "webmcp"),
				Org:             fallbackString(strings.TrimSpace(finding.Org), "local"),
				Repo:            strings.TrimSpace(finding.Repo),
				Location:        strings.TrimSpace(finding.Location),
				EvidenceType:    "webmcp_declaration",
				Confidence:      "medium",
				DeclarationType: fallbackString(evidence["declaration_method"], "webmcp_declaration"),
				TransportHint:   "http",
			})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Org != items[j].Org {
			return items[i].Org < items[j].Org
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		if items[i].CandidateName != items[j].CandidateName {
			return items[i].CandidateName < items[j].CandidateName
		}
		return items[i].Location < items[j].Location
	})
	return items
}

func buildMCPMissDiagnostics(snapshot state.Snapshot, repoFilter string, rows []MCPListRow, candidates []MCPCandidate, expectedServers []string) []MCPMissDiagnostic {
	index := buildMCPDiagnosticIndex(snapshot, repoFilter)
	if repoFilter != "" {
		ensureDiagnosticDetail(index, inferDiagnosticOrg(snapshot, repoFilter), repoFilter)
	}
	rowNamesByRepo := map[string]map[string]struct{}{}
	for _, row := range rows {
		key := diagnosticRepoKey(row.Org, row.Repo)
		if rowNamesByRepo[key] == nil {
			rowNamesByRepo[key] = map[string]struct{}{}
		}
		rowNamesByRepo[key][strings.ToLower(strings.TrimSpace(row.ServerName))] = struct{}{}
		ensureDiagnosticDetail(index, row.Org, row.Repo).parsedConfigs = append(
			ensureDiagnosticDetail(index, row.Org, row.Repo).parsedConfigs,
			strings.TrimSpace(row.Location),
		)
	}
	candidateNamesByRepo := map[string]map[string]struct{}{}
	for _, candidate := range candidates {
		key := diagnosticRepoKey(candidate.Org, candidate.Repo)
		if candidateNamesByRepo[key] == nil {
			candidateNamesByRepo[key] = map[string]struct{}{}
		}
		candidateNamesByRepo[key][strings.ToLower(strings.TrimSpace(candidate.CandidateName))] = struct{}{}
		detail := ensureDiagnosticDetail(index, candidate.Org, candidate.Repo)
		detail.candidatesFound = append(detail.candidatesFound, strings.TrimSpace(candidate.CandidateName))
		detail.candidateFilesScanned = append(detail.candidateFilesScanned, strings.TrimSpace(candidate.Location))
		if strings.TrimSpace(candidate.UnsupportedReason) != "" {
			detail.unsupportedDeclarations = append(detail.unsupportedDeclarations, strings.TrimSpace(candidate.UnsupportedReason))
		}
	}

	diagnostics := make([]MCPMissDiagnostic, 0)
	if len(expectedServers) == 0 {
		expectedServers = inferredExpectedServers(candidates)
	}
	if len(expectedServers) == 0 {
		for key, detail := range index {
			if len(detail.candidatesFound) == 0 && len(detail.parseFailures) == 0 && len(detail.generatedSuppressions) == 0 {
				continue
			}
			org, repo := splitDiagnosticRepoKey(key)
			diagnostics = append(diagnostics, MCPMissDiagnostic{
				Org:                     org,
				Repo:                    repo,
				Status:                  deriveDiagnosticStatus(detail, false, false),
				AbsenceStatus:           diagnosticAbsenceStatus(deriveDiagnosticStatus(detail, false, false)),
				CandidateFilesScanned:   uniqueMCPListStrings(detail.candidateFilesScanned),
				ParsedConfigs:           uniqueMCPListStrings(detail.parsedConfigs),
				CandidatesFound:         uniqueMCPListStrings(detail.candidatesFound),
				ParseFailures:           uniqueMCPListStrings(detail.parseFailures),
				GeneratedSuppressions:   uniqueMCPListStrings(detail.generatedSuppressions),
				UnsupportedDeclarations: uniqueMCPListStrings(detail.unsupportedDeclarations),
				Explanation:             diagnosticExplanation(deriveDiagnosticStatus(detail, false, false)),
				AbsenceImpact:           scanqualityAbsenceImpact(diagnosticAbsenceStatus(deriveDiagnosticStatus(detail, false, false))),
			})
		}
		sortMCPDiagnostics(diagnostics)
		return diagnostics
	}

	for key, detail := range index {
		org, repo := splitDiagnosticRepoKey(key)
		for _, expected := range expectedServers {
			normalizedExpected := strings.ToLower(strings.TrimSpace(expected))
			if normalizedExpected == "" {
				continue
			}
			_, found := rowNamesByRepo[key][normalizedExpected]
			_, candidateOnly := candidateNamesByRepo[key][normalizedExpected]
			status := deriveDiagnosticStatus(detail, found, candidateOnly)
			diagnostics = append(diagnostics, MCPMissDiagnostic{
				Org:                     org,
				Repo:                    repo,
				ExpectedServer:          strings.TrimSpace(expected),
				Status:                  status,
				AbsenceStatus:           diagnosticAbsenceStatus(status),
				CandidateFilesScanned:   uniqueMCPListStrings(detail.candidateFilesScanned),
				ParsedConfigs:           uniqueMCPListStrings(detail.parsedConfigs),
				CandidatesFound:         uniqueMCPListStrings(detail.candidatesFound),
				ParseFailures:           uniqueMCPListStrings(detail.parseFailures),
				GeneratedSuppressions:   uniqueMCPListStrings(detail.generatedSuppressions),
				UnsupportedDeclarations: uniqueMCPListStrings(detail.unsupportedDeclarations),
				Explanation:             diagnosticExplanation(status),
				AbsenceImpact:           scanqualityAbsenceImpact(diagnosticAbsenceStatus(status)),
			})
		}
	}
	sortMCPDiagnostics(diagnostics)
	return diagnostics
}

type mcpDiagnosticDetail struct {
	candidateFilesScanned   []string
	parsedConfigs           []string
	candidatesFound         []string
	parseFailures           []string
	generatedSuppressions   []string
	unsupportedDeclarations []string
}

func ensureDiagnosticDetail(index map[string]*mcpDiagnosticDetail, org, repo string) *mcpDiagnosticDetail {
	key := diagnosticRepoKey(org, repo)
	if index[key] == nil {
		index[key] = &mcpDiagnosticDetail{}
	}
	return index[key]
}

func buildMCPDiagnosticIndex(snapshot state.Snapshot, repoFilter string) map[string]*mcpDiagnosticDetail {
	out := map[string]*mcpDiagnosticDetail{}

	for _, finding := range snapshot.Findings {
		if repoFilter != "" && strings.TrimSpace(finding.Repo) != repoFilter {
			continue
		}
		switch strings.TrimSpace(finding.FindingType) {
		case "mcp_server", "mcp_server_candidate", "webmcp_declaration":
			ensureDiagnosticDetail(out, finding.Org, finding.Repo).candidateFilesScanned = append(
				ensureDiagnosticDetail(out, finding.Org, finding.Repo).candidateFilesScanned,
				strings.TrimSpace(finding.Location),
			)
		case "parse_error":
			if !isMCPCoverageParseError(finding) {
				continue
			}
			ensureDiagnosticDetail(out, finding.Org, finding.Repo).parseFailures = append(
				ensureDiagnosticDetail(out, finding.Org, finding.Repo).parseFailures,
				strings.TrimSpace(finding.Location),
			)
		}
	}

	if snapshot.ScanQuality != nil {
		for _, item := range snapshot.ScanQuality.SuppressedPaths {
			if repoFilter != "" && strings.TrimSpace(item.Repo) != repoFilter {
				continue
			}
			detail := ensureDiagnosticDetail(out, item.Org, item.Repo)
			if strings.Contains(strings.ToLower(strings.TrimSpace(item.Path)), "mcp") || strings.Contains(strings.ToLower(strings.TrimSpace(item.Path)), "webmcp") {
				detail.generatedSuppressions = append(detail.generatedSuppressions, strings.TrimSpace(item.Path))
			}
		}
	}
	return out
}

func inferDiagnosticOrg(snapshot state.Snapshot, repo string) string {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return "local"
	}
	for _, finding := range snapshot.Findings {
		if strings.TrimSpace(finding.Repo) != repo {
			continue
		}
		if org := strings.TrimSpace(finding.Org); org != "" {
			return org
		}
	}
	if snapshot.Inventory != nil {
		for _, tool := range snapshot.Inventory.Tools {
			for _, location := range tool.Locations {
				if strings.TrimSpace(location.Repo) != repo {
					continue
				}
				if org := strings.TrimSpace(tool.Org); org != "" {
					return org
				}
			}
		}
	}
	if snapshot.ScanQuality != nil {
		for _, item := range snapshot.ScanQuality.SuppressedPaths {
			if strings.TrimSpace(item.Repo) != repo {
				continue
			}
			if org := strings.TrimSpace(item.Org); org != "" {
				return org
			}
		}
	}
	if cut := strings.Index(repo, "/"); cut > 0 {
		return strings.TrimSpace(repo[:cut])
	}
	return "local"
}

func isMCPCoverageParseError(finding source.Finding) bool {
	location := strings.TrimSpace(finding.Location)
	detector := strings.TrimSpace(finding.Detector)
	if isKnownMCPDeclarationPath(location) {
		return true
	}
	return strings.EqualFold(detector, "mcp") || strings.EqualFold(detector, "webmcp")
}

func inferredExpectedServers(candidates []MCPCandidate) []string {
	set := map[string]struct{}{}
	for _, candidate := range candidates {
		name := strings.TrimSpace(candidate.CandidateName)
		if name == "" {
			continue
		}
		set[name] = struct{}{}
	}
	return uniqueSortedStringsMap(set)
}

func deriveDiagnosticStatus(detail *mcpDiagnosticDetail, found bool, candidateOnly bool) string {
	switch {
	case found:
		return "found"
	case candidateOnly:
		return "candidate_only"
	case detail != nil && (len(detail.parseFailures) > 0 || len(detail.generatedSuppressions) > 0):
		return "reduced_coverage"
	default:
		return "not_detected"
	}
}

func diagnosticExplanation(status string) []string {
	switch strings.TrimSpace(status) {
	case "found":
		return []string{"authoritative MCP server evidence is present in saved state"}
	case "candidate_only":
		return []string{"Wrkr found MCP candidate evidence, but not enough fixed-config or bound source evidence to emit an authoritative server"}
	case "reduced_coverage":
		return []string{"Wrkr saw parse failures or generated suppression on MCP-bearing surfaces, so a negative result is coverage-reduced rather than authoritative"}
	default:
		return []string{"Wrkr did not find authoritative or candidate MCP evidence for the requested repo"}
	}
}

func diagnosticAbsenceStatus(status string) string {
	switch strings.TrimSpace(status) {
	case "candidate_only", "reduced_coverage":
		return scanquality.AbsenceStatusNotFoundReducedCoverage
	case "not_detected":
		return scanquality.AbsenceStatusNotFoundCompleteCoverage
	default:
		return ""
	}
}

func mcpAbsenceSummary(report *scanquality.Report, repoFilter string, rows []MCPListRow, candidates []MCPCandidate, diagnostics []MCPMissDiagnostic) (string, []string, string) {
	if len(rows) > 0 {
		return "", nil, ""
	}
	if claim := mcpAbsenceClaim(report, repoFilter); claim != nil {
		return claim.Status, append([]string(nil), claim.Reasons...), strings.TrimSpace(claim.Impact)
	}

	reasons := []string{"scan_quality:unavailable"}
	if len(candidates) > 0 {
		reasons = append(reasons, "candidate_evidence:present")
		return scanquality.AbsenceStatusNotFoundReducedCoverage, uniqueMCPListStrings(reasons), scanqualityAbsenceImpact(scanquality.AbsenceStatusNotFoundReducedCoverage)
	}
	for _, diagnostic := range diagnostics {
		if strings.TrimSpace(diagnostic.AbsenceStatus) == "" {
			continue
		}
		reasons = append(reasons, diagnostic.Status)
		return strings.TrimSpace(diagnostic.AbsenceStatus), uniqueMCPListStrings(reasons), scanqualityAbsenceImpact(strings.TrimSpace(diagnostic.AbsenceStatus))
	}
	return scanquality.AbsenceStatusNotScanned, uniqueMCPListStrings(reasons), scanqualityAbsenceImpact(scanquality.AbsenceStatusNotScanned)
}

func mcpAbsenceClaim(report *scanquality.Report, repoFilter string) *scanquality.AbsenceClaim {
	if report == nil {
		return nil
	}
	if strings.TrimSpace(repoFilter) != "" {
		org := inferDiagnosticOrg(state.Snapshot{ScanQuality: report}, repoFilter)
		if claim := scanquality.AbsenceClaimForSurface(report, org, repoFilter, scanquality.SurfaceMCPServer); claim != nil {
			return claim
		}
		if claim := scanquality.AbsenceClaimForSurface(report, "", repoFilter, scanquality.SurfaceMCPServer); claim != nil {
			return claim
		}
	}
	for _, claim := range report.AbsenceClaims {
		if strings.TrimSpace(claim.Surface) != scanquality.SurfaceMCPServer {
			continue
		}
		copyClaim := claim
		copyClaim.Reasons = append([]string(nil), claim.Reasons...)
		return &copyClaim
	}
	return nil
}

func scanqualityAbsenceImpact(status string) string {
	switch strings.TrimSpace(status) {
	case scanquality.AbsenceStatusNotFoundCompleteCoverage:
		return "Complete MCP coverage supported a clean negative result for the scanned surfaces."
	case scanquality.AbsenceStatusCandidateParseFailed:
		return "At least one MCP candidate surface failed to parse, so absence is not authoritative."
	case scanquality.AbsenceStatusUnsupportedSurface:
		return "Only unsupported MCP-style surfaces were seen, so absence is not authoritative."
	case scanquality.AbsenceStatusNotFoundReducedCoverage:
		return "Coverage was reduced or only candidate MCP evidence was present, so absence is not authoritative."
	case scanquality.AbsenceStatusNotScanned:
		return "MCP coverage was not scanned for this repo, so absence is not authoritative."
	default:
		return ""
	}
}

func diagnosticRepoKey(org, repo string) string {
	return fallbackString(strings.TrimSpace(org), "local") + "|" + strings.TrimSpace(repo)
}

func splitDiagnosticRepoKey(key string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(key), "|", 2)
	if len(parts) != 2 {
		return "local", strings.TrimSpace(key)
	}
	return parts[0], parts[1]
}

func sortMCPDiagnostics(items []MCPMissDiagnostic) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Org != items[j].Org {
			return items[i].Org < items[j].Org
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		if items[i].ExpectedServer != items[j].ExpectedServer {
			return items[i].ExpectedServer < items[j].ExpectedServer
		}
		return items[i].Status < items[j].Status
	})
}

func splitMCPListCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return uniqueMCPListStrings(strings.Split(value, ","))
}

func uniqueMCPListStrings(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	return uniqueSortedStringsMap(set)
}

func uniqueSortedStringsMap(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
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

func buildMCPRiskNote(finding model.Finding, trustStatus, gatewayCoverage string, privilegeSurface []string) string {
	if trustDepth := agginventory.TrustDepthFromFinding(finding); trustDepth != nil {
		if trustDepth.Exposure == agginventory.TrustExposurePublic && trustDepth.GatewayCoverage == agginventory.TrustCoverageUnprotected {
			return "Public MCP exposure is not gateway protected; prioritize policy binding, sanitization, and least-privilege review."
		}
		for _, gap := range trustDepth.TrustGaps {
			switch strings.TrimSpace(gap) {
			case "delegation_without_policy":
				return "Delegating MCP surface is missing declared policy binding."
			case "policy_ref_missing":
				return "MCP trust posture is missing policy references for operator review."
			case "sanitization_unspecified":
				return "MCP surface does not declare sanitization claims; validate prompt and tool input controls."
			}
		}
	}
	surfaceLabel := ""
	switch {
	case containsString(privilegeSurface, "admin"):
		surfaceLabel = "admin-capable"
	case containsString(privilegeSurface, "write"):
		surfaceLabel = "write-capable"
	case containsString(privilegeSurface, "read"):
		surfaceLabel = "read-capable"
	}
	switch trustStatus {
	case MCPTrustBlocked:
		return "Gait trust overlay marks this server blocked."
	case MCPTrustUnavailable:
		if gatewayCoverage == "unprotected" {
			if surfaceLabel != "" {
				return "No local Gait trust overlay; gateway posture is unprotected for a " + surfaceLabel + " MCP surface."
			}
			return "No local Gait trust overlay; gateway posture is unprotected."
		}
		return "No local Gait trust overlay; static discovery only."
	}

	switch gatewayCoverage {
	case "unprotected":
		if surfaceLabel != "" {
			return "Gateway posture is unprotected for a " + surfaceLabel + " MCP surface."
		}
		return "Gateway posture is unprotected; review least-privilege controls."
	case "unknown":
		if surfaceLabel != "" {
			return "Gateway posture is unknown; verify transport and " + surfaceLabel + " access scope."
		}
		return "Gateway posture is unknown; verify transport and access scope."
	}

	switch surfaceLabel {
	case "admin-capable":
		return "Static MCP declaration advertises an admin-capable surface; verify package pinning and trust."
	case "write-capable":
		return "Static MCP declaration advertises a write-capable surface; verify least-privilege controls."
	case "read-capable":
		return "Static MCP declaration advertises a read-capable surface; verify package pinning and trust."
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

func declaredActionSurface(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	items := strings.Split(strings.TrimSpace(raw), ",")
	out := make([]string, 0, len(items))
	for _, item := range items {
		switch trimmed := strings.TrimSpace(item); trimmed {
		case "read", "write", "admin":
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == strings.TrimSpace(target) {
			return true
		}
	}
	return false
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
