package scanquality

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

const ReportVersion = "1"

type Report struct {
	ScanQualityVersion string                 `json:"scan_quality_version"`
	Mode               string                 `json:"mode"`
	Detectors          []DetectorHealth       `json:"detectors,omitempty"`
	SuppressedPaths    []SuppressedPath       `json:"suppressed_paths,omitempty"`
	ParseErrors        []ParseIssue           `json:"parse_errors,omitempty"`
	DetectorErrors     []detect.DetectorError `json:"detector_errors,omitempty"`
}

type DetectorHealth struct {
	Org                     string   `json:"org,omitempty"`
	Repo                    string   `json:"repo,omitempty"`
	Detector                string   `json:"detector"`
	Status                  string   `json:"status"`
	CoverageReasons         []string `json:"coverage_reasons,omitempty"`
	AttemptedFiles          int      `json:"attempted_files"`
	ParsedFiles             int      `json:"parsed_files"`
	PartialParses           int      `json:"partial_parses,omitempty"`
	SkippedFiles            int      `json:"skipped_files,omitempty"`
	SuppressedFiles         int      `json:"suppressed_files,omitempty"`
	ParseFailures           int      `json:"parse_failures,omitempty"`
	UnsupportedDeclarations int      `json:"unsupported_declarations,omitempty"`
	Findings                int      `json:"findings,omitempty"`
}

type SuppressedPath struct {
	Org    string `json:"org,omitempty"`
	Repo   string `json:"repo,omitempty"`
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

type ParseIssue struct {
	Org               string `json:"org,omitempty"`
	Repo              string `json:"repo,omitempty"`
	Path              string `json:"path"`
	Detector          string `json:"detector,omitempty"`
	Kind              string `json:"kind"`
	Format            string `json:"format,omitempty"`
	Message           string `json:"message,omitempty"`
	Reason            string `json:"reason,omitempty"`
	RecommendedAction string `json:"recommended_action,omitempty"`
}

type Input struct {
	Mode           string
	Scopes         []detect.Scope
	Findings       []model.Finding
	DetectorErrors []detect.DetectorError
}

func Build(input Input) Report {
	report := Report{
		ScanQualityVersion: ReportVersion,
		Mode:               normalizeMode(input.Mode),
		DetectorErrors:     cloneDetectorErrors(input.DetectorErrors),
	}
	if report.Mode != "deep" {
		report.SuppressedPaths = collectSuppressedPaths(input.Scopes)
	}
	report.ParseErrors = collectParseIssues(input.Findings)
	report.Detectors = collectDetectorHealth(input)
	return report
}

func collectSuppressedPaths(scopes []detect.Scope) []SuppressedPath {
	items := make([]SuppressedPath, 0)
	seen := map[string]struct{}{}
	for _, scope := range scopes {
		root := strings.TrimSpace(scope.Root)
		if root == "" {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			if rel == "." || rel == "" {
				return nil
			}
			if !detect.IsGeneratedPath(rel) {
				return nil
			}
			kind := "file"
			if d != nil && d.IsDir() {
				kind = "directory"
			}
			key := strings.Join([]string{scope.Org, scope.Repo, rel, kind}, "|")
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				items = append(items, SuppressedPath{
					Org:    strings.TrimSpace(scope.Org),
					Repo:   strings.TrimSpace(scope.Repo),
					Path:   rel,
					Kind:   kind,
					Reason: "generated_or_package_noise",
				})
			}
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Org != items[j].Org {
			return items[i].Org < items[j].Org
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		return items[i].Kind < items[j].Kind
	})
	return items
}

func collectParseIssues(findings []model.Finding) []ParseIssue {
	items := make([]ParseIssue, 0)
	for _, finding := range findings {
		if finding.ParseError == nil {
			continue
		}
		reason := "detector_parse_error"
		recommendedAction := "debug_only"
		if detect.IsGeneratedPath(finding.Location) || detect.IsGeneratedPath(finding.ParseError.Path) {
			reason = "generated_or_package_noise"
			recommendedAction = "suppress"
		}
		items = append(items, ParseIssue{
			Org:               strings.TrimSpace(finding.Org),
			Repo:              strings.TrimSpace(finding.Repo),
			Path:              firstNonEmpty(finding.ParseError.Path, finding.Location),
			Detector:          strings.TrimSpace(finding.ParseError.Detector),
			Kind:              strings.TrimSpace(finding.ParseError.Kind),
			Format:            strings.TrimSpace(finding.ParseError.Format),
			Message:           strings.TrimSpace(finding.ParseError.Message),
			Reason:            reason,
			RecommendedAction: recommendedAction,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Org != items[j].Org {
			return items[i].Org < items[j].Org
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		if items[i].Detector != items[j].Detector {
			return items[i].Detector < items[j].Detector
		}
		return items[i].Message < items[j].Message
	})
	return items
}

type detectorScopeKey struct {
	org      string
	repo     string
	detector string
}

type parsePathStatus struct {
	kind    string
	message string
}

type detectorPathMetrics struct {
	attemptedPaths  []string
	suppressedFiles int
	skippedFiles    int
}

type pathDecision struct {
	candidate  bool
	suppressed bool
	skipDir    bool
}

func collectDetectorHealth(input Input) []DetectorHealth {
	parseIndex := buildParsePathIndex(input.Findings)
	positiveIndex := buildPositivePathIndex(input.Findings)
	detectorErrorCounts := buildDetectorErrorIndex(input.DetectorErrors)

	out := make([]DetectorHealth, 0)
	for _, scope := range input.Scopes {
		for _, detectorID := range []string{"dependency", "mcp", "webmcp"} {
			scopeKey := detectorScopeKey{
				org:      strings.TrimSpace(scope.Org),
				repo:     strings.TrimSpace(scope.Repo),
				detector: detectorID,
			}
			metrics := collectDetectorScopeMetrics(scope, detectorID, normalizeMode(input.Mode))
			parsePaths := parseIndex[scopeKey]
			positivePaths := positiveIndex[scopeKey]
			if !shouldEmitDetectorHealth(detectorID, metrics, parsePaths, positivePaths, detectorErrorCounts[scopeKey]) {
				continue
			}
			fileSet := map[string]struct{}{}
			for _, path := range metrics.attemptedPaths {
				fileSet[path] = struct{}{}
			}
			for path := range parsePaths {
				fileSet[path] = struct{}{}
			}
			for path := range positivePaths {
				fileSet[path] = struct{}{}
			}

			item := DetectorHealth{
				Org:             scopeKey.org,
				Repo:            scopeKey.repo,
				Detector:        scopeKey.detector,
				AttemptedFiles:  len(metrics.attemptedPaths),
				SuppressedFiles: metrics.suppressedFiles,
				SkippedFiles:    metrics.skippedFiles,
			}
			reasonSet := map[string]struct{}{}
			if item.AttemptedFiles == 0 && item.SuppressedFiles == 0 && len(parsePaths) == 0 && len(positivePaths) == 0 && detectorErrorCounts[scopeKey] == 0 {
				reasonSet["no_candidate_inputs"] = struct{}{}
			}
			if item.SuppressedFiles > 0 {
				reasonSet["generated_suppression"] = struct{}{}
			}
			if detectorErrorCounts[scopeKey] > 0 {
				reasonSet["detector_error"] = struct{}{}
			}

			for path := range fileSet {
				parseStatus, hasParse := parsePaths[path]
				findingsCount := positivePaths[path]
				switch {
				case hasParse && findingsCount > 0:
					item.PartialParses++
					item.ParsedFiles++
					item.Findings += findingsCount
					reasonSet["partial_parse"] = struct{}{}
				case hasParse:
					item.ParseFailures++
					if isUnsupportedParseStatus(parseStatus) {
						item.UnsupportedDeclarations++
						reasonSet["unsupported_declaration"] = struct{}{}
					} else {
						reasonSet["parse_failures"] = struct{}{}
					}
				default:
					if containsPath(metrics.attemptedPaths, path) {
						item.ParsedFiles++
					}
					item.Findings += findingsCount
				}
				if isBlockedParseStatus(parseStatus) {
					reasonSet["blocked_path"] = struct{}{}
				}
			}

			switch {
			case detectorErrorCounts[scopeKey] > 0 || hasReason(reasonSet, "blocked_path"):
				item.Status = "blocked"
			case item.PartialParses > 0:
				item.Status = "partial"
			case item.ParseFailures > 0 || item.SuppressedFiles > 0 || item.UnsupportedDeclarations > 0 || item.SkippedFiles > 0:
				item.Status = "reduced"
			default:
				item.Status = "complete"
			}
			item.CoverageReasons = sortedReasonKeys(reasonSet)
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Org != out[j].Org {
			return out[i].Org < out[j].Org
		}
		if out[i].Repo != out[j].Repo {
			return out[i].Repo < out[j].Repo
		}
		return out[i].Detector < out[j].Detector
	})
	return out
}

func buildParsePathIndex(findings []model.Finding) map[detectorScopeKey]map[string]parsePathStatus {
	out := map[detectorScopeKey]map[string]parsePathStatus{}
	for _, finding := range findings {
		if finding.ParseError == nil {
			continue
		}
		key := detectorScopeKey{
			org:      strings.TrimSpace(finding.Org),
			repo:     strings.TrimSpace(finding.Repo),
			detector: strings.TrimSpace(finding.ParseError.Detector),
		}
		if key.detector == "" {
			key.detector = strings.TrimSpace(finding.Detector)
		}
		if key.detector == "" {
			continue
		}
		if out[key] == nil {
			out[key] = map[string]parsePathStatus{}
		}
		path := firstNonEmpty(finding.ParseError.Path, finding.Location)
		out[key][path] = parsePathStatus{
			kind:    strings.TrimSpace(finding.ParseError.Kind),
			message: strings.TrimSpace(finding.ParseError.Message),
		}
	}
	return out
}

func buildPositivePathIndex(findings []model.Finding) map[detectorScopeKey]map[string]int {
	out := map[detectorScopeKey]map[string]int{}
	for _, finding := range findings {
		if finding.ParseError != nil {
			continue
		}
		detectorID := strings.TrimSpace(finding.Detector)
		if detectorID == "" {
			continue
		}
		key := detectorScopeKey{
			org:      strings.TrimSpace(finding.Org),
			repo:     strings.TrimSpace(finding.Repo),
			detector: detectorID,
		}
		if out[key] == nil {
			out[key] = map[string]int{}
		}
		out[key][strings.TrimSpace(finding.Location)]++
	}
	return out
}

func buildDetectorErrorIndex(in []detect.DetectorError) map[detectorScopeKey]int {
	out := map[detectorScopeKey]int{}
	for _, item := range in {
		key := detectorScopeKey{
			org:      strings.TrimSpace(item.Org),
			repo:     strings.TrimSpace(item.Repo),
			detector: strings.TrimSpace(item.Detector),
		}
		out[key]++
	}
	return out
}

func collectDetectorScopeMetrics(scope detect.Scope, detectorID, mode string) detectorPathMetrics {
	switch detectorID {
	case "dependency":
		return collectDependencyScopeMetrics(scope.Root, mode)
	case "mcp":
		return collectMCPScopeMetrics(scope.Root)
	case "webmcp":
		return collectWebMCPScopeMetrics(scope.Root, mode)
	default:
		return detectorPathMetrics{}
	}
}

func collectDependencyScopeMetrics(root, mode string) detectorPathMetrics {
	return walkCandidatePaths(root, func(rel string, isDir bool) pathDecision {
		if mode != "deep" && detect.IsGeneratedPath(rel) {
			return pathDecision{candidate: true, suppressed: true, skipDir: isDir}
		}
		if !isDependencyManifestPath(rel) {
			return pathDecision{}
		}
		return pathDecision{candidate: true}
	})
}

func collectMCPScopeMetrics(root string) detectorPathMetrics {
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
	metrics := detectorPathMetrics{}
	for _, rel := range paths {
		exists, parseErr := detect.FileExistsWithinRoot("scanquality", root, rel)
		if parseErr != nil || exists {
			metrics.attemptedPaths = append(metrics.attemptedPaths, rel)
		}
	}
	return metrics
}

func collectWebMCPScopeMetrics(root, mode string) detectorPathMetrics {
	return walkCandidatePaths(root, func(rel string, isDir bool) pathDecision {
		if detect.IsGeneratedPath(rel) {
			if mode != "deep" {
				return pathDecision{candidate: true, suppressed: true, skipDir: isDir}
			}
			if isDir {
				return pathDecision{}
			}
			if isWebMCPRouteFile(rel) {
				return pathDecision{candidate: true}
			}
			if !isWebMCPCandidatePath(rel) {
				return pathDecision{}
			}
			return pathDecision{candidate: true, suppressed: true}
		}
		if !isWebMCPCandidatePath(rel) {
			return pathDecision{}
		}
		return pathDecision{candidate: true}
	})
}

func walkCandidatePaths(root string, classify func(rel string, isDir bool) pathDecision) detectorPathMetrics {
	metrics := detectorPathMetrics{}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			metrics.skippedFiles++
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if walkErr != nil {
			metrics.skippedFiles++
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d != nil && d.IsDir() {
			if rel == ".git" || strings.HasPrefix(rel, ".git/") {
				return filepath.SkipDir
			}
			decision := classify(rel, true)
			if decision.candidate && decision.suppressed {
				metrics.suppressedFiles++
			}
			if decision.skipDir {
				return filepath.SkipDir
			}
			return nil
		}
		decision := classify(rel, false)
		if !decision.candidate {
			return nil
		}
		if decision.suppressed {
			metrics.suppressedFiles++
			return nil
		}
		metrics.attemptedPaths = append(metrics.attemptedPaths, rel)
		return nil
	})
	sort.Strings(metrics.attemptedPaths)
	return metrics
}

func isWebMCPCandidatePath(rel string) bool {
	lower := strings.ToLower(strings.TrimSpace(rel))
	ext := strings.ToLower(filepath.Ext(lower))
	if isWebMCPRouteFile(lower) {
		return true
	}
	if ext == ".html" || ext == ".htm" || ext == ".js" || ext == ".mjs" || ext == ".cjs" {
		return true
	}
	switch ext {
	case ".go", ".ts", ".tsx", ".py", ".rb", ".php", ".java", ".kt", ".rs":
		return true
	default:
		return false
	}
}

func isDependencyManifestPath(rel string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(rel)))
	switch {
	case base == "go.mod", base == "package.json", base == "pyproject.toml", base == "cargo.toml":
		return true
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return true
	default:
		return false
	}
}

func isWebMCPRouteFile(rel string) bool {
	lower := strings.ToLower(strings.TrimSpace(rel))
	switch lower {
	case ".well-known/webmcp", ".well-known/webmcp.json", ".well-known/webmcp.yaml", ".well-known/webmcp.yml":
		return true
	}
	return strings.HasSuffix(lower, "/.well-known/webmcp") ||
		strings.HasSuffix(lower, "/.well-known/webmcp.json") ||
		strings.HasSuffix(lower, "/.well-known/webmcp.yaml") ||
		strings.HasSuffix(lower, "/.well-known/webmcp.yml")
}

func shouldEmitDetectorHealth(detectorID string, metrics detectorPathMetrics, parsePaths map[string]parsePathStatus, positivePaths map[string]int, detectorErrors int) bool {
	if detectorID == "mcp" || detectorID == "webmcp" {
		return true
	}
	return len(metrics.attemptedPaths) > 0 || metrics.suppressedFiles > 0 || len(parsePaths) > 0 || len(positivePaths) > 0 || detectorErrors > 0
}

func containsPath(paths []string, path string) bool {
	for _, candidate := range paths {
		if candidate == path {
			return true
		}
	}
	return false
}

func isBlockedParseStatus(status parsePathStatus) bool {
	switch strings.TrimSpace(status.kind) {
	case "permission_denied", "unsafe_path":
		return true
	default:
		return false
	}
}

func isUnsupportedParseStatus(status parsePathStatus) bool {
	if strings.TrimSpace(status.kind) == "schema_validation_error" {
		return true
	}
	return strings.Contains(strings.ToLower(strings.TrimSpace(status.message)), "unsupported")
}

func sortedReasonKeys(values map[string]struct{}) []string {
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

func hasReason(values map[string]struct{}, reason string) bool {
	_, ok := values[reason]
	return ok
}

func cloneDetectorErrors(in []detect.DetectorError) []detect.DetectorError {
	if len(in) == 0 {
		return nil
	}
	out := append([]detect.DetectorError(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Org != out[j].Org {
			return out[i].Org < out[j].Org
		}
		if out[i].Repo != out[j].Repo {
			return out[i].Repo < out[j].Repo
		}
		if out[i].Detector != out[j].Detector {
			return out[i].Detector < out[j].Detector
		}
		return out[i].Message < out[j].Message
	})
	return out
}

func normalizeMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case "quick", "deep":
		return strings.TrimSpace(mode)
	default:
		return "governance"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
