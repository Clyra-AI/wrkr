package routes

import (
	"context"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/mutableendpoint"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "routes"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

var (
	expressRoutePattern = regexp.MustCompile("(?i)(?:router|app)\\.(get|post|put|patch|delete)\\(\\s*[\"'`]([^\"'`]+)[\"'`]")
	fastAPIRoutePattern = regexp.MustCompile("(?i)@\\w+\\.(get|post|put|patch|delete)\\(\\s*[\"'`]([^\"'`]+)[\"'`]")
)

func (Detector) Detect(_ context.Context, scope detect.Scope, options detect.Options) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}
	files, err := detect.WalkFilesWithParseErrors(detectorID, scope.Root, options)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	for _, file := range files {
		if !isRouteCandidate(file.Rel) {
			continue
		}
		if file.ParseError != nil {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "route",
				Location:    file.Rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  file.ParseError,
			})
			continue
		}
		payload, parseErr := detect.ReadFileWithinRoot(detectorID, scope.Root, file.Rel)
		if parseErr != nil {
			return nil, detect.ParseErrorAsError(parseErr)
		}
		for _, route := range parseRoutes(string(payload)) {
			semantics := mutableendpoint.Classify(route.method, route.path, "", "", "route", "medium")
			if len(semantics) == 0 {
				continue
			}
			evidence := []model.Evidence{
				{Key: "endpoint_method", Value: route.method},
				{Key: "endpoint_route", Value: route.path},
			}
			for _, encoded := range mutableendpoint.EncodeEvidenceValues(semantics) {
				evidence = append(evidence, model.Evidence{Key: "mutable_endpoint_semantic", Value: encoded})
			}
			for _, hint := range mutableendpoint.TargetClassHintsForSemantics(semantics) {
				evidence = append(evidence, model.Evidence{Key: "target_class_hint", Value: hint})
			}
			findings = append(findings, model.Finding{
				FindingType: "route_endpoint",
				Severity:    mutableendpoint.SeverityForSemantics(semantics),
				ToolType:    "route",
				Location:    file.Rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				Permissions: mutableendpoint.PermissionsForSemantics(semantics),
				Evidence:    evidence,
				Remediation: "Confirm static route mutations, owners, and proof before treating these paths as buyer-ready control coverage.",
			})
		}
	}

	model.SortFindings(findings)
	return findings, nil
}

type routeDecl struct {
	method string
	path   string
}

func parseRoutes(content string) []routeDecl {
	out := []routeDecl{}
	for _, pattern := range []*regexp.Regexp{expressRoutePattern, fastAPIRoutePattern} {
		matches := pattern.FindAllStringSubmatch(content, -1)
		for _, match := range matches {
			if len(match) < 3 {
				continue
			}
			out = append(out, routeDecl{
				method: strings.ToUpper(strings.TrimSpace(match[1])),
				path:   strings.TrimSpace(match[2]),
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].path != out[j].path {
			return out[i].path < out[j].path
		}
		return out[i].method < out[j].method
	})
	return out
}

func isRouteCandidate(rel string) bool {
	lower := strings.ToLower(strings.TrimSpace(rel))
	ext := strings.ToLower(filepath.Ext(lower))
	switch ext {
	case ".js", ".jsx", ".ts", ".tsx", ".go", ".py", ".rb":
	default:
		return false
	}
	return strings.Contains(lower, "route") || strings.Contains(lower, "router") || strings.Contains(lower, "api/")
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return strings.TrimSpace(org)
}
