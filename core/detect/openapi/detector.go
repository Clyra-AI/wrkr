package openapi

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/mutableendpoint"
	"github.com/Clyra-AI/wrkr/core/model"
)

const detectorID = "openapi"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

type document struct {
	OpenAPI string                          `json:"openapi" yaml:"openapi"`
	Swagger string                          `json:"swagger" yaml:"swagger"`
	Paths   map[string]map[string]operation `json:"paths" yaml:"paths"`
}

type operation struct {
	Summary     string `json:"summary" yaml:"summary"`
	OperationID string `json:"operationId" yaml:"operationId"`
}

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
		if !isOpenAPICandidate(file.Rel) {
			continue
		}
		if file.ParseError != nil {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "openapi",
				Location:    file.Rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  file.ParseError,
			})
			continue
		}

		doc, parseErr := parseDocument(scope.Root, file.Rel)
		if parseErr != nil {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "openapi",
				Location:    file.Rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  parseErr,
			})
			continue
		}
		for _, item := range operations(doc.Paths) {
			semantics := mutableendpoint.Classify(item.method, item.route, item.summary, item.operationID, "openapi", "high")
			if len(semantics) == 0 {
				continue
			}
			evidence := []model.Evidence{
				{Key: "endpoint_method", Value: item.method},
				{Key: "endpoint_route", Value: item.route},
			}
			if strings.TrimSpace(item.summary) != "" {
				evidence = append(evidence, model.Evidence{Key: "endpoint_summary", Value: strings.TrimSpace(item.summary)})
			}
			if strings.TrimSpace(item.operationID) != "" {
				evidence = append(evidence, model.Evidence{Key: "operation_id", Value: strings.TrimSpace(item.operationID)})
			}
			for _, encoded := range mutableendpoint.EncodeEvidenceValues(semantics) {
				evidence = append(evidence, model.Evidence{Key: "mutable_endpoint_semantic", Value: encoded})
			}
			for _, hint := range mutableendpoint.TargetClassHintsForSemantics(semantics) {
				evidence = append(evidence, model.Evidence{Key: "target_class_hint", Value: hint})
			}
			findings = append(findings, model.Finding{
				FindingType: "openapi_endpoint",
				Severity:    mutableendpoint.SeverityForSemantics(semantics),
				ToolType:    "openapi",
				Location:    file.Rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				Permissions: mutableendpoint.PermissionsForSemantics(semantics),
				Evidence:    evidence,
				Remediation: "Review declared OpenAPI mutations, confirm owners and proof, and keep endpoint classification static-only.",
			})
		}
	}

	model.SortFindings(findings)
	return findings, nil
}

type pathOperation struct {
	method      string
	route       string
	summary     string
	operationID string
}

func operations(paths map[string]map[string]operation) []pathOperation {
	if len(paths) == 0 {
		return nil
	}
	out := []pathOperation{}
	for route, methods := range paths {
		for method, operation := range methods {
			upperMethod := strings.ToUpper(strings.TrimSpace(method))
			switch upperMethod {
			case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
				out = append(out, pathOperation{
					method:      upperMethod,
					route:       strings.TrimSpace(route),
					summary:     strings.TrimSpace(operation.Summary),
					operationID: strings.TrimSpace(operation.OperationID),
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].route != out[j].route {
			return out[i].route < out[j].route
		}
		return out[i].method < out[j].method
	})
	return out
}

func parseDocument(root, rel string) (document, *model.ParseError) {
	var doc document
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".json":
		if parseErr := detect.ParseJSONFileAllowUnknownFields(detectorID, root, rel, &doc); parseErr != nil {
			return document{}, parseErr
		}
	default:
		if parseErr := detect.ParseYAMLFileAllowUnknownFields(detectorID, root, rel, &doc); parseErr != nil {
			return document{}, parseErr
		}
	}
	return doc, nil
}

func isOpenAPICandidate(rel string) bool {
	lower := strings.ToLower(strings.TrimSpace(rel))
	ext := strings.ToLower(filepath.Ext(lower))
	switch ext {
	case ".yaml", ".yml", ".json":
	default:
		return false
	}
	base := filepath.Base(lower)
	return strings.Contains(base, "openapi") || strings.Contains(base, "swagger")
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return strings.TrimSpace(org)
}
