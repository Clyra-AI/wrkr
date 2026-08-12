package openapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/mutableendpoint"
	"github.com/Clyra-AI/wrkr/core/executiontopology"
	"github.com/Clyra-AI/wrkr/core/model"
	"gopkg.in/yaml.v3"
)

const detectorID = "openapi"

type Detector struct {
	mu       sync.Mutex
	coverage map[string]detect.SurfaceCoverage
}

func New() *Detector { return &Detector{coverage: map[string]detect.SurfaceCoverage{}} }

func (*Detector) ID() string { return detectorID }

func (d *Detector) SurfaceCoverage(scope detect.Scope, _ detect.Options) []detect.SurfaceCoverage {
	d.mu.Lock()
	defer d.mu.Unlock()
	receipt, ok := d.coverage[scope.Root]
	if !ok {
		return nil
	}
	receipt.ReasonCodes = append([]string(nil), receipt.ReasonCodes...)
	return []detect.SurfaceCoverage{receipt}
}

type document struct {
	OpenAPI string                          `json:"openapi" yaml:"openapi"`
	Swagger string                          `json:"swagger" yaml:"swagger"`
	Paths   map[string]map[string]operation `json:"paths" yaml:"paths"`
}

type operation struct {
	Summary     string `json:"summary" yaml:"summary"`
	OperationID string `json:"operationId" yaml:"operationId"`
}

func (d *Detector) Detect(_ context.Context, scope detect.Scope, options detect.Options) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}
	files, err := detect.WalkFilesWithParseErrors(detectorID, scope.Root, options)
	if err != nil {
		return nil, err
	}
	generated, discovery := discoverGeneratedSpecs(scope.Root, files)
	files = append(files, generated...)
	sort.Slice(files, func(i, j int) bool { return files[i].Rel < files[j].Rel })

	findings := make([]model.Finding, 0)
	receipt := detect.SurfaceCoverage{Surface: "api_specification", Org: scope.Org, Repo: scope.Repo, Detector: detectorID, ParserVersion: "2", Suppressed: discovery.suppressed, Partial: discovery.partial}
	receipt.ReasonCodes = append(receipt.ReasonCodes, discovery.reasons...)
	if discovery.suppressed > 0 {
		receipt.ReasonCodes = append(receipt.ReasonCodes, "generated_spec_selection_limit")
	}
	for _, file := range files {
		candidate, candidateErr := isOpenAPICandidate(scope.Root, file.Rel)
		if candidateErr != nil {
			findings = append(findings, parseErrorFinding(scope, file.Rel, candidateErr))
			continue
		}
		if !candidate {
			continue
		}
		receipt.Discovered++
		receipt.Selected++
		receipt.Attempted++
		if file.ParseError != nil {
			receipt.Partial++
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
			receipt.Partial++
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
		if !supportedVersion(doc) {
			receipt.Unsupported++
			findings = append(findings, model.Finding{
				FindingType: "openapi_specification",
				Severity:    model.SeverityInfo,
				ToolType:    "openapi",
				Location:    file.Rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				Evidence: []model.Evidence{
					{Key: "spec_role", Value: "specification"},
					{Key: "spec_resolution_state", Value: "unsupported_version"},
				},
				Remediation: "Validate the OpenAPI or Swagger version before using this specification as execution context.",
			})
			continue
		}
		receipt.Parsed++
		refReceipt := resolveSpecRefs(scope.Root, file.Rel)
		receipt.Resolved += refReceipt.resolved
		receipt.Unresolved += refReceipt.unresolved
		if refReceipt.partial {
			receipt.Partial++
		}
		receipt.ReasonCodes = append(receipt.ReasonCodes, refReceipt.reasons...)
		generatorRefs, generatorTruncated := findLocalGenerators(scope.Root, file.Rel, files)
		consumerRefs, consumerTruncated := findLocalConsumers(scope.Root, file.Rel, files)
		lineageStates := []string{}
		if generatorTruncated {
			receipt.Partial++
			receipt.Suppressed++
			receipt.Unresolved++
			receipt.ReasonCodes = append(receipt.ReasonCodes, "spec_generator:fanout_limited")
			lineageStates = append(lineageStates, "generator_fanout_limited:64")
		}
		if consumerTruncated {
			receipt.Partial++
			receipt.Suppressed++
			receipt.Unresolved++
			receipt.ReasonCodes = append(receipt.ReasonCodes, "spec_consumer:fanout_limited")
			lineageStates = append(lineageStates, "consumer_fanout_limited:64")
		}
		runtimeRelation := declaredRuntimeRelation(options.ExecutionTopology, file.Rel)
		executionRelationships := specExecutionRelationships(file.Rel, generatorRefs, consumerRefs, runtimeRelation)
		if len(generatorRefs) > 0 {
			receipt.Resolved += len(generatorRefs)
		}
		if len(consumerRefs) > 0 {
			receipt.Resolved += len(consumerRefs)
		} else {
			receipt.Unresolved++
		}
		if runtimeRelation != "" {
			receipt.Resolved++
		}
		findings = append(findings, specificationFinding(scope, file.Rel, doc, generatorRefs, consumerRefs, refReceipt, lineageStates, runtimeRelation, executionRelationships))
		for _, item := range operations(doc.Paths) {
			semantics := mutableendpoint.Classify(item.method, item.route, item.summary, item.operationID, "openapi", "high")
			if len(semantics) == 0 {
				continue
			}
			evidence := []model.Evidence{
				{Key: "spec_role", Value: "specification"},
				{Key: "spec_resolution_state", Value: "resolved_local"},
				{Key: "endpoint_method", Value: item.method},
				{Key: "endpoint_route", Value: item.route},
			}
			for _, ref := range consumerRefs {
				evidence = append(evidence, model.Evidence{Key: "spec_consumer_ref", Value: ref})
			}
			for _, ref := range generatorRefs {
				evidence = append(evidence, model.Evidence{Key: "spec_generator_ref", Value: ref})
			}
			for _, state := range refReceipt.states {
				evidence = append(evidence, model.Evidence{Key: "spec_ref_state", Value: state})
			}
			for _, state := range lineageStates {
				evidence = append(evidence, model.Evidence{Key: "spec_lineage_state", Value: state})
			}
			if runtimeRelation != "" {
				evidence = append(evidence, model.Evidence{Key: "spec_runtime_relationship", Value: runtimeRelation})
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
				FindingType:            "openapi_endpoint",
				Severity:               mutableendpoint.SeverityForSemantics(semantics),
				ToolType:               "openapi",
				Location:               file.Rel,
				Repo:                   scope.Repo,
				Org:                    fallbackOrg(scope.Org),
				Detector:               detectorID,
				Permissions:            mutableendpoint.PermissionsForSemantics(semantics),
				Evidence:               evidence,
				ExecutionRelationships: model.NormalizeExecutionRelationships(executionRelationships),
				Remediation:            "Review declared OpenAPI mutations, confirm owners and proof, and keep endpoint classification static-only.",
			})
		}
	}

	model.SortFindings(findings)
	receipt.Findings = len(findings)
	receipt.ReasonCodes = dedupeSorted(receipt.ReasonCodes)
	d.mu.Lock()
	if d.coverage == nil {
		d.coverage = map[string]detect.SurfaceCoverage{}
	}
	d.coverage[scope.Root] = receipt
	d.mu.Unlock()
	return findings, nil
}

func parseErrorFinding(scope detect.Scope, rel string, parseErr *model.ParseError) model.Finding {
	return model.Finding{FindingType: "parse_error", Severity: model.SeverityMedium, ToolType: "openapi", Location: rel, Repo: scope.Repo, Org: fallbackOrg(scope.Org), Detector: detectorID, ParseError: parseErr}
}

func specificationFinding(scope detect.Scope, rel string, doc document, generators, consumers []string, refs specRefReceipt, lineageStates []string, runtimeRelation string, relationships []model.ExecutionRelationship) model.Finding {
	evidence := []model.Evidence{
		{Key: "spec_role", Value: "specification"},
		{Key: "spec_resolution_state", Value: "resolved_local"},
		{Key: "spec_operation_count", Value: strconv.Itoa(len(operations(doc.Paths)))},
	}
	if detect.IsGeneratedPath(rel) {
		evidence = append(evidence, model.Evidence{Key: "spec_origin", Value: "generated_selected"})
	}
	for _, consumer := range consumers {
		evidence = append(evidence, model.Evidence{Key: "spec_consumer_ref", Value: consumer})
	}
	for _, generator := range generators {
		evidence = append(evidence, model.Evidence{Key: "spec_generator_ref", Value: generator})
	}
	for _, state := range refs.states {
		evidence = append(evidence, model.Evidence{Key: "spec_ref_state", Value: state})
	}
	for _, state := range lineageStates {
		evidence = append(evidence, model.Evidence{Key: "spec_lineage_state", Value: state})
	}
	if runtimeRelation != "" {
		evidence = append(evidence, model.Evidence{Key: "spec_runtime_relationship", Value: runtimeRelation})
	}
	return model.Finding{FindingType: "openapi_specification", Severity: model.SeverityInfo, ToolType: "openapi", Location: rel, Repo: scope.Repo, Org: fallbackOrg(scope.Org), Detector: detectorID, Evidence: evidence, ExecutionRelationships: model.NormalizeExecutionRelationships(relationships), Remediation: "Correlate this static API specification with an observed local consumer or imported runtime evidence before treating operations as executable."}
}

func specExecutionRelationships(specRel string, generators, consumers []string, runtimeRelation string) []model.ExecutionRelationship {
	relationships := make([]model.ExecutionRelationship, 0, len(generators)+len(consumers)+1)
	for _, generator := range generators {
		relationships = append(relationships, newSpecRelationship("api_spec_generator", generator, specRel, "source_declared", "resolved_local", "high", []string{"spec_generator_ref:" + generator}))
	}
	for _, consumer := range consumers {
		relationships = append(relationships, newSpecRelationship("api_spec_consumer", specRel, consumer, "source_declared", "resolved_local", "high", []string{"spec_consumer_ref:" + consumer}))
	}
	if runtimeRelation != "" {
		parts := strings.Split(runtimeRelation, "|")
		if len(parts) >= 2 {
			relationships = append(relationships, newSpecRelationship("api_runtime", specRel, parts[1], "customer_topology", parts[0], "medium", []string{"spec_runtime_relationship:" + runtimeRelation}))
		}
	}
	return model.NormalizeExecutionRelationships(relationships)
}

func newSpecRelationship(kind, caller, callee, origin, state, confidence string, evidenceRefs []string) model.ExecutionRelationship {
	digest := sha256.Sum256([]byte(strings.Join([]string{kind, caller, callee, state}, "\x00")))
	return model.ExecutionRelationship{RelationshipID: "xrel-" + hex.EncodeToString(digest[:8]), Kind: kind, Caller: caller, Callee: callee, Origin: origin, ResolutionState: state, Confidence: confidence, EvidenceRefs: evidenceRefs}
}

func declaredRuntimeRelation(raw any, rel string) string {
	topology, ok := raw.(*executiontopology.Topology)
	if !ok || topology == nil {
		return ""
	}
	for _, alias := range []string{strings.TrimSpace(rel), filepath.Base(strings.TrimSpace(rel))} {
		if mapping, found := topology.Resolve("api_runtime", alias); found {
			return "resolved_declared|" + mapping.SourceRepo + ":" + mapping.SourcePath + "|topology:" + topology.Digest
		}
	}
	return ""
}

const (
	maxGeneratedSpecCandidates   = 64
	maxGeneratedDiscoveryEntries = 4096
	maxSpecRefDepth              = 8
	maxSpecRefFiles              = 64
	maxSpecLineageFanout         = 64
)

type specRefReceipt struct {
	resolved   int
	unresolved int
	partial    bool
	filesRead  int
	states     []string
	reasons    []string
}

type generatedDiscoveryReceipt struct {
	suppressed int
	partial    int
	reasons    []string
}

func discoverGeneratedSpecs(root string, existing []detect.WalkedFile) ([]detect.WalkedFile, generatedDiscoveryReceipt) {
	seen := map[string]struct{}{}
	for _, file := range existing {
		seen[file.Rel] = struct{}{}
	}
	selected := []detect.WalkedFile{}
	receipt := generatedDiscoveryReceipt{}
	visitedEntries := 0
	walkResult := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			receipt.partial++
			receipt.reasons = append(receipt.reasons, "generated_spec_discovery:walk_error")
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry == nil {
			receipt.partial++
			receipt.reasons = append(receipt.reasons, "generated_spec_discovery:missing_entry")
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			receipt.partial++
			receipt.reasons = append(receipt.reasons, "generated_spec_discovery:relative_path_error")
			return nil
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			if isGeneratedDependencyTree(rel) {
				return fs.SkipDir
			}
			visitedEntries++
			if visitedEntries > maxGeneratedDiscoveryEntries {
				receipt.suppressed++
				return fs.SkipAll
			}
			return nil
		}
		visitedEntries++
		if visitedEntries > maxGeneratedDiscoveryEntries {
			receipt.suppressed++
			return fs.SkipAll
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !detect.IsGeneratedPath(rel) {
			return nil
		}
		if !isOwnedGeneratedSpecPath(rel) {
			return nil
		}
		if _, ok := seen[rel]; ok {
			return nil
		}
		candidate, candidateErr := isOpenAPICandidate(root, rel)
		if candidateErr != nil {
			receipt.partial++
			receipt.reasons = append(receipt.reasons, "generated_spec_discovery:candidate_read_error")
			return nil
		}
		if !candidate {
			return nil
		}
		if len(selected) >= maxGeneratedSpecCandidates {
			receipt.suppressed++
			return nil
		}
		seen[rel] = struct{}{}
		selected = append(selected, detect.WalkedFile{Rel: rel})
		return nil
	})
	if walkResult != nil {
		receipt.partial++
		receipt.reasons = append(receipt.reasons, "generated_spec_discovery:walk_error")
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Rel < selected[j].Rel })
	receipt.reasons = dedupeSorted(receipt.reasons)
	return selected, receipt
}

func isGeneratedDependencyTree(rel string) bool {
	normalized := strings.ToLower(filepath.ToSlash(strings.TrimSpace(rel)))
	for _, segment := range strings.Split(normalized, "/") {
		switch segment {
		case ".git", "node_modules", "vendor", ".venv", ".pnpm", ".pnpm-store", ".yarn", ".docusaurus", ".next", ".nuxt", ".cache":
			return true
		}
	}
	return false
}

func isOwnedGeneratedSpecPath(rel string) bool {
	if isGeneratedDependencyTree(rel) {
		return false
	}
	normalized := strings.ToLower(filepath.ToSlash(strings.TrimSpace(rel)))
	for _, segment := range strings.Split(normalized, "/") {
		switch segment {
		case "build", "dist", "generated", "generated-sdk", "generated-sdks", "target":
			return true
		}
	}
	return false
}

func resolveSpecRefs(root, rel string) specRefReceipt {
	receipt := specRefReceipt{}
	traversal := &specRefTraversal{stack: map[string]bool{}, seen: map[string]bool{}, documents: map[string]any{}}
	resolveSpecRefFile(root, rel, rel, 0, traversal, &receipt)
	receipt.states = dedupeSorted(receipt.states)
	receipt.reasons = dedupeSorted(receipt.reasons)
	return receipt
}

type specRefTraversal struct {
	stack     map[string]bool
	seen      map[string]bool
	documents map[string]any
}

func resolveSpecRefFile(root, sourceRel, currentRel string, depth int, traversal *specRefTraversal, receipt *specRefReceipt) bool {
	if depth > maxSpecRefDepth {
		receipt.unresolved++
		receipt.partial = true
		receipt.states = append(receipt.states, "depth_limited:"+currentRel)
		receipt.reasons = append(receipt.reasons, "spec_ref:depth_limited")
		return false
	}
	if traversal.stack[currentRel] {
		receipt.unresolved++
		receipt.partial = true
		receipt.states = append(receipt.states, "cycle_blocked:"+currentRel)
		receipt.reasons = append(receipt.reasons, "spec_ref:cycle_blocked")
		return false
	}
	if resolved, seen := traversal.seen[currentRel]; seen {
		return resolved
	}
	if len(traversal.seen) >= maxSpecRefFiles {
		receipt.unresolved++
		receipt.partial = true
		receipt.states = append(receipt.states, "fanout_limited:"+currentRel)
		receipt.reasons = append(receipt.reasons, "spec_ref:fanout_limited")
		return false
	}
	traversal.seen[currentRel] = false
	traversal.stack[currentRel] = true
	receipt.filesRead++
	defer delete(traversal.stack, currentRel)
	payload, parseErr := detect.ReadFileWithinRoot(detectorID, root, currentRel)
	if parseErr != nil || len(payload) > 1<<20 {
		receipt.unresolved++
		receipt.partial = true
		receipt.states = append(receipt.states, "unresolved_local:"+currentRel)
		receipt.reasons = append(receipt.reasons, "spec_ref:unreadable_local")
		return false
	}
	document, refs, parseReasons := parseDocumentRefs(payload, filepath.Ext(currentRel))
	if document == nil {
		receipt.unresolved++
		receipt.partial = true
		receipt.states = append(receipt.states, "unresolved_local:"+currentRel)
		receipt.reasons = append(receipt.reasons, "spec_ref:unreadable_local")
		return false
	}
	for _, reason := range parseReasons {
		receipt.unresolved++
		receipt.partial = true
		receipt.states = append(receipt.states, "reference_truncated:"+currentRel)
		receipt.reasons = append(receipt.reasons, reason)
	}
	traversal.documents[currentRel] = document
	for _, ref := range refs {
		if strings.HasPrefix(ref, "#") {
			if documentFragmentExists(document, strings.TrimPrefix(ref, "#")) {
				receipt.resolved++
				receipt.states = append(receipt.states, "resolved_fragment:"+ref)
			} else {
				receipt.unresolved++
				receipt.partial = true
				receipt.states = append(receipt.states, "unresolved_fragment:"+ref)
				receipt.reasons = append(receipt.reasons, "spec_ref:missing_fragment")
			}
			continue
		}
		parsed, err := url.Parse(ref)
		if err != nil || parsed.IsAbs() || parsed.Host != "" || strings.HasPrefix(ref, "//") {
			receipt.unresolved++
			receipt.states = append(receipt.states, remoteReferenceReceipt(ref))
			receipt.reasons = append(receipt.reasons, "spec_ref:remote_not_fetched")
			continue
		}
		pathPart := strings.SplitN(ref, "#", 2)[0]
		if strings.TrimSpace(pathPart) == "" {
			receipt.resolved++
			continue
		}
		target := filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(currentRel), filepath.FromSlash(pathPart))))
		if target == ".." || strings.HasPrefix(target, "../") || filepath.IsAbs(target) {
			receipt.unresolved++
			receipt.partial = true
			receipt.states = append(receipt.states, "unsafe_path_blocked:"+ref)
			receipt.reasons = append(receipt.reasons, "spec_ref:unsafe_path_blocked")
			continue
		}
		if resolveSpecRefFile(root, sourceRel, target, depth+1, traversal, receipt) {
			if parsed.Fragment != "" && !documentFragmentExists(traversal.documents[target], parsed.Fragment) {
				receipt.unresolved++
				receipt.partial = true
				receipt.states = append(receipt.states, "unresolved_fragment:"+target+"#"+parsed.Fragment)
				receipt.reasons = append(receipt.reasons, "spec_ref:missing_fragment")
				continue
			}
			receipt.resolved++
			receipt.states = append(receipt.states, "resolved_local:"+sourceRel+"->"+target)
		}
	}
	traversal.seen[currentRel] = true
	return true
}

func remoteReferenceReceipt(ref string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(ref)))
	return "unresolved_remote:sha256:" + hex.EncodeToString(digest[:8])
}

func parseDocumentRefs(payload []byte, ext string) (any, []string, []string) {
	var root any
	if strings.EqualFold(ext, ".json") {
		if err := json.Unmarshal(payload, &root); err != nil {
			return nil, nil, nil
		}
	} else if err := yaml.Unmarshal(payload, &root); err != nil {
		return nil, nil, nil
	}
	refs := []string{}
	reasons := []string{}
	var walk func(any, int)
	walk = func(value any, depth int) {
		if depth > 64 {
			reasons = append(reasons, "spec_ref:document_depth_limited")
			return
		}
		if len(refs) >= 4096 {
			reasons = append(reasons, "spec_ref:reference_limit")
			return
		}
		switch typed := value.(type) {
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for key := range typed {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				child := typed[key]
				if key == "$ref" {
					if ref, ok := child.(string); ok && strings.TrimSpace(ref) != "" {
						if len(refs) >= 4096 {
							reasons = append(reasons, "spec_ref:reference_limit")
						} else {
							refs = append(refs, strings.TrimSpace(ref))
						}
					}
					continue
				}
				walk(child, depth+1)
			}
		case []any:
			for _, child := range typed {
				walk(child, depth+1)
			}
		}
	}
	walk(root, 0)
	return root, dedupeSorted(refs), dedupeSorted(reasons)
}

func documentFragmentExists(document any, fragment string) bool {
	fragment = strings.TrimSpace(fragment)
	if fragment == "" {
		return document != nil
	}
	decoded, err := url.PathUnescape(fragment)
	if err != nil || !strings.HasPrefix(decoded, "/") {
		return false
	}
	current := document
	for _, token := range strings.Split(strings.TrimPrefix(decoded, "/"), "/") {
		token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
		switch value := current.(type) {
		case map[string]any:
			child, ok := value[token]
			if !ok {
				return false
			}
			current = child
		case []any:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(value) {
				return false
			}
			current = value[index]
		default:
			return false
		}
	}
	return true
}

func dedupeSorted(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			set[strings.TrimSpace(value)] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
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

func isOpenAPICandidate(root, rel string) (bool, *model.ParseError) {
	lower := strings.ToLower(strings.TrimSpace(rel))
	ext := strings.ToLower(filepath.Ext(lower))
	switch ext {
	case ".yaml", ".yml", ".json":
	default:
		return false, nil
	}
	base := filepath.Base(lower)
	if strings.Contains(base, "openapi") || strings.Contains(base, "swagger") {
		return true, nil
	}
	size, parseErr := detect.FileSizeWithinRoot(detectorID, root, rel)
	if parseErr != nil {
		return false, parseErr
	}
	if size > 1<<20 {
		return false, nil
	}
	payload, parseErr := detect.ReadFileWithinRoot(detectorID, root, rel)
	if parseErr != nil {
		return false, parseErr
	}
	return hasOpenAPIRootKey(payload, filepath.Ext(lower)), nil
}

func hasOpenAPIRootKey(payload []byte, ext string) bool {
	var root map[string]any
	if strings.EqualFold(ext, ".json") {
		if err := json.Unmarshal(payload, &root); err != nil {
			return false
		}
	} else if err := yaml.Unmarshal(payload, &root); err != nil {
		return false
	}
	return strings.TrimSpace(stringValue(root["openapi"])) != "" || strings.TrimSpace(stringValue(root["swagger"])) != ""
}

func supportedVersion(doc document) bool {
	return strings.HasPrefix(strings.TrimSpace(doc.OpenAPI), "3.") || strings.HasPrefix(strings.TrimSpace(doc.Swagger), "2.")
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func findLocalConsumers(root, specRel string, files []detect.WalkedFile) ([]string, bool) {
	refs := []string{}
	for _, file := range files {
		if file.ParseError != nil || file.Rel == specRel || !consumerCandidate(file.Rel) || generatorCandidate(file.Rel) {
			continue
		}
		payload, parseErr := detect.ReadFileWithinRoot(detectorID, root, file.Rel)
		if parseErr != nil || len(payload) > 1<<20 {
			continue
		}
		lower := bytes.ToLower(payload)
		if referencesArtifactPath(file.Rel, specRel, lower) && (bytes.Contains(lower, []byte("swagger")) || bytes.Contains(lower, []byte("api-hub")) || bytes.Contains(lower, []byte("api_hub")) || bytes.Contains(lower, []byte("openapi"))) {
			if len(refs) >= maxSpecLineageFanout {
				return refs, true
			}
			refs = append(refs, file.Rel)
		}
	}
	sort.Strings(refs)
	return dedupe(refs), false
}

func findLocalGenerators(root, specRel string, files []detect.WalkedFile) ([]string, bool) {
	refs := []string{}
	for _, file := range files {
		if file.ParseError != nil || file.Rel == specRel || !generatorCandidate(file.Rel) {
			continue
		}
		payload, parseErr := detect.ReadFileWithinRoot(detectorID, root, file.Rel)
		if parseErr != nil || len(payload) > 1<<20 {
			continue
		}
		lower := bytes.ToLower(payload)
		if referencesArtifactPath(file.Rel, specRel, lower) && (bytes.Contains(lower, []byte("openapi-generator")) || bytes.Contains(lower, []byte("swagger-codegen")) || bytes.Contains(lower, []byte("generatorname"))) {
			if len(refs) >= maxSpecLineageFanout {
				return refs, true
			}
			refs = append(refs, file.Rel)
		}
	}
	sort.Strings(refs)
	return dedupe(refs), false
}

func referencesArtifactPath(sourceRel, artifactRel string, lowerPayload []byte) bool {
	artifact := strings.ToLower(filepath.ToSlash(filepath.Clean(strings.TrimSpace(artifactRel))))
	if artifact == "" || artifact == "." {
		return false
	}
	relative, err := filepath.Rel(filepath.Dir(filepath.FromSlash(sourceRel)), filepath.FromSlash(artifact))
	if err != nil {
		return false
	}
	relative = strings.ToLower(filepath.ToSlash(relative))
	candidates := []string{artifact, relative, strings.TrimPrefix(relative, "./")}
	if filepath.Dir(filepath.FromSlash(sourceRel)) == filepath.Dir(filepath.FromSlash(artifact)) {
		candidates = append(candidates, filepath.Base(artifact))
	}
	if !strings.Contains(artifact, "/") {
		candidates = append(candidates, "/"+artifact)
	}
	for _, candidate := range dedupeSorted(candidates) {
		if candidate != "" && bytes.Contains(lowerPayload, []byte(candidate)) {
			return true
		}
	}
	return false
}

func generatorCandidate(rel string) bool {
	lower := strings.ToLower(filepath.ToSlash(rel))
	base := filepath.Base(lower)
	if !strings.Contains(lower, "generator") && !strings.Contains(lower, "codegen") {
		return false
	}
	switch strings.ToLower(filepath.Ext(base)) {
	case ".yaml", ".yml", ".json", ".gradle", ".kts", ".xml":
		return true
	default:
		return false
	}
}

func consumerCandidate(rel string) bool {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".yaml", ".yml", ".json", ".js", ".ts", ".tsx", ".jsx", ".html":
		return true
	default:
		return false
	}
}

func dedupe(values []string) []string {
	out := values[:0]
	for _, value := range values {
		if len(out) == 0 || out[len(out)-1] != value {
			out = append(out, value)
		}
	}
	return out
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return strings.TrimSpace(org)
}
