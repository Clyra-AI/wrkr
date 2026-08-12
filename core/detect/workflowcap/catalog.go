package workflowcap

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/executiontopology"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/workflowloc"
)

type CatalogEntry struct {
	Path        string
	Platform    string
	SurfaceRole string
	Result      Result
	ParseError  *model.ParseError
}

// Catalog is immutable after construction and owns the canonical parser
// outcome for every supported workflow surface in one repository root.
type Catalog struct {
	entries map[string]CatalogEntry
	paths   []string
}

func BuildCatalog(root string, options detect.Options) (*Catalog, error) {
	files, err := detect.WalkFilesWithParseErrors(detectorID, root, options)
	if err != nil {
		return nil, err
	}
	entries := map[string]CatalogEntry{}
	paths := []string{}
	for _, file := range files {
		if !workflowloc.IsCIWorkflow(file.Rel) && !isCompositeAction(file.Rel) && !isJenkinsScript(file.Rel) {
			continue
		}
		entry := CatalogEntry{Path: file.Rel, Platform: platformForPath(file.Rel), SurfaceRole: surfaceRoleForPath(file.Rel)}
		if file.ParseError != nil {
			entry.ParseError = cloneParseError(file.ParseError)
		} else if entry.Platform == "gitlab_ci" && entry.SurfaceRole == "shared_source" {
			// GitLab include fragments are parsed and resolved by the entry pipeline.
			// Retain them in coverage without independently treating them as pipelines.
		} else {
			payload, parseErr := detect.ReadFileWithinRoot(detectorID, root, file.Rel)
			if parseErr != nil {
				entry.ParseError = cloneParseError(parseErr)
			} else {
				entry.Result, entry.ParseError = AnalyzeInRoot(root, file.Rel, payload)
			}
		}
		entry.Result = applyExecutionTopology(entry.Result, options.ExecutionTopology)
		entry.Result.ExecutionRelationships = normalizedExecutionRelationships(entry.Result.Evidence)
		entries[file.Rel] = entry
		paths = append(paths, file.Rel)
	}
	sort.Strings(paths)
	return &Catalog{entries: entries, paths: paths}, nil
}

func applyExecutionTopology(result Result, raw any) Result {
	topology, ok := raw.(*executiontopology.Topology)
	if !ok || topology == nil {
		return result
	}
	for index, evidence := range result.Evidence {
		if evidence.Key != "execution_relationship" {
			continue
		}
		parts := strings.Split(evidence.Value, "|")
		if len(parts) < 4 || parts[3] != "unresolved_external" {
			continue
		}
		mapping, found := resolveExecutionTopologyMapping(topology, parts[0], parts[2])
		if !found {
			continue
		}
		parts[2] = mapping.SourceRepo + ":" + mapping.SourcePath
		parts[3] = "resolved_declared"
		parts = append(parts, "topology:"+topology.Digest)
		result.Evidence[index].Value = strings.Join(parts, "|")
	}
	return result
}

func resolveExecutionTopologyMapping(topology *executiontopology.Topology, kind, alias string) (executiontopology.Mapping, bool) {
	if mapping, found := topology.Resolve(kind, alias); found {
		return mapping, true
	}
	switch strings.TrimSpace(kind) {
	case "github_reusable_workflow", "github_composite_action", "gitlab_include", "azure_template":
		return topology.Resolve("workflow_alias", alias)
	default:
		return executiontopology.Mapping{}, false
	}
}

func CatalogFor(root string, options detect.Options) (*Catalog, error) {
	if options.WorkflowCatalogs != nil {
		if value, ok := options.WorkflowCatalogs[root]; ok {
			if catalog, ok := value.(*Catalog); ok && catalog != nil {
				return catalog, nil
			}
		}
	}
	return BuildCatalog(root, options)
}

func (c *Catalog) Paths() []string {
	if c == nil {
		return nil
	}
	return append([]string(nil), c.paths...)
}

func (c *Catalog) EntrypointPaths() []string {
	if c == nil {
		return nil
	}
	out := []string{}
	for _, path := range c.paths {
		if c.entries[path].SurfaceRole == "entrypoint" {
			out = append(out, path)
		}
	}
	return out
}

func (c *Catalog) Lookup(path string) (CatalogEntry, bool) {
	if c == nil {
		return CatalogEntry{}, false
	}
	entry, ok := c.entries[strings.TrimSpace(path)]
	if !ok {
		return CatalogEntry{}, false
	}
	entry.Result = cloneResult(entry.Result)
	entry.ParseError = cloneParseError(entry.ParseError)
	return entry, true
}

func cloneResult(in Result) Result {
	out := in
	out.Capabilities = append([]string(nil), in.Capabilities...)
	out.Evidence = append([]model.Evidence(nil), in.Evidence...)
	out.JobNames = append([]string(nil), in.JobNames...)
	out.EnvironmentNames = append([]string(nil), in.EnvironmentNames...)
	out.Triggers = append([]string(nil), in.Triggers...)
	out.ExecutionRelationships = cloneExecutionRelationships(in.ExecutionRelationships)
	return out
}

func cloneParseError(in *model.ParseError) *model.ParseError {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func platformForPath(path string) string {
	switch {
	case workflowloc.IsGitHubWorkflow(path), isCompositeAction(path):
		return "github_actions"
	case workflowloc.IsJenkinsfile(path):
		return "jenkins"
	case isJenkinsLibrarySource(path):
		return "jenkins"
	case workflowloc.IsGitLabCIPath(path):
		return "gitlab_ci"
	case workflowloc.IsAzurePipelinePath(path):
		return "azure_pipelines"
	default:
		return "unsupported"
	}
}

func surfaceRoleForPath(path string) string {
	if isJenkinsScript(path) || isCompositeAction(path) {
		return "shared_source"
	}
	if workflowloc.IsGitLabCIPath(path) && !workflowloc.IsGitLabEntryPipeline(path) {
		return "shared_source"
	}
	return "entrypoint"
}

func isJenkinsLibrarySource(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path), "\\", "/"))
	return strings.HasSuffix(normalized, ".groovy") &&
		(strings.HasPrefix(normalized, "vars/") || strings.HasPrefix(normalized, "src/") || strings.Contains(normalized, "/vars/") || strings.Contains(normalized, "/src/"))
}

func isJenkinsScript(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path), "\\", "/"))
	return strings.HasSuffix(normalized, ".groovy")
}

type CatalogScope struct {
	Repo    string
	Root    string
	Catalog *Catalog
}

// ResolveCatalogs returns new immutable catalogs with topology-backed inherited
// facts. A declared mapping resolves only when its source is in the scan set.
func ResolveCatalogs(scopes []CatalogScope) map[string]*Catalog {
	bySource := map[string]CatalogEntry{}
	for _, scope := range scopes {
		if scope.Catalog == nil {
			continue
		}
		for _, path := range scope.Catalog.paths {
			bySource[strings.TrimSpace(scope.Repo)+":"+path] = scope.Catalog.entries[path]
		}
	}
	out := map[string]*Catalog{}
	for _, scope := range scopes {
		if scope.Catalog == nil {
			continue
		}
		entries := map[string]CatalogEntry{}
		for _, path := range scope.Catalog.paths {
			entry := scope.Catalog.entries[path]
			entry.Result = resolveEntryInheritance(scope.Repo, entry, bySource)
			entries[path] = entry
		}
		out[scope.Root] = &Catalog{entries: entries, paths: append([]string(nil), scope.Catalog.paths...)}
	}
	return out
}

const (
	maxRelationshipDepth  = 8
	maxRelationshipFanout = 64
)

func resolveEntryInheritance(repo string, entry CatalogEntry, bySource map[string]CatalogEntry) Result {
	result := cloneResult(entry.Result)
	startKey := strings.TrimSpace(repo) + ":" + entry.Path
	visited := map[string]bool{startKey: true}
	resolveRelationships(&result, strings.TrimSpace(repo), entry, bySource, visited, 0)
	result.ExecutionRelationships = normalizedExecutionRelationships(result.Evidence)
	sort.Slice(result.Evidence, func(i, j int) bool {
		if result.Evidence[i].Key != result.Evidence[j].Key {
			return result.Evidence[i].Key < result.Evidence[j].Key
		}
		return result.Evidence[i].Value < result.Evidence[j].Value
	})
	return result
}

func resolveRelationships(result *Result, repo string, entry CatalogEntry, bySource map[string]CatalogEntry, visited map[string]bool, depth int) {
	relationships := executionRelationships(entry.Result.Evidence)
	if len(relationships) > maxRelationshipFanout {
		result.Evidence = append(result.Evidence, model.Evidence{Key: "execution_resolution", Value: "relationship_fanout|" + entry.Path + "|" + entry.Path + "|fanout_limited|limit:64"})
		relationships = relationships[:maxRelationshipFanout]
	}
	for _, relationship := range relationships {
		parts := strings.Split(relationship.Value, "|")
		kind, caller, target, state := parts[0], parts[1], parts[2], parts[3]
		if state != "resolved_declared" && state != "resolved_local" {
			result.Evidence = append(result.Evidence, model.Evidence{Key: "execution_resolution", Value: kind + "|" + caller + "|" + target + "|" + state})
			continue
		}
		sourceKey := target
		if state == "resolved_local" {
			sourcePath := resolveLocalRelationshipPath(caller, target)
			sourceKey = repo + ":" + sourcePath
		}
		source, ok := bySource[sourceKey]
		if !ok && state == "resolved_declared" {
			// A topology mapping proves the declared relationship even when its
			// source repository is outside this scan. Without source facts there is
			// nothing to inherit, but the declaration itself remains resolved.
			continue
		}
		if !ok && state == "resolved_local" && relationshipResolvedByPlatformAdapter(kind) {
			// GitLab includes and Azure templates are recursively parsed by their
			// platform adapters. Their local source need not be a standalone
			// catalog entry, and the adapter's resolved edge remains authoritative.
			continue
		}
		if !ok || source.ParseError != nil || (state == "resolved_declared" && !declaredRelationshipSourceEligible(kind, source)) {
			result.Evidence = append(result.Evidence, model.Evidence{Key: "execution_resolution", Value: kind + "|" + caller + "|" + target + "|unresolved_external|source:" + sourceKey})
			continue
		}
		if visited[sourceKey] {
			result.Evidence = append(result.Evidence, model.Evidence{Key: "execution_resolution", Value: kind + "|" + caller + "|" + target + "|cycle_blocked|source:" + sourceKey})
			continue
		}
		if depth >= maxRelationshipDepth {
			result.Evidence = append(result.Evidence, model.Evidence{Key: "execution_resolution", Value: kind + "|" + caller + "|" + target + "|depth_limited|source:" + sourceKey})
			continue
		}
		inheritCatalogResult(result, source.Result, sourceKey, state)
		nextVisited := cloneVisited(visited)
		nextVisited[sourceKey] = true
		sourceRepo := repo
		if split := strings.LastIndex(sourceKey, ":"); split >= 0 {
			sourceRepo = sourceKey[:split]
		}
		resolveRelationships(result, sourceRepo, source, bySource, nextVisited, depth+1)
	}
}

func declaredRelationshipSourceEligible(kind string, source CatalogEntry) bool {
	switch strings.TrimSpace(kind) {
	case "github_reusable_workflow":
		return source.Platform == "github_actions" && workflowloc.IsGitHubWorkflow(source.Path)
	case "github_composite_action":
		return source.Platform == "github_actions" && isCompositeAction(source.Path)
	case "gitlab_include":
		return source.Platform == "gitlab_ci"
	case "azure_template":
		return source.Platform == "azure_pipelines"
	default:
		return source.SurfaceRole == "shared_source"
	}
}

func relationshipResolvedByPlatformAdapter(kind string) bool {
	switch strings.TrimSpace(kind) {
	case "gitlab_include", "azure_template":
		return true
	default:
		return false
	}
}

func executionRelationships(evidence []model.Evidence) []model.Evidence {
	out := []model.Evidence{}
	for _, item := range evidence {
		if item.Key == "execution_relationship" && len(strings.Split(item.Value, "|")) >= 4 {
			out = append(out, item)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
	return out
}

func resolveLocalRelationshipPath(caller, target string) string {
	normalized := filepath.ToSlash(filepath.Clean(strings.TrimSpace(target)))
	normalized = strings.TrimPrefix(normalized, "./")
	if strings.HasPrefix(strings.TrimSpace(target), "./") && strings.HasSuffix(strings.ToLower(strings.TrimSpace(target)), ".groovy") {
		normalized = filepath.ToSlash(filepath.Clean(filepath.Join(filepath.Dir(caller), strings.TrimPrefix(strings.TrimSpace(target), "./"))))
	}
	return normalized
}

func inheritCatalogResult(result *Result, source Result, sourceKey, state string) {
	result.Capabilities = mergeCatalogStrings(result.Capabilities, source.Capabilities)
	result.Headless = result.Headless || source.Headless
	result.DangerousFlags = result.DangerousFlags || source.DangerousFlags
	result.HasSecretAccess = result.HasSecretAccess || source.HasSecretAccess
	result.HasApprovalGate = result.HasApprovalGate || source.HasApprovalGate
	for _, sourceEvidence := range source.Evidence {
		switch sourceEvidence.Key {
		case "workflow_secret_refs", "workflow_credential_kind", "workflow_noncredential_secret_refs", "auth_surfaces", "authority_binding", "execution_relationship":
			result.Evidence = append(result.Evidence, sourceEvidence)
		}
	}
	result.Evidence = append(result.Evidence, model.Evidence{Key: "execution_origin", Value: "inherited|" + sourceKey + "|" + state})
}

func cloneVisited(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func mergeCatalogStrings(groups ...[]string) []string {
	set := map[string]struct{}{}
	for _, group := range groups {
		for _, value := range group {
			if strings.TrimSpace(value) != "" {
				set[strings.TrimSpace(value)] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func isCompositeAction(path string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(path), "\\", "/"))
	return strings.HasPrefix(normalized, ".github/actions/") &&
		(strings.HasSuffix(normalized, "/action.yml") || strings.HasSuffix(normalized, "/action.yaml"))
}
