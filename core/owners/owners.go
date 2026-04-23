package owners

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type rule struct {
	pattern       string
	owner         string
	source        string
	evidenceBasis string
	priority      int
	inferred      bool
}

const (
	OwnerSourceCodeowners   = "codeowners"
	OwnerSourceCustomMap    = "custom_owner_mapping"
	OwnerSourceService      = "service_catalog"
	OwnerSourceBackstage    = "backstage_catalog"
	OwnerSourceGitHub       = "github_metadata"
	OwnerSourceRepoFallback = "repo_fallback"
	OwnerSourceConflict     = "multi_repo_conflict"
	OwnerSourceMissing      = "missing_owner"

	OwnershipStatusExplicit   = "explicit"
	OwnershipStatusInferred   = "inferred"
	OwnershipStatusUnresolved = "unresolved"

	OwnershipStateExplicit    = "explicit_owner"
	OwnershipStateInferred    = "inferred_owner"
	OwnershipStateConflicting = "conflicting_owner"
	OwnershipStateMissing     = "missing_owner"
)

type Resolution struct {
	Owner               string
	OwnerSource         string
	OwnershipStatus     string
	OwnershipState      string
	OwnershipConfidence float64
	EvidenceBasis       []string
	ConflictOwners      []string
}

type Metadata struct {
	Topics []string `json:"topics,omitempty" yaml:"topics,omitempty"`
	Teams  []string `json:"teams,omitempty" yaml:"teams,omitempty"`
}

func Resolve(root, repo, org, location string) Resolution {
	return ResolveWithMetadata(root, repo, org, location, Metadata{})
}

func ResolveWithMetadata(root, repo, org, location string, metadata Metadata) Resolution {
	rules := loadCodeowners(root)
	rules = append(rules, loadOwnerMappings(root)...)
	rules = append(rules, loadServiceCatalog(root)...)
	rules = append(rules, loadBackstageCatalog(root)...)
	rules = append(rules, rulesFromMetadata(repo, org, metadata)...)
	normalized := normalizePath(location)
	candidates := make([]rule, 0)
	for _, item := range rules {
		if matchPattern(item.pattern, normalized) {
			candidates = append(candidates, item)
		}
	}
	candidates = collapseCandidatesBySource(candidates)
	if len(candidates) > 0 {
		return resolveCandidates(candidates, repo, org)
	}
	if strings.TrimSpace(repo) == "" {
		return Resolution{
			Owner:               "",
			OwnerSource:         OwnerSourceMissing,
			OwnershipStatus:     OwnershipStatusUnresolved,
			OwnershipState:      OwnershipStateMissing,
			OwnershipConfidence: 0,
			EvidenceBasis:       []string{"owner_resolution:no_repo_context"},
		}
	}
	return Resolution{
		Owner:               FallbackOwner(repo, org),
		OwnerSource:         OwnerSourceRepoFallback,
		OwnershipStatus:     OwnershipStatusInferred,
		OwnershipState:      OwnershipStateInferred,
		OwnershipConfidence: 0.45,
		EvidenceBasis:       []string{"repo_fallback:repo_name"},
	}
}

// ResolveOwner derives ownership from CODEOWNERS with deterministic fallback.
func ResolveOwner(root, repo, org, location string) string {
	return Resolve(root, repo, org, location).Owner
}

func loadCodeowners(root string) []rule {
	paths := []string{"CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS"}
	for _, rel := range paths {
		path := filepath.Join(root, filepath.FromSlash(rel))
		payload, err := os.ReadFile(path) // #nosec G304 -- path is derived from known CODEOWNERS locations under the selected local root.
		if err != nil {
			continue
		}
		rules := parseRulesWithSource(string(payload), OwnerSourceCodeowners, rel, 0, false)
		if len(rules) > 0 {
			return rules
		}
	}
	return nil
}

func parseRulesWithSource(content, source, evidencePath string, priority int, inferred bool) []rule {
	scanner := bufio.NewScanner(strings.NewReader(content))
	out := make([]rule, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		pattern := normalizePath(parts[0])
		out = append(out, rule{
			pattern:       pattern,
			owner:         strings.TrimSpace(parts[1]),
			source:        source,
			evidenceBasis: source + ":" + evidencePath + ":" + pattern,
			priority:      priority,
			inferred:      inferred,
		})
	}
	return out
}

type ownerMappingDoc struct {
	Owners   []ownerMapping `json:"owners" yaml:"owners"`
	Mappings []ownerMapping `json:"mappings" yaml:"mappings"`
}

type ownerMapping struct {
	Repo    string   `json:"repo" yaml:"repo"`
	Repos   []string `json:"repos" yaml:"repos"`
	Path    string   `json:"path" yaml:"path"`
	Pattern string   `json:"pattern" yaml:"pattern"`
	Paths   []string `json:"paths" yaml:"paths"`
	Owner   string   `json:"owner" yaml:"owner"`
	Team    string   `json:"team" yaml:"team"`
}

func loadOwnerMappings(root string) []rule {
	return loadMappingFiles(root, []string{
		".wrkr/owners.yaml",
		".wrkr/owners.yml",
		".wrkr/owners.json",
		"wrkr-owners.yaml",
		"wrkr-owners.yml",
		"owners.yaml",
		"owners.yml",
	}, OwnerSourceCustomMap, 1)
}

func loadMappingFiles(root string, rels []string, source string, priority int) []rule {
	out := make([]rule, 0)
	for _, rel := range rels {
		path := filepath.Join(root, filepath.FromSlash(rel))
		payload, err := os.ReadFile(path) // #nosec G304 -- owner mapping paths are deterministic files under the selected scan root.
		if err != nil {
			continue
		}
		out = append(out, parseOwnerMappingDoc(payload, rel, source, priority)...)
	}
	return out
}

func parseOwnerMappingDoc(payload []byte, evidencePath, source string, priority int) []rule {
	var doc ownerMappingDoc
	if strings.HasSuffix(strings.ToLower(evidencePath), ".json") {
		if err := json.Unmarshal(payload, &doc); err != nil {
			return nil
		}
	} else if err := yaml.Unmarshal(payload, &doc); err != nil {
		return nil
	}
	items := append([]ownerMapping(nil), doc.Owners...)
	items = append(items, doc.Mappings...)
	return ownerMappingRules(items, evidencePath, source, priority, false)
}

func ownerMappingRules(items []ownerMapping, evidencePath, source string, priority int, inferred bool) []rule {
	out := make([]rule, 0, len(items))
	for _, item := range items {
		owner := normalizeOwner(item.Owner)
		if owner == "" {
			owner = normalizeOwner(item.Team)
		}
		if owner == "" {
			continue
		}
		patterns := mappingPatterns(item)
		for _, pattern := range patterns {
			out = append(out, rule{
				pattern:       pattern,
				owner:         owner,
				source:        source,
				evidenceBasis: source + ":" + evidencePath + ":" + pattern,
				priority:      priority,
				inferred:      inferred,
			})
		}
	}
	return out
}

func mappingPatterns(item ownerMapping) []string {
	values := append([]string(nil), item.Paths...)
	for _, value := range []string{item.Path, item.Pattern} {
		if strings.TrimSpace(value) != "" {
			values = append(values, value)
		}
	}
	if len(values) == 0 {
		values = []string{"*"}
	}
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		pattern := normalizePath(value)
		if pattern == "" {
			continue
		}
		if _, ok := seen[pattern]; ok {
			continue
		}
		seen[pattern] = struct{}{}
		out = append(out, pattern)
	}
	sort.Strings(out)
	return out
}

type serviceCatalogDoc struct {
	Services   []serviceCatalogItem `json:"services" yaml:"services"`
	Components []serviceCatalogItem `json:"components" yaml:"components"`
}

type serviceCatalogItem struct {
	Name    string   `json:"name" yaml:"name"`
	Repo    string   `json:"repo" yaml:"repo"`
	Owner   string   `json:"owner" yaml:"owner"`
	Team    string   `json:"team" yaml:"team"`
	Path    string   `json:"path" yaml:"path"`
	Paths   []string `json:"paths" yaml:"paths"`
	Pattern string   `json:"pattern" yaml:"pattern"`
}

func loadServiceCatalog(root string) []rule {
	rels := []string{
		".wrkr/service-catalog.yaml",
		".wrkr/service-catalog.yml",
		".wrkr/service-catalog.json",
		"service-catalog.yaml",
		"service-catalog.yml",
	}
	out := make([]rule, 0)
	for _, rel := range rels {
		path := filepath.Join(root, filepath.FromSlash(rel))
		payload, err := os.ReadFile(path) // #nosec G304 -- service catalog paths are deterministic files under the selected scan root.
		if err != nil {
			continue
		}
		out = append(out, parseServiceCatalogDoc(payload, rel)...)
	}
	return out
}

func parseServiceCatalogDoc(payload []byte, evidencePath string) []rule {
	var doc serviceCatalogDoc
	if strings.HasSuffix(strings.ToLower(evidencePath), ".json") {
		if err := json.Unmarshal(payload, &doc); err != nil {
			return nil
		}
	} else if err := yaml.Unmarshal(payload, &doc); err != nil {
		return nil
	}
	mappings := make([]ownerMapping, 0, len(doc.Services)+len(doc.Components))
	for _, item := range append(append([]serviceCatalogItem(nil), doc.Services...), doc.Components...) {
		mappings = append(mappings, ownerMapping{
			Repo:    item.Repo,
			Path:    item.Path,
			Paths:   append([]string(nil), item.Paths...),
			Pattern: item.Pattern,
			Owner:   item.Owner,
			Team:    item.Team,
		})
	}
	return ownerMappingRules(mappings, evidencePath, OwnerSourceService, 2, false)
}

type backstageCatalogDoc struct {
	Metadata struct {
		Name        string            `json:"name" yaml:"name"`
		Annotations map[string]string `json:"annotations" yaml:"annotations"`
	} `json:"metadata" yaml:"metadata"`
	Spec struct {
		Owner string `json:"owner" yaml:"owner"`
	} `json:"spec" yaml:"spec"`
}

func loadBackstageCatalog(root string) []rule {
	rels := []string{
		"catalog-info.yaml",
		"catalog-info.yml",
		".backstage/catalog-info.yaml",
		".backstage/catalog-info.yml",
	}
	out := make([]rule, 0)
	for _, rel := range rels {
		path := filepath.Join(root, filepath.FromSlash(rel))
		payload, err := os.ReadFile(path) // #nosec G304 -- Backstage catalog paths are deterministic files under the selected scan root.
		if err != nil {
			continue
		}
		out = append(out, parseBackstageCatalogDoc(payload, rel)...)
	}
	return out
}

func parseBackstageCatalogDoc(payload []byte, evidencePath string) []rule {
	var doc backstageCatalogDoc
	if err := yaml.Unmarshal(payload, &doc); err != nil {
		return nil
	}
	owner := normalizeOwner(doc.Spec.Owner)
	if owner == "" {
		owner = normalizeOwner(doc.Metadata.Annotations["github.com/team-slug"])
	}
	if owner == "" {
		return nil
	}
	return []rule{{
		pattern:       "*",
		owner:         owner,
		source:        OwnerSourceBackstage,
		evidenceBasis: OwnerSourceBackstage + ":" + evidencePath + ":spec.owner",
		priority:      3,
	}}
}

func rulesFromMetadata(repo, org string, metadata Metadata) []rule {
	owners := make([]string, 0)
	for _, team := range metadata.Teams {
		if owner := ownerFromTeamSlug(team, org); owner != "" {
			owners = append(owners, owner)
		}
	}
	for _, topic := range metadata.Topics {
		if owner := ownerFromTopic(topic, org); owner != "" {
			owners = append(owners, owner)
		}
	}
	owners = uniqueSorted(owners)
	out := make([]rule, 0, len(owners))
	for _, owner := range owners {
		out = append(out, rule{
			pattern:       "*",
			owner:         owner,
			source:        OwnerSourceGitHub,
			evidenceBasis: OwnerSourceGitHub + ":" + strings.TrimSpace(repo),
			priority:      4,
			inferred:      true,
		})
	}
	return out
}

func ownerFromTopic(topic, org string) string {
	normalized := strings.Trim(strings.ToLower(strings.TrimSpace(topic)), " /")
	for _, prefix := range []string{"team-", "owner-", "owners-", "team:", "owner:", "owners:"} {
		if strings.HasPrefix(normalized, prefix) {
			return ownerFromTeamSlug(strings.TrimPrefix(normalized, prefix), org)
		}
	}
	return ""
}

func ownerFromTeamSlug(team, org string) string {
	team = strings.Trim(strings.TrimSpace(team), " @/")
	if team == "" {
		return ""
	}
	if strings.Contains(team, "/") {
		return "@" + strings.TrimPrefix(team, "@")
	}
	if strings.TrimSpace(org) == "" {
		return "@local/" + strings.ToLower(team)
	}
	return "@" + strings.ToLower(strings.TrimSpace(org)) + "/" + strings.ToLower(team)
}

func resolveCandidates(candidates []rule, repo, org string) Resolution {
	byOwner := map[string][]rule{}
	for _, item := range candidates {
		owner := normalizeOwner(item.owner)
		if owner == "" {
			continue
		}
		byOwner[owner] = append(byOwner[owner], item)
	}
	if len(byOwner) == 0 {
		if strings.TrimSpace(repo) == "" {
			return Resolution{OwnerSource: OwnerSourceMissing, OwnershipStatus: OwnershipStatusUnresolved, OwnershipState: OwnershipStateMissing, EvidenceBasis: []string{"owner_resolution:no_owner_candidate"}}
		}
		return Resolution{
			Owner:               FallbackOwner(repo, org),
			OwnerSource:         OwnerSourceRepoFallback,
			OwnershipStatus:     OwnershipStatusInferred,
			OwnershipState:      OwnershipStateInferred,
			OwnershipConfidence: 0.45,
			EvidenceBasis:       []string{"repo_fallback:repo_name"},
		}
	}
	owners := make([]string, 0, len(byOwner))
	for owner := range byOwner {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	if len(owners) > 1 {
		return Resolution{
			Owner:               FallbackOwner(repo, org),
			OwnerSource:         OwnerSourceConflict,
			OwnershipStatus:     OwnershipStatusUnresolved,
			OwnershipState:      OwnershipStateConflicting,
			OwnershipConfidence: 0.2,
			EvidenceBasis:       evidenceBasisForCandidates(candidates),
			ConflictOwners:      owners,
		}
	}
	items := byOwner[owners[0]]
	sort.Slice(items, func(i, j int) bool {
		if items[i].priority != items[j].priority {
			return items[i].priority < items[j].priority
		}
		if items[i].source != items[j].source {
			return items[i].source < items[j].source
		}
		return items[i].evidenceBasis < items[j].evidenceBasis
	})
	best := items[0]
	status := OwnershipStatusExplicit
	state := OwnershipStateExplicit
	confidence := 0.9
	if best.inferred {
		status = OwnershipStatusInferred
		state = OwnershipStateInferred
		confidence = 0.65
	}
	if best.source == OwnerSourceCodeowners || best.source == OwnerSourceCustomMap {
		confidence = 0.95
	}
	return Resolution{
		Owner:               owners[0],
		OwnerSource:         best.source,
		OwnershipStatus:     status,
		OwnershipState:      state,
		OwnershipConfidence: confidence,
		EvidenceBasis:       evidenceBasisForCandidates(items),
	}
}

func collapseCandidatesBySource(candidates []rule) []rule {
	if len(candidates) == 0 {
		return nil
	}
	bySource := map[string]rule{}
	order := make([]string, 0, len(candidates))
	for _, item := range candidates {
		source := strings.TrimSpace(item.source)
		if source == "" {
			source = "unknown"
		}
		if _, exists := bySource[source]; !exists {
			order = append(order, source)
		}
		bySource[source] = item
	}
	out := make([]rule, 0, len(bySource))
	for _, source := range order {
		out = append(out, bySource[source])
	}
	return out
}

func evidenceBasisForCandidates(candidates []rule) []string {
	values := make([]string, 0, len(candidates))
	for _, item := range candidates {
		if strings.TrimSpace(item.evidenceBasis) != "" {
			values = append(values, item.evidenceBasis)
		}
	}
	return uniqueSorted(values)
}

func normalizeOwner(owner string) string {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return ""
	}
	if strings.Contains(owner, "/") && !strings.HasPrefix(owner, "@") {
		return "@" + owner
	}
	return owner
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func matchPattern(pattern, path string) bool {
	pattern = strings.TrimPrefix(pattern, "/")
	path = strings.TrimPrefix(path, "/")
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(path, strings.TrimSuffix(pattern, "/"))
	}
	if strings.Contains(pattern, "*") {
		ok, err := filepath.Match(pattern, path)
		if err == nil && ok {
			return true
		}
	}
	if pattern == path {
		return true
	}
	return strings.HasSuffix(path, pattern)
}

func FallbackOwner(repo, org string) string {
	trimmedRepo := strings.TrimSpace(repo)
	team := "owners"
	if trimmedRepo != "" {
		if idx := strings.LastIndex(trimmedRepo, "/"); idx >= 0 && idx < len(trimmedRepo)-1 {
			trimmedRepo = trimmedRepo[idx+1:]
		}
		if token := strings.Split(strings.ReplaceAll(trimmedRepo, "_", "-"), "-")[0]; strings.TrimSpace(token) != "" {
			team = strings.ToLower(token)
		}
	}
	if strings.TrimSpace(org) == "" {
		return "@local/" + team
	}
	return "@" + strings.ToLower(strings.TrimSpace(org)) + "/" + team
}

func normalizePath(in string) string {
	return filepath.ToSlash(strings.TrimSpace(in))
}
