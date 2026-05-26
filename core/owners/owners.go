package owners

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/config"
	"github.com/Clyra-AI/wrkr/core/evidencepolicy"
	"gopkg.in/yaml.v3"
)

type rule struct {
	pattern       string
	owner         string
	source        string
	sourceType    string
	evidenceBasis string
	evidenceRefs  []string
	priority      int
	inferred      bool
	repoScopes    []string
	observedAt    string
	validUntil    string
	maxAge        string
	issuer        string
	confidence    string
	status        string
}

const (
	OwnerSourceCodeowners   = "codeowners"
	OwnerSourceCustomMap    = "custom_owner_mapping"
	OwnerSourceService      = "service_catalog"
	OwnerSourceBackstage    = "backstage_catalog"
	OwnerSourceGitHub       = "github_metadata"
	OwnerSourceGitHubTeam   = "github_team_export"
	OwnerSourceAppCatalog   = "app_catalog"
	OwnerSourceCustomerMap  = "customer_owner_map"
	OwnerSourceProvider     = "provider_export"
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
	EvidenceDecision    *evidencepolicy.Decision
}

type Metadata struct {
	Topics []string `json:"topics,omitempty" yaml:"topics,omitempty"`
	Teams  []string `json:"teams,omitempty" yaml:"teams,omitempty"`
}

func Resolve(root, repo, org, location string) Resolution {
	return ResolveWithMetadata(root, repo, org, location, Metadata{})
}

func ResolveWithMetadata(root, repo, org, location string, metadata Metadata) Resolution {
	return ResolveWithMetadataAt(root, repo, org, location, metadata, time.Time{})
}

func ResolveWithMetadataAt(root, repo, org, location string, metadata Metadata, generatedAt time.Time) Resolution {
	rules := loadCodeowners(root)
	rules = append(rules, loadOwnerMappings(root)...)
	rules = append(rules, loadServiceCatalog(root)...)
	rules = append(rules, loadBackstageCatalog(root)...)
	rules = append(rules, loadExternalOwnerMappings(root)...)
	rules = append(rules, loadDeclaredOwnerMappings(root)...)
	rules = append(rules, rulesFromMetadata(repo, org, metadata)...)
	normalized := normalizePath(location)
	candidates := make([]rule, 0)
	for _, item := range rules {
		if ruleMatchesRepo(item, repo, org) && matchPattern(item.pattern, normalized) {
			candidates = append(candidates, item)
		}
	}
	candidates = collapseCandidatesBySource(candidates)
	if len(candidates) > 0 {
		return resolveCandidates(candidates, repo, org, generatedAt)
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
		EvidenceDecision: &evidencepolicy.Decision{
			Field:                  evidencepolicy.FieldOwner,
			SelectedValue:          FallbackOwner(repo, org),
			SelectedSourceType:     evidencepolicy.SourceTypeRepoFallback,
			SelectedSource:         evidencepolicy.SourceTypeRepoFallback,
			SelectedFreshnessState: evidencepolicy.FreshnessStateUnknown,
			ReasonCodes:            []string{"precedence:selected:repo_fallback"},
		},
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
			sourceType:    source,
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
				sourceType:    source,
				evidenceBasis: source + ":" + evidencePath + ":" + pattern,
				evidenceRefs:  nil,
				priority:      priority,
				inferred:      inferred,
				repoScopes:    mappingRepos(item),
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

func mappingRepos(item ownerMapping) []string {
	values := append([]string(nil), item.Repos...)
	if strings.TrimSpace(item.Repo) != "" {
		values = append(values, item.Repo)
	}
	out := make([]string, 0, len(values))
	seen := map[string]struct{}{}
	for _, value := range values {
		scope := normalizeRepoScope(value)
		if scope == "" {
			continue
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
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
		sourceType:    OwnerSourceBackstage,
		evidenceBasis: OwnerSourceBackstage + ":" + evidencePath + ":spec.owner",
		evidenceRefs:  nil,
		priority:      3,
	}}
}

type externalOwnerEvidenceDoc struct {
	SchemaVersion string                        `json:"schema_version"`
	Records       []externalOwnerEvidenceRecord `json:"records"`
}

type externalOwnerEvidenceRecord struct {
	RecordKind    string   `json:"record_kind"`
	SourceType    string   `json:"source_type"`
	Source        string   `json:"source"`
	Repo          string   `json:"repo"`
	Workflow      string   `json:"workflow"`
	Path          string   `json:"path"`
	Location      string   `json:"location"`
	ObservedAt    string   `json:"observed_at"`
	ValidUntil    string   `json:"valid_until"`
	MaxAge        string   `json:"max_age"`
	Issuer        string   `json:"issuer"`
	Confidence    string   `json:"confidence"`
	Status        string   `json:"status"`
	EvidenceClass string   `json:"evidence_class"`
	Owner         string   `json:"owner"`
	EvidenceRefs  []string `json:"evidence_refs"`
}

func loadExternalOwnerMappings(root string) []rule {
	path := filepath.Join(root, ".wrkr", "provenance", "external-control-evidence.json")
	payload, err := os.ReadFile(path) // #nosec G304 -- deterministic repo-local external control evidence sidecar.
	if err != nil {
		return nil
	}
	var doc externalOwnerEvidenceDoc
	if err := json.Unmarshal(payload, &doc); err != nil {
		return nil
	}
	if strings.TrimSpace(doc.SchemaVersion) != "" && strings.TrimSpace(doc.SchemaVersion) != "v1" {
		return nil
	}

	out := make([]rule, 0, len(doc.Records))
	for _, record := range doc.Records {
		if strings.TrimSpace(record.RecordKind) != "external_control" || strings.TrimSpace(record.EvidenceClass) != "owner_assignment" {
			continue
		}
		owner := normalizeOwner(record.Owner)
		if owner == "" {
			continue
		}
		pattern := normalizePath(firstNonEmptyOwner(record.Path, record.Workflow, record.Location, "*"))
		if pattern == "" {
			pattern = "*"
		}
		sourceType := externalOwnerSourceType(record.SourceType)
		out = append(out, rule{
			pattern:       pattern,
			owner:         owner,
			source:        uniqueExternalOwnerSource(sourceType, record.Source, pattern, record.ObservedAt, record.EvidenceRefs),
			sourceType:    sourceType,
			evidenceBasis: sourceType + ":" + filepath.ToSlash(filepath.Join(".wrkr", "provenance", "external-control-evidence.json")) + ":" + pattern,
			evidenceRefs:  uniqueSorted(record.EvidenceRefs),
			priority:      externalOwnerPriority(record.SourceType),
			inferred:      false,
			repoScopes:    externalOwnerRepoScopes(record.Repo),
			observedAt:    strings.TrimSpace(record.ObservedAt),
			validUntil:    strings.TrimSpace(record.ValidUntil),
			maxAge:        strings.TrimSpace(record.MaxAge),
			issuer:        strings.TrimSpace(record.Issuer),
			confidence:    strings.TrimSpace(record.Confidence),
			status:        strings.TrimSpace(record.Status),
		})
	}
	return out
}

func externalOwnerSourceType(sourceType string) string {
	switch strings.TrimSpace(sourceType) {
	case OwnerSourceGitHubTeam:
		return OwnerSourceGitHubTeam
	case OwnerSourceAppCatalog:
		return OwnerSourceAppCatalog
	case OwnerSourceCustomerMap:
		return evidencepolicy.SourceTypeSignedDeclaration
	case OwnerSourceProvider:
		return OwnerSourceProvider
	case "backstage_export":
		return evidencepolicy.SourceTypeBackstageExport
	case evidencepolicy.SourceTypeTicketExport:
		return evidencepolicy.SourceTypeTicketExport
	default:
		return evidencepolicy.NormalizeSourceType(sourceType)
	}
}

func externalOwnerPriority(sourceType string) int {
	switch strings.TrimSpace(sourceType) {
	case OwnerSourceProvider, OwnerSourceGitHubTeam:
		return 1
	case OwnerSourceCustomerMap, OwnerSourceAppCatalog, "backstage_export":
		return 2
	default:
		return 3
	}
}

func externalOwnerRepoScopes(repo string) []string {
	if strings.TrimSpace(repo) == "" {
		return nil
	}
	return []string{normalizeRepoScope(repo)}
}

func uniqueExternalOwnerSource(sourceType, source, pattern, observedAt string, refs []string) string {
	return strings.Join([]string{
		sourceType,
		strings.TrimSpace(source),
		strings.TrimSpace(pattern),
		strings.TrimSpace(observedAt),
		strings.Join(uniqueSorted(refs), "|"),
	}, "::")
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
			sourceType:    OwnerSourceGitHub,
			evidenceBasis: OwnerSourceGitHub + ":" + strings.TrimSpace(repo),
			evidenceRefs:  nil,
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

func ruleMatchesRepo(item rule, repo, org string) bool {
	if len(item.repoScopes) == 0 {
		return true
	}
	candidates := repoScopeCandidates(repo, org)
	for _, scope := range item.repoScopes {
		if _, ok := candidates[scope]; ok {
			return true
		}
	}
	return false
}

func repoScopeCandidates(repo, org string) map[string]struct{} {
	out := map[string]struct{}{}
	repoScope := normalizeRepoScope(repo)
	orgScope := normalizeRepoScope(org)
	if repoScope == "" {
		return out
	}
	out[repoScope] = struct{}{}
	if slash := strings.LastIndex(repoScope, "/"); slash >= 0 && slash < len(repoScope)-1 {
		out[repoScope[slash+1:]] = struct{}{}
	} else if orgScope != "" {
		out[orgScope+"/"+repoScope] = struct{}{}
	}
	return out
}

func normalizeRepoScope(value string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(value)), "@/")
}

func resolveCandidates(candidates []rule, repo, org string, generatedAt time.Time) Resolution {
	evidenceCandidates := make([]evidencepolicy.Candidate, 0, len(candidates))
	for _, item := range candidates {
		owner := normalizeOwner(item.owner)
		if owner == "" {
			continue
		}
		evidenceCandidates = append(evidenceCandidates, evidencepolicy.Candidate{
			Field:          evidencepolicy.FieldOwner,
			Value:          owner,
			SourceType:     firstNonEmptyOwner(item.sourceType, item.source),
			Source:         item.source,
			EvidenceRefs:   append([]string{item.evidenceBasis}, item.evidenceRefs...),
			ObservedAt:     item.observedAt,
			ValidUntil:     item.validUntil,
			MaxAge:         item.maxAge,
			Issuer:         item.issuer,
			Confidence:     item.confidence,
			Status:         item.status,
			FreshnessState: evidencepolicy.FreshnessStateUnknown,
		})
	}
	decision := evidencepolicy.ResolveDecision(evidenceCandidates, generatedAt)
	if strings.TrimSpace(decision.SelectedValue) == "" {
		if strings.TrimSpace(repo) == "" {
			return Resolution{
				OwnerSource:      OwnerSourceMissing,
				OwnershipStatus:  OwnershipStatusUnresolved,
				OwnershipState:   OwnershipStateMissing,
				EvidenceBasis:    []string{"owner_resolution:no_owner_candidate"},
				EvidenceDecision: &decision,
			}
		}
		fallback := FallbackOwner(repo, org)
		return Resolution{
			Owner:               fallback,
			OwnerSource:         OwnerSourceRepoFallback,
			OwnershipStatus:     OwnershipStatusInferred,
			OwnershipState:      OwnershipStateInferred,
			OwnershipConfidence: 0.45,
			EvidenceBasis:       []string{"repo_fallback:repo_name"},
			EvidenceDecision: &evidencepolicy.Decision{
				Field:                  evidencepolicy.FieldOwner,
				SelectedValue:          fallback,
				SelectedSourceType:     evidencepolicy.SourceTypeRepoFallback,
				SelectedSource:         evidencepolicy.SourceTypeRepoFallback,
				SelectedFreshnessState: evidencepolicy.FreshnessStateUnknown,
				ReasonCodes:            []string{"precedence:selected:repo_fallback"},
			},
		}
	}

	status := OwnershipStatusExplicit
	state := OwnershipStateExplicit
	confidence := ownershipConfidenceForDecision(decision)
	if decision.ConflictState == evidencepolicy.ConflictStateAmbiguous {
		status = OwnershipStatusUnresolved
		state = OwnershipStateConflicting
		confidence = 0.2
	}
	if ownershipSourceIsInferred(decision.SelectedSourceType) {
		status = OwnershipStatusInferred
		state = OwnershipStateInferred
	}

	resolution := Resolution{
		Owner:               strings.TrimSpace(decision.SelectedValue),
		OwnerSource:         strings.TrimSpace(decision.SelectedSourceType),
		OwnershipStatus:     status,
		OwnershipState:      state,
		OwnershipConfidence: confidence,
		EvidenceBasis:       evidenceBasisForCandidates(candidates),
		EvidenceDecision:    &decision,
	}
	if decision.ConflictState == evidencepolicy.ConflictStateAmbiguous {
		resolution.OwnerSource = OwnerSourceConflict
		resolution.ConflictOwners = conflictOwnersFromDecision(decision)
	}
	return resolution
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
		values = append(values, item.evidenceRefs...)
	}
	return uniqueSorted(values)
}

func ownershipSourceIsInferred(sourceType string) bool {
	switch evidencepolicy.NormalizeSourceType(sourceType) {
	case OwnerSourceGitHub, evidencepolicy.SourceTypeRepoFallback:
		return true
	default:
		return false
	}
}

func ownershipConfidenceForDecision(decision evidencepolicy.Decision) float64 {
	switch evidencepolicy.NormalizeSourceType(decision.SelectedSourceType) {
	case evidencepolicy.SourceTypeProviderExport, evidencepolicy.SourceTypeGitHubTeamExport, evidencepolicy.SourceTypeBackstageExport:
		return 0.98
	case evidencepolicy.SourceTypeSignedDeclaration:
		return 0.94
	case evidencepolicy.SourceTypeCodeowners, evidencepolicy.SourceTypeCustomOwnerMap:
		return 0.95
	case evidencepolicy.SourceTypeServiceCatalog, evidencepolicy.SourceTypeBackstageCatalog, evidencepolicy.SourceTypeAppCatalog:
		return 0.9
	case evidencepolicy.SourceTypeGitHubMetadata:
		return 0.65
	case evidencepolicy.SourceTypeRepoFallback:
		return 0.45
	default:
		return 0.75
	}
}

func conflictOwnersFromDecision(decision evidencepolicy.Decision) []string {
	values := []string{decision.SelectedValue}
	for _, item := range decision.RejectedCandidates {
		values = append(values, item.Value)
	}
	return uniqueSorted(values)
}

func loadDeclaredOwnerMappings(root string) []rule {
	doc, paths, err := config.LoadControlDeclarations(root)
	if err != nil || len(paths) == 0 || len(doc.Owners) == 0 {
		return nil
	}
	out := make([]rule, 0, len(doc.Owners))
	for _, item := range doc.Owners {
		owner := normalizeOwner(item.Owner)
		if owner == "" {
			continue
		}
		patterns := mappingPatterns(ownerMapping{
			Path:    item.Path,
			Pattern: item.Pattern,
			Paths:   item.Paths,
		})
		if len(patterns) == 0 {
			patterns = []string{"*"}
		}
		repoScopes := mappingRepos(ownerMapping{Repo: item.Repo, Repos: item.Repos})
		for _, pattern := range patterns {
			out = append(out, rule{
				pattern:       pattern,
				owner:         owner,
				source:        strings.Join([]string{evidencepolicy.SourceTypeSignedDeclaration, strings.Join(paths, "|"), pattern, strings.TrimSpace(item.ObservedAt)}, "::"),
				sourceType:    evidencepolicy.SourceTypeSignedDeclaration,
				evidenceBasis: evidencepolicy.SourceTypeSignedDeclaration + ":" + filepath.ToSlash(filepath.Join("wrkr-control-declarations.yaml")) + ":" + pattern,
				evidenceRefs:  uniqueSorted(item.EvidenceRefs),
				priority:      1,
				inferred:      false,
				repoScopes:    repoScopes,
				observedAt:    strings.TrimSpace(item.ObservedAt),
				validUntil:    strings.TrimSpace(item.ValidUntil),
				maxAge:        strings.TrimSpace(item.MaxAge),
				issuer:        firstNonEmptyOwner(item.Issuer, doc.Issuer),
				confidence:    strings.TrimSpace(item.Confidence),
			})
		}
	}
	return out
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

func firstNonEmptyOwner(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
