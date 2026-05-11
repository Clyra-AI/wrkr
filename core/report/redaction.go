package report

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/risk"
)

type RedactionField string

const (
	RedactionOwners             RedactionField = "owners"
	RedactionRepos              RedactionField = "repos"
	RedactionPaths              RedactionField = "paths"
	RedactionCredentialSubjects RedactionField = "credential-subjects" // #nosec G101 -- redaction selector label, not a credential
	RedactionAuthors            RedactionField = "authors"
	RedactionFilesystem         RedactionField = "filesystem"
	RedactionProviders          RedactionField = "providers"
	RedactionProofRefs          RedactionField = "proof-refs"
	RedactionGraphRefs          RedactionField = "graph-refs"
)

type RedactionConfig struct {
	Profile       ShareProfile
	DefaultFields []RedactionField
	Fields        []RedactionField
	fieldSet      map[RedactionField]struct{}
}

var windowsDriveRE = regexp.MustCompile(`(?i)^[a-z]:[\\/].*`)

func ParseRedactionFields(raw string) ([]RedactionField, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]RedactionField, 0, len(parts))
	seen := map[RedactionField]struct{}{}
	for _, part := range parts {
		field := RedactionField(strings.TrimSpace(part))
		if field == "" {
			return nil, fmt.Errorf("--redact must be a comma-separated list of non-empty fields")
		}
		if !validRedactionField(field) {
			return nil, fmt.Errorf("--redact field %q must be one of owners|repos|paths|credential-subjects|authors|filesystem|providers|proof-refs|graph-refs", field)
		}
		if _, ok := seen[field]; ok {
			return nil, fmt.Errorf("--redact field %q was provided more than once", field)
		}
		seen[field] = struct{}{}
		out = append(out, field)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i] < out[j]
	})
	return out, nil
}

func ResolveRedactionConfig(profile ShareProfile, requested []RedactionField) RedactionConfig {
	defaults := defaultRedactionFields(profile)
	fields := append([]RedactionField(nil), defaults...)
	fields = append(fields, requested...)
	fields = uniqueRedactionFields(fields)
	fieldSet := make(map[RedactionField]struct{}, len(fields))
	for _, field := range fields {
		fieldSet[field] = struct{}{}
	}
	return RedactionConfig{
		Profile:       profile,
		DefaultFields: defaults,
		Fields:        fields,
		fieldSet:      fieldSet,
	}
}

func (c RedactionConfig) Applies() bool {
	return len(c.Fields) > 0
}

func (c RedactionConfig) Has(field RedactionField) bool {
	_, ok := c.fieldSet[field]
	return ok
}

func (c RedactionConfig) RequiresLegacySanitizer() bool {
	switch c.Profile {
	case ShareProfilePublic,
		ShareProfileCustomerRedacted,
		ShareProfileDesignPartner,
		ShareProfileExternalRedacted,
		ShareProfileInvestorSafe:
		return true
	default:
		return false
	}
}

func BuildShareProfileMetadata(config RedactionConfig) *ShareProfileMetadata {
	if !config.Applies() {
		return nil
	}
	return &ShareProfileMetadata{
		RedactionApplied:     true,
		RedactionVersion:     "customer-share-v2",
		PolicySummary:        redactionPolicySummary(config),
		SelectedFields:       redactionFieldStrings(config.Fields),
		ProfileDefaultFields: redactionFieldStrings(config.DefaultFields),
	}
}

func SanitizeFindings(in []risk.ScoredFinding, config RedactionConfig) []risk.ScoredFinding {
	out := make([]risk.ScoredFinding, 0, len(in))
	for _, item := range in {
		copyItem := item
		if config.Has(RedactionRepos) {
			copyItem.Finding.Repo = redactValue("repo", copyItem.Finding.Repo, 6)
			copyItem.Finding.Org = redactValue("org", copyItem.Finding.Org, 6)
		}
		copyItem.Finding.Location = redactLocationWithConfig(copyItem.Finding.Location, config)
		if config.Has(RedactionPaths) {
			copyItem.CanonicalKey = redactValue("finding", copyItem.CanonicalKey, 12)
		}
		out = append(out, copyItem)
	}
	return out
}

func redactLocationWithConfig(value string, config RedactionConfig) string {
	value = maybeRedactFilesystemValue(value, config)
	if config.Has(RedactionPaths) {
		return redactValue("loc", value, 8)
	}
	return value
}

func maybeRedactFilesystemValue(value string, config RedactionConfig) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || !config.Has(RedactionFilesystem) {
		return trimmed
	}
	if !looksLikeFilesystemPath(trimmed) {
		return trimmed
	}
	return redactValue("fs", trimmed, 8)
}

func looksLikeFilesystemPath(value string) bool {
	normalized := strings.ReplaceAll(strings.TrimSpace(value), "\\", "/")
	switch {
	case normalized == "":
		return false
	case strings.HasPrefix(normalized, "/"),
		strings.HasPrefix(normalized, "~/"),
		strings.HasPrefix(normalized, "../"),
		strings.HasPrefix(normalized, "./"),
		strings.Contains(normalized, "/Users/"),
		strings.Contains(normalized, "/home/"),
		strings.Contains(normalized, "/var/"),
		strings.Contains(normalized, "/tmp/"),
		windowsDriveRE.MatchString(value):
		return true
	default:
		return false
	}
}

func defaultRedactionFields(profile ShareProfile) []RedactionField {
	switch profile {
	case ShareProfileDesignPartner, ShareProfilePublic, ShareProfileCustomerRedacted, ShareProfileExternalRedacted, ShareProfileInvestorSafe:
		return []RedactionField{
			RedactionOwners,
			RedactionRepos,
			RedactionPaths,
			RedactionCredentialSubjects,
			RedactionAuthors,
			RedactionFilesystem,
			RedactionProviders,
			RedactionProofRefs,
			RedactionGraphRefs,
		}
	default:
		return nil
	}
}

func redactionPolicySummary(config RedactionConfig) []string {
	fields := strings.Join(redactionFieldStrings(config.Fields), ", ")
	if fields == "" {
		fields = "none"
	}
	return []string{
		fmt.Sprintf("selected redaction fields: %s", fields),
		"deterministic pseudonyms preserve joins inside one artifact set while keeping static posture, counts, risk tiers, and remediation facts intact",
	}
}

func redactionFieldStrings(values []RedactionField) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, string(value))
	}
	sort.Strings(out)
	return out
}

func uniqueRedactionFields(values []RedactionField) []RedactionField {
	if len(values) == 0 {
		return nil
	}
	seen := map[RedactionField]struct{}{}
	out := make([]RedactionField, 0, len(values))
	for _, value := range values {
		if !validRedactionField(value) {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i] < out[j]
	})
	return out
}

func validRedactionField(value RedactionField) bool {
	switch value {
	case RedactionOwners,
		RedactionRepos,
		RedactionPaths,
		RedactionCredentialSubjects,
		RedactionAuthors,
		RedactionFilesystem,
		RedactionProviders,
		RedactionProofRefs,
		RedactionGraphRefs:
		return true
	default:
		return false
	}
}
