package nonhumanidentity

import (
	"context"
	"encoding/json"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
	"gopkg.in/yaml.v3"
)

const detectorID = "nonhumanidentity"

var botUserRE = regexp.MustCompile(`(?i)([a-z0-9._-]+\[bot\])`)
var serviceAccountEmailRE = regexp.MustCompile(`(?i)\b([a-z0-9._%+\-]+@[a-z0-9.\-]+\.iam\.gserviceaccount\.com)\b`)

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

func (Detector) Detect(_ context.Context, scope detect.Scope, options detect.Options) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}
	if detect.IsLocalMachineScope(scope) {
		return nil, nil
	}

	files, err := detect.WalkFilesWithParseErrors(detectorID, scope.Root, options)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	seen := map[string]struct{}{}
	for _, file := range files {
		rel := file.Rel
		if !isCandidatePath(rel) {
			continue
		}
		if file.ParseError != nil {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "non_human_identity",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  file.ParseError,
			})
			continue
		}
		candidates, ok := readStructuredCandidates(scope.Root, rel)
		if !ok {
			continue
		}
		for _, identity := range classifyCandidates(candidates) {
			key := strings.Join([]string{rel, identity.identityType, identity.subject, identity.source}, "|")
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			findings = append(findings, model.Finding{
				FindingType: "non_human_identity",
				Severity:    identity.severity,
				ToolType:    "non_human_identity",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				Evidence: []model.Evidence{
					{Key: "identity_type", Value: identity.identityType},
					{Key: "subject", Value: identity.subject},
					{Key: "source", Value: identity.source},
					{Key: "confidence", Value: identity.confidence},
					{Key: "credential_provenance_type", Value: credentialProvenanceType(identity.identityType)},
					{Key: "credential_subject", Value: identity.subject},
					{Key: "credential_scope", Value: "workflow"},
					{Key: "credential_confidence", Value: credentialProvenanceConfidence(identity.identityType, identity.confidence)},
				},
				Remediation: "Review the durable non-human execution identity backing this AI-enabled delivery path.",
			})
		}
	}

	model.SortFindings(findings)
	return findings, nil
}

type identityCandidate struct {
	identityType string
	subject      string
	source       string
	confidence   string
	severity     string
}

func isCandidatePath(rel string) bool {
	lower := strings.ToLower(strings.TrimSpace(rel))
	if !strings.HasPrefix(lower, ".github/") {
		return false
	}
	switch filepath.Ext(lower) {
	case ".json", ".yaml", ".yml":
		return true
	default:
		return false
	}
}

func readStructuredCandidates(root, rel string) ([]string, bool) {
	payload, parseErr := detect.ReadFileWithinRoot(detectorID, root, rel)
	if parseErr != nil {
		return nil, false
	}

	var decoded any
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".json":
		if err := json.Unmarshal(payload, &decoded); err != nil {
			return nil, false
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(payload, &decoded); err != nil {
			return nil, false
		}
	default:
		return nil, false
	}

	values := make([]string, 0)
	collectStructuredStrings(decoded, &values)
	sort.Strings(values)
	return dedupeStrings(values), true
}

func collectStructuredStrings(in any, out *[]string) {
	switch value := in.(type) {
	case map[string]any:
		for key, item := range value {
			*out = append(*out, strings.ToLower(strings.TrimSpace(key)))
			collectStructuredStrings(item, out)
		}
	case map[any]any:
		for key, item := range value {
			*out = append(*out, strings.ToLower(strings.TrimSpace(toString(key))))
			collectStructuredStrings(item, out)
		}
	case []any:
		for _, item := range value {
			collectStructuredStrings(item, out)
		}
	case string:
		trimmed := strings.ToLower(strings.TrimSpace(value))
		if trimmed != "" {
			*out = append(*out, trimmed)
		}
	}
}

func classifyCandidates(values []string) []identityCandidate {
	out := make([]identityCandidate, 0)
	seen := map[string]struct{}{}
	hasGitHubAppPair := hasAnySubstring(values, "app-id", "app_id") && hasAnySubstring(values, "private-key", "private_key")
	hasPartialGitHubApp := hasAnySubstring(values, "app-id", "app_id", "private-key", "private_key")

	if hasAnySubstring(values, "actions/create-github-app-token@") || hasGitHubAppPair {
		appendIdentity(seen, identityCandidate{
			identityType: "github_app",
			subject:      "github_app",
			source:       "workflow_static_signal",
			confidence:   "high",
			severity:     model.SeverityLow,
		}, &out)
	} else if hasPartialGitHubApp {
		appendIdentity(seen, identityCandidate{
			identityType: "unknown",
			subject:      "github_app_reference",
			source:       "workflow_static_signal",
			confidence:   "low",
			severity:     model.SeverityInfo,
		}, &out)
	}

	for _, value := range values {
		for _, match := range botUserRE.FindAllStringSubmatch(value, -1) {
			if len(match) != 2 {
				continue
			}
			appendIdentity(seen, identityCandidate{
				identityType: "bot_user",
				subject:      strings.ToLower(strings.TrimSpace(match[1])),
				source:       "workflow_static_signal",
				confidence:   "high",
				severity:     model.SeverityLow,
			}, &out)
		}
		for _, match := range serviceAccountEmailRE.FindAllStringSubmatch(value, -1) {
			if len(match) != 2 {
				continue
			}
			appendIdentity(seen, identityCandidate{
				identityType: "service_account",
				subject:      strings.ToLower(strings.TrimSpace(match[1])),
				source:       "workflow_static_signal",
				confidence:   "high",
				severity:     model.SeverityLow,
			}, &out)
		}
	}

	if hasAnySubstring(values, "service_account", "service-account", "client_email") && !hasIdentityType(out, "service_account") {
		appendIdentity(seen, identityCandidate{
			identityType: "unknown",
			subject:      "service_account_reference",
			source:       "workflow_static_signal",
			confidence:   "low",
			severity:     model.SeverityInfo,
		}, &out)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].identityType != out[j].identityType {
			return out[i].identityType < out[j].identityType
		}
		return out[i].subject < out[j].subject
	})
	return out
}

func appendIdentity(seen map[string]struct{}, item identityCandidate, out *[]identityCandidate) {
	key := strings.Join([]string{item.identityType, item.subject, item.source}, "|")
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, item)
}

func hasIdentityType(items []identityCandidate, target string) bool {
	for _, item := range items {
		if strings.TrimSpace(item.identityType) == strings.TrimSpace(target) {
			return true
		}
	}
	return false
}

func hasAnySubstring(values []string, needles ...string) bool {
	for _, value := range values {
		for _, needle := range needles {
			if strings.Contains(value, strings.ToLower(strings.TrimSpace(needle))) {
				return true
			}
		}
	}
	return false
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}

func credentialProvenanceType(identityType string) string {
	switch strings.TrimSpace(identityType) {
	case "github_app", "service_account":
		return "workload_identity"
	case "bot_user":
		return "inherited_human"
	default:
		return "unknown"
	}
}

func credentialProvenanceConfidence(identityType, confidence string) string {
	switch strings.TrimSpace(identityType) {
	case "github_app", "service_account":
		return "high"
	case "bot_user":
		if strings.TrimSpace(confidence) == "high" {
			return "medium"
		}
		return "low"
	default:
		if strings.TrimSpace(confidence) == "high" {
			return "medium"
		}
		return "low"
	}
}

func toString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return strings.TrimSpace(org)
}
