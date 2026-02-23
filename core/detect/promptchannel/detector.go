package promptchannel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
	"gopkg.in/yaml.v3"
)

const detectorID = "promptchannel"

const (
	findingTypeHiddenText      = "prompt_channel_hidden_text"
	findingTypeOverride        = "prompt_channel_override"
	findingTypeUntrustedInject = "prompt_channel_untrusted_context"

	reasonCodeHiddenText      = "PC-INVISIBLE-TEXT"
	reasonCodeOverride        = "PC-INSTRUCTION-OVERRIDE"
	reasonCodeUntrustedInject = "PC-UNTRUSTED-CONTEXT-INJECTION"
)

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	files, err := detect.WalkFiles(scope.Root)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	for _, rel := range files {
		if !isPromptSurface(rel) {
			continue
		}
		raw, parseSegments, format, parseErr := loadFile(scope.Root, rel)
		if parseErr != nil {
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "prompt_channel",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  parseErr,
			})
			continue
		}
		signals := analyze(rel, raw, parseSegments)
		for _, signal := range signals {
			findings = append(findings, signalFinding(scope, rel, format, signal))
		}
	}

	model.SortFindings(findings)
	return findings, nil
}

func loadFile(root, rel string) (string, []string, string, *model.ParseError) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	// #nosec G304 -- detector reads repository content selected by user.
	payload, err := os.ReadFile(path)
	if err != nil {
		return "", nil, "", &model.ParseError{
			Kind:     "file_read_error",
			Path:     rel,
			Detector: detectorID,
			Message:  strings.TrimSpace(err.Error()),
		}
	}

	raw := string(payload)
	format := fileFormat(rel)
	segments := normalizeLineSegments(raw)
	switch format {
	case "json":
		var parsed any
		if err := json.Unmarshal(payload, &parsed); err != nil {
			return "", nil, format, &model.ParseError{
				Kind:     "parse_error",
				Format:   format,
				Path:     rel,
				Detector: detectorID,
				Message:  strings.TrimSpace(err.Error()),
			}
		}
		segments = append(segments, collectStringValues(parsed)...)
	case "yaml":
		var parsed any
		if err := yaml.Unmarshal(payload, &parsed); err != nil {
			return "", nil, format, &model.ParseError{
				Kind:     "parse_error",
				Format:   format,
				Path:     rel,
				Detector: detectorID,
				Message:  strings.TrimSpace(err.Error()),
			}
		}
		segments = append(segments, collectStringValues(parsed)...)
	case "toml":
		parsed := map[string]any{}
		if _, err := toml.Decode(string(payload), &parsed); err != nil {
			return "", nil, format, &model.ParseError{
				Kind:     "parse_error",
				Format:   format,
				Path:     rel,
				Detector: detectorID,
				Message:  strings.TrimSpace(err.Error()),
			}
		}
		segments = append(segments, collectStringValues(parsed)...)
	}

	segments = normalizeSegments(segments)
	return raw, segments, format, nil
}

func analyze(rel string, raw string, segments []string) []signal {
	out := make([]signal, 0, 3)

	if snippets := hiddenTextSnippets(raw); len(snippets) > 0 {
		out = append(out, signal{
			FindingType:    findingTypeHiddenText,
			ReasonCode:     reasonCodeHiddenText,
			PatternFamily:  "invisible_text",
			Confidence:     "high",
			Severity:       model.SeverityHigh,
			LocationClass:  classifyLocation(rel),
			Snippets:       snippets,
			Remediation:    "Remove hidden Unicode control and zero-width characters from prompt-bearing files.",
			RuleDescriptor: "hidden-text",
		})
	}

	if snippets := overrideSnippets(segments); len(snippets) > 0 {
		out = append(out, signal{
			FindingType:    findingTypeOverride,
			ReasonCode:     reasonCodeOverride,
			PatternFamily:  "instruction_override",
			Confidence:     "medium",
			Severity:       model.SeverityHigh,
			LocationClass:  classifyLocation(rel),
			Snippets:       snippets,
			Remediation:    "Remove instruction-override language and align prompts with policy/system directives.",
			RuleDescriptor: "override",
		})
	}

	if snippets := untrustedInjectionSnippets(segments); len(snippets) > 0 {
		out = append(out, signal{
			FindingType:    findingTypeUntrustedInject,
			ReasonCode:     reasonCodeUntrustedInject,
			PatternFamily:  "untrusted_context_injection",
			Confidence:     "medium",
			Severity:       model.SeverityHigh,
			LocationClass:  classifyLocation(rel),
			Snippets:       snippets,
			Remediation:    "Avoid composing system prompts directly from untrusted runtime/user-controlled content.",
			RuleDescriptor: "injection",
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].FindingType != out[j].FindingType {
			return out[i].FindingType < out[j].FindingType
		}
		return out[i].ReasonCode < out[j].ReasonCode
	})
	return out
}

func signalFinding(scope detect.Scope, rel string, format string, sig signal) model.Finding {
	snippet := ""
	if len(sig.Snippets) > 0 {
		snippet = sig.Snippets[0]
	}
	return model.Finding{
		FindingType:     sig.FindingType,
		Severity:        sig.Severity,
		DiscoveryMethod: model.DiscoveryMethodStatic,
		ToolType:        "prompt_channel",
		Location:        rel,
		Repo:            scope.Repo,
		Org:             fallbackOrg(scope.Org),
		Detector:        detectorID,
		Remediation:     sig.Remediation,
		Evidence: []model.Evidence{
			{Key: "reason_code", Value: sig.ReasonCode},
			{Key: "pattern_family", Value: sig.PatternFamily},
			{Key: "evidence_snippet_hash", Value: snippetHash(sig.RuleDescriptor, snippet)},
			{Key: "location_class", Value: sig.LocationClass},
			{Key: "confidence_class", Value: sig.Confidence},
			{Key: "match_count", Value: strconv.Itoa(len(sig.Snippets))},
			{Key: "format", Value: format},
		},
	}
}

func snippetHash(ruleDescriptor string, snippet string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(ruleDescriptor) + "\n" + strings.TrimSpace(snippet)))
	return hex.EncodeToString(sum[:])
}

func collectStringValues(value any) []string {
	out := make([]string, 0)
	collectStringValuesInto(value, &out)
	return out
}

func collectStringValuesInto(value any, out *[]string) {
	switch typed := value.(type) {
	case string:
		*out = append(*out, typed)
	case []any:
		for _, item := range typed {
			collectStringValuesInto(item, out)
		}
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			*out = append(*out, key)
			collectStringValuesInto(typed[key], out)
		}
	case map[any]any:
		keys := make([]string, 0, len(typed))
		byKey := map[string]any{}
		for key, val := range typed {
			k := strings.TrimSpace(fmt.Sprintf("%v", key))
			if k == "" {
				continue
			}
			keys = append(keys, k)
			byKey[k] = val
		}
		sort.Strings(keys)
		for _, key := range keys {
			*out = append(*out, key)
			collectStringValuesInto(byKey[key], out)
		}
	}
}

func normalizeLineSegments(raw string) []string {
	lines := strings.Split(raw, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func normalizeSegments(in []string) []string {
	set := map[string]struct{}{}
	for _, item := range in {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}

func fileFormat(rel string) string {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".json":
		return "json"
	case ".yaml", ".yml":
		return "yaml"
	case ".toml":
		return "toml"
	case ".md":
		return "markdown"
	case ".sh":
		return "shell"
	default:
		return "text"
	}
}
