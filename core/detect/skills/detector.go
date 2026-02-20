package skills

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/detect/gaitpolicy"
	"github.com/Clyra-AI/wrkr/core/model"
	"gopkg.in/yaml.v3"
)

const detectorID = "skills"

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

type frontmatter struct {
	AllowedTools []string `yaml:"allowed-tools"`
}

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	info, err := os.Stat(scope.Root)
	if err != nil || !info.IsDir() {
		return nil, nil
	}

	files, walkErr := detect.WalkFiles(scope.Root)
	if walkErr != nil {
		return nil, walkErr
	}
	skills := make([]string, 0)
	for _, rel := range files {
		if strings.HasSuffix(rel, "/SKILL.md") && (strings.HasPrefix(rel, ".claude/skills/") || strings.HasPrefix(rel, ".agents/skills/")) {
			skills = append(skills, rel)
		}
	}
	sort.Strings(skills)
	if len(skills) == 0 {
		return nil, nil
	}

	blockedTools, _, blockedErr := gaitpolicy.LoadBlockedTools(scope.Root)
	if blockedErr != nil {
		return nil, blockedErr
	}

	type counter struct {
		total int
		exec  int
		write int
		read  int
		none  int
	}
	stats := counter{total: len(skills)}
	ceiling := map[string]struct{}{}
	findings := make([]model.Finding, 0)

	for _, rel := range skills {
		tools, parseErr := parseAllowedTools(scope.Root, rel)
		if parseErr != nil {
			parseErr.Detector = detectorID
			findings = append(findings, model.Finding{
				FindingType: "parse_error",
				Severity:    model.SeverityMedium,
				ToolType:    "skill",
				Location:    rel,
				Repo:        scope.Repo,
				Org:         fallbackOrg(scope.Org),
				Detector:    detectorID,
				ParseError:  parseErr,
			})
			continue
		}
		permissions := normalizeTools(tools)
		hasExec := false
		hasWrite := false
		hasRead := false
		for _, permission := range permissions {
			switch permission {
			case "proc.exec":
				hasExec = true
			case "filesystem.write":
				hasWrite = true
			case "filesystem.read":
				hasRead = true
			}
		}
		switch {
		case hasExec:
			stats.exec++
		case hasWrite:
			stats.write++
		case hasRead:
			stats.read++
		default:
			stats.none++
		}

		findings = append(findings, model.Finding{
			FindingType: "skill",
			Severity:    severityForSkill(hasExec, hasWrite),
			ToolType:    "skill",
			Location:    rel,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Permissions: permissions,
			Evidence: []model.Evidence{
				{Key: "allowed_tools_count", Value: fmt.Sprintf("%d", len(permissions))},
			},
		})

		for _, permission := range permissions {
			if _, exists := ceiling[permission]; exists {
				continue
			}
			ceiling[permission] = struct{}{}
			if permission == "proc.exec" {
				findings = append(findings, model.Finding{
					FindingType: "skill_contribution",
					Severity:    model.SeverityHigh,
					ToolType:    "skill",
					Location:    rel,
					Repo:        scope.Repo,
					Org:         fallbackOrg(scope.Org),
					Detector:    detectorID,
					Permissions: []string{permission},
					Evidence: []model.Evidence{
						{Key: "adds_high_privilege", Value: permission},
					},
				})
			}
		}

		for _, permission := range permissions {
			if ruleSource, blocked := blockedTools[permission]; blocked {
				findings = append(findings, model.Finding{
					FindingType: "skill_policy_conflict",
					Severity:    model.SeverityHigh,
					ToolType:    "skill",
					Location:    rel,
					Repo:        scope.Repo,
					Org:         fallbackOrg(scope.Org),
					Detector:    detectorID,
					Permissions: []string{permission},
					Evidence: []model.Evidence{
						{Key: "skill", Value: rel},
						{Key: "grant", Value: permission},
						{Key: "conflicting_policy_rule", Value: ruleSource},
					},
				})
			}
		}
	}

	ceilingList := make([]string, 0, len(ceiling))
	for permission := range ceiling {
		ceilingList = append(ceilingList, permission)
	}
	sort.Strings(ceilingList)
	execRatio := ratio(stats.exec, stats.total)
	writeRatio := ratio(stats.write, stats.total)
	execWriteRatio := ratio(stats.exec+stats.write, stats.total)

	findings = append(findings, model.Finding{
		FindingType: "skill_metrics",
		Severity:    model.SeverityMedium,
		ToolType:    "skill",
		Location:    filepath.ToSlash(".agents/skills"),
		Repo:        scope.Repo,
		Org:         fallbackOrg(scope.Org),
		Detector:    detectorID,
		Permissions: ceilingList,
		Evidence: []model.Evidence{
			{Key: "skill_privilege_ceiling", Value: strings.Join(ceilingList, ",")},
			{Key: "skill_privilege_concentration.exec_ratio", Value: execRatio},
			{Key: "skill_privilege_concentration.write_ratio", Value: writeRatio},
			{Key: "skill_privilege_concentration.exec_write_ratio", Value: execWriteRatio},
			{Key: "skill_sprawl.total", Value: fmt.Sprintf("%d", stats.total)},
			{Key: "skill_sprawl.exec", Value: fmt.Sprintf("%d", stats.exec)},
			{Key: "skill_sprawl.write", Value: fmt.Sprintf("%d", stats.write)},
			{Key: "skill_sprawl.read", Value: fmt.Sprintf("%d", stats.read)},
			{Key: "skill_sprawl.none", Value: fmt.Sprintf("%d", stats.none)},
		},
	})

	model.SortFindings(findings)
	return findings, nil
}

func parseAllowedTools(root, rel string) ([]string, *model.ParseError) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	// #nosec G304 -- reads skills from selected repository root.
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, &model.ParseError{Kind: "file_read_error", Path: rel, Message: err.Error()}
	}
	content := string(payload)
	tools := make([]string, 0)

	if strings.HasPrefix(content, "---\n") {
		idx := strings.Index(content[4:], "\n---\n")
		if idx > 0 {
			var front frontmatter
			decoder := yaml.NewDecoder(bytes.NewBufferString(content[4 : 4+idx]))
			if decodeErr := decoder.Decode(&front); decodeErr == nil {
				tools = append(tools, front.AllowedTools...)
			}
		}
	}

	lines := strings.Split(content, "\n")
	inAllowedSection := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "allowed-tools:") {
			inAllowedSection = true
			inline := strings.TrimSpace(strings.TrimPrefix(trimmed, "allowed-tools:"))
			if strings.HasPrefix(inline, "[") && strings.HasSuffix(inline, "]") {
				inline = strings.TrimSuffix(strings.TrimPrefix(inline, "["), "]")
				for _, part := range strings.Split(inline, ",") {
					tools = append(tools, strings.Trim(strings.TrimSpace(part), "\""))
				}
			}
			continue
		}
		if strings.HasPrefix(lower, "##") || strings.HasPrefix(lower, "###") {
			inAllowedSection = false
		}
		if inAllowedSection && (strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "* ")) {
			tools = append(tools, strings.TrimSpace(trimmed[2:]))
		}
	}
	return tools, nil
}

func normalizeTools(in []string) []string {
	set := map[string]struct{}{}
	for _, item := range in {
		normalized := normalizeTool(item)
		if normalized == "" {
			continue
		}
		set[normalized] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for item := range set {
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func normalizeTool(in string) string {
	trimmed := strings.ToLower(strings.TrimSpace(in))
	switch {
	case trimmed == "":
		return ""
	case strings.Contains(trimmed, "bash"), strings.Contains(trimmed, "exec"), strings.Contains(trimmed, "proc.exec"):
		return "proc.exec"
	case strings.Contains(trimmed, "write"), strings.Contains(trimmed, "file_edit"):
		return "filesystem.write"
	case strings.Contains(trimmed, "read"), strings.Contains(trimmed, "search"), strings.Contains(trimmed, "grep"):
		return "filesystem.read"
	case strings.Contains(trimmed, "mcp"):
		return "mcp.access"
	default:
		return strings.ReplaceAll(trimmed, " ", "_")
	}
}

func ratio(part, total int) string {
	if total == 0 {
		return "0.00"
	}
	return fmt.Sprintf("%.2f", float64(part)/float64(total))
}

func severityForSkill(hasExec, hasWrite bool) string {
	switch {
	case hasExec:
		return model.SeverityHigh
	case hasWrite:
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return org
}
