package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const ControlDeclarationsVersion = "v1"

type ControlDeclarations struct {
	SchemaVersion string                      `json:"schema_version" yaml:"schema_version"`
	GeneratedAt   string                      `json:"generated_at,omitempty" yaml:"generated_at,omitempty"`
	Issuer        string                      `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	SignatureRef  string                      `json:"signature_ref,omitempty" yaml:"signature_ref,omitempty"`
	Owners        []ControlDeclarationOwner   `json:"owners,omitempty" yaml:"owners,omitempty"`
	Targets       []ControlDeclarationTarget  `json:"targets,omitempty" yaml:"targets,omitempty"`
	Controls      []ControlDeclarationControl `json:"controls,omitempty" yaml:"controls,omitempty"`
}

type ControlDeclarationOwner struct {
	Repo          string   `json:"repo,omitempty" yaml:"repo,omitempty"`
	Repos         []string `json:"repos,omitempty" yaml:"repos,omitempty"`
	Path          string   `json:"path,omitempty" yaml:"path,omitempty"`
	Pattern       string   `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Paths         []string `json:"paths,omitempty" yaml:"paths,omitempty"`
	Owner         string   `json:"owner" yaml:"owner"`
	EvidenceRefs  []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
	ObservedAt    string   `json:"observed_at,omitempty" yaml:"observed_at,omitempty"`
	ValidUntil    string   `json:"valid_until,omitempty" yaml:"valid_until,omitempty"`
	MaxAge        string   `json:"max_age,omitempty" yaml:"max_age,omitempty"`
	Issuer        string   `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	Confidence    string   `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	RedactionMode string   `json:"redaction_mode,omitempty" yaml:"redaction_mode,omitempty"`
}

type ControlDeclarationTarget struct {
	Repo          string   `json:"repo,omitempty" yaml:"repo,omitempty"`
	Repos         []string `json:"repos,omitempty" yaml:"repos,omitempty"`
	Path          string   `json:"path,omitempty" yaml:"path,omitempty"`
	Pattern       string   `json:"pattern,omitempty" yaml:"pattern,omitempty"`
	Paths         []string `json:"paths,omitempty" yaml:"paths,omitempty"`
	TargetClass   string   `json:"target_class" yaml:"target_class"`
	NonProduction bool     `json:"non_production,omitempty" yaml:"non_production,omitempty"`
	EvidenceRefs  []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
	ObservedAt    string   `json:"observed_at,omitempty" yaml:"observed_at,omitempty"`
	ValidUntil    string   `json:"valid_until,omitempty" yaml:"valid_until,omitempty"`
	MaxAge        string   `json:"max_age,omitempty" yaml:"max_age,omitempty"`
	Issuer        string   `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	Confidence    string   `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	RedactionMode string   `json:"redaction_mode,omitempty" yaml:"redaction_mode,omitempty"`
}

type ControlDeclarationControl struct {
	Repo             string   `json:"repo,omitempty" yaml:"repo,omitempty"`
	Repos            []string `json:"repos,omitempty" yaml:"repos,omitempty"`
	Path             string   `json:"path,omitempty" yaml:"path,omitempty"`
	Workflow         string   `json:"workflow,omitempty" yaml:"workflow,omitempty"`
	Environment      string   `json:"environment,omitempty" yaml:"environment,omitempty"`
	Branch           string   `json:"branch,omitempty" yaml:"branch,omitempty"`
	ApprovalRequired bool     `json:"approval_required,omitempty" yaml:"approval_required,omitempty"`
	RequiredChecks   []string `json:"required_checks,omitempty" yaml:"required_checks,omitempty"`
	SecurityGates    []string `json:"security_gates,omitempty" yaml:"security_gates,omitempty"`
	FreezeWindows    []string `json:"freeze_windows,omitempty" yaml:"freeze_windows,omitempty"`
	KillSwitches     []string `json:"kill_switches,omitempty" yaml:"kill_switches,omitempty"`
	EvidenceRefs     []string `json:"evidence_refs,omitempty" yaml:"evidence_refs,omitempty"`
	ObservedAt       string   `json:"observed_at,omitempty" yaml:"observed_at,omitempty"`
	ValidUntil       string   `json:"valid_until,omitempty" yaml:"valid_until,omitempty"`
	MaxAge           string   `json:"max_age,omitempty" yaml:"max_age,omitempty"`
	Issuer           string   `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	Confidence       string   `json:"confidence,omitempty" yaml:"confidence,omitempty"`
	RedactionMode    string   `json:"redaction_mode,omitempty" yaml:"redaction_mode,omitempty"`
}

func LoadControlDeclarations(root string) (ControlDeclarations, []string, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return ControlDeclarations{}, nil, nil
	}
	paths := []string{
		filepath.Join(root, "wrkr-control-declarations.yaml"),
		filepath.Join(root, ".wrkr", "control-declarations.yaml"),
	}
	loaded := ControlDeclarations{SchemaVersion: ControlDeclarationsVersion}
	used := []string{}
	for _, path := range paths {
		payload, err := os.ReadFile(path) // #nosec G304 -- deterministic declaration lookup under the selected local root.
		if err != nil {
			continue
		}
		var decoded ControlDeclarations
		if err := yaml.Unmarshal(payload, &decoded); err != nil {
			return ControlDeclarations{}, used, fmt.Errorf("parse control declarations %s: %w", filepath.ToSlash(path), err)
		}
		if err := validateControlDeclarations(decoded); err != nil {
			return ControlDeclarations{}, used, fmt.Errorf("validate control declarations %s: %w", filepath.ToSlash(path), err)
		}
		loaded = mergeControlDeclarations(loaded, decoded)
		used = append(used, filepath.ToSlash(path))
	}
	if len(used) == 0 {
		return ControlDeclarations{}, nil, nil
	}
	return loaded, used, nil
}

func validateControlDeclarations(doc ControlDeclarations) error {
	version := strings.TrimSpace(doc.SchemaVersion)
	if version == "" {
		version = ControlDeclarationsVersion
	}
	if version != ControlDeclarationsVersion {
		return fmt.Errorf("unsupported schema_version %q", doc.SchemaVersion)
	}
	if doc.GeneratedAt != "" {
		if _, err := time.Parse(time.RFC3339, strings.TrimSpace(doc.GeneratedAt)); err != nil {
			return fmt.Errorf("generated_at must be RFC3339")
		}
	}

	seen := map[string]struct{}{}
	for _, item := range doc.Owners {
		if strings.TrimSpace(item.Owner) == "" {
			return fmt.Errorf("owners.owner is required")
		}
		if err := validateDeclarationTiming(item.ObservedAt, item.ValidUntil, item.MaxAge); err != nil {
			return err
		}
		if err := validateDeclarationPaths(pathValues(item.Path, item.Pattern, item.Paths)); err != nil {
			return err
		}
		if err := validateEvidenceRefs(item.EvidenceRefs); err != nil {
			return err
		}
		if err := validateRedactionMode(item.RedactionMode); err != nil {
			return err
		}
		for _, scope := range declarationScopes(item.Repo, item.Repos, pathValues(item.Path, item.Pattern, item.Paths)) {
			key := "owner|" + scope
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate owner scope %s", scope)
			}
			seen[key] = struct{}{}
		}
	}
	for _, item := range doc.Targets {
		if !validTargetClass(item.TargetClass) {
			return fmt.Errorf("invalid target_class %q", item.TargetClass)
		}
		if err := validateDeclarationTiming(item.ObservedAt, item.ValidUntil, item.MaxAge); err != nil {
			return err
		}
		if err := validateDeclarationPaths(pathValues(item.Path, item.Pattern, item.Paths)); err != nil {
			return err
		}
		if err := validateEvidenceRefs(item.EvidenceRefs); err != nil {
			return err
		}
		if err := validateRedactionMode(item.RedactionMode); err != nil {
			return err
		}
		for _, scope := range declarationScopes(item.Repo, item.Repos, pathValues(item.Path, item.Pattern, item.Paths)) {
			key := "target|" + scope
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate target scope %s", scope)
			}
			seen[key] = struct{}{}
		}
	}
	for _, item := range doc.Controls {
		if err := validateDeclarationTiming(item.ObservedAt, item.ValidUntil, item.MaxAge); err != nil {
			return err
		}
		if err := validateDeclarationPaths(pathValues(item.Path, item.Workflow, nil)); err != nil {
			return err
		}
		if err := validateEvidenceRefs(item.EvidenceRefs); err != nil {
			return err
		}
		if err := validateRedactionMode(item.RedactionMode); err != nil {
			return err
		}
		for _, scope := range declarationScopes(item.Repo, item.Repos, pathValues(item.Path, item.Workflow, nil)) {
			key := "control|" + scope
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate control scope %s", scope)
			}
			seen[key] = struct{}{}
		}
	}
	return nil
}

func mergeControlDeclarations(base, incoming ControlDeclarations) ControlDeclarations {
	out := base
	if strings.TrimSpace(out.SchemaVersion) == "" {
		out.SchemaVersion = ControlDeclarationsVersion
	}
	if strings.TrimSpace(out.GeneratedAt) == "" {
		out.GeneratedAt = strings.TrimSpace(incoming.GeneratedAt)
	}
	if strings.TrimSpace(out.Issuer) == "" {
		out.Issuer = strings.TrimSpace(incoming.Issuer)
	}
	if strings.TrimSpace(out.SignatureRef) == "" {
		out.SignatureRef = strings.TrimSpace(incoming.SignatureRef)
	}
	out.Owners = append(out.Owners, incoming.Owners...)
	out.Targets = append(out.Targets, incoming.Targets...)
	out.Controls = append(out.Controls, incoming.Controls...)
	sort.Slice(out.Owners, func(i, j int) bool {
		return declarationSortKey(out.Owners[i].Repo, out.Owners[i].Repos, pathValues(out.Owners[i].Path, out.Owners[i].Pattern, out.Owners[i].Paths)) < declarationSortKey(out.Owners[j].Repo, out.Owners[j].Repos, pathValues(out.Owners[j].Path, out.Owners[j].Pattern, out.Owners[j].Paths))
	})
	sort.Slice(out.Targets, func(i, j int) bool {
		return declarationSortKey(out.Targets[i].Repo, out.Targets[i].Repos, pathValues(out.Targets[i].Path, out.Targets[i].Pattern, out.Targets[i].Paths)) < declarationSortKey(out.Targets[j].Repo, out.Targets[j].Repos, pathValues(out.Targets[j].Path, out.Targets[j].Pattern, out.Targets[j].Paths))
	})
	sort.Slice(out.Controls, func(i, j int) bool {
		return declarationSortKey(out.Controls[i].Repo, out.Controls[i].Repos, pathValues(out.Controls[i].Path, out.Controls[i].Workflow, nil)) < declarationSortKey(out.Controls[j].Repo, out.Controls[j].Repos, pathValues(out.Controls[j].Path, out.Controls[j].Workflow, nil))
	})
	return out
}

func validateDeclarationTiming(observedAt, validUntil, maxAge string) error {
	observedAt = strings.TrimSpace(observedAt)
	validUntil = strings.TrimSpace(validUntil)
	maxAge = strings.TrimSpace(maxAge)
	var observed time.Time
	if observedAt != "" {
		parsed, err := time.Parse(time.RFC3339, observedAt)
		if err != nil {
			return fmt.Errorf("observed_at must be RFC3339")
		}
		observed = parsed
	}
	if validUntil != "" {
		expires, err := time.Parse(time.RFC3339, validUntil)
		if err != nil {
			return fmt.Errorf("valid_until must be RFC3339")
		}
		if !observed.IsZero() && expires.Before(observed) {
			return fmt.Errorf("valid_until must not precede observed_at")
		}
	}
	if maxAge != "" {
		if _, err := time.ParseDuration(maxAge); err != nil {
			return fmt.Errorf("max_age must be a valid duration")
		}
	}
	return nil
}

func validateDeclarationPaths(values []string) error {
	for _, value := range values {
		trimmed := filepath.ToSlash(strings.TrimSpace(value))
		if trimmed == "" {
			continue
		}
		if filepath.IsAbs(trimmed) || strings.HasPrefix(trimmed, "../") || strings.Contains(trimmed, "/../") {
			return fmt.Errorf("unsafe declaration path %q", value)
		}
	}
	return nil
}

func validateEvidenceRefs(values []string) error {
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "evidence://"),
			strings.HasPrefix(trimmed, "proof://"),
			strings.HasPrefix(trimmed, "policy://"),
			strings.HasPrefix(trimmed, "file://"):
		default:
			return fmt.Errorf("unsupported evidence ref %q", value)
		}
	}
	return nil
}

func validateRedactionMode(value string) error {
	switch strings.TrimSpace(value) {
	case "", "none", "hash", "omit":
		return nil
	default:
		return fmt.Errorf("invalid redaction_mode %q", value)
	}
}

func validTargetClass(value string) bool {
	switch strings.TrimSpace(value) {
	case "production_impacting", "release_adjacent", "customer_data_adjacent", "internal_tooling", "developer_productivity", "test_demo_sandbox", "unknown":
		return true
	default:
		return false
	}
}

func declarationScopes(repo string, repos []string, paths []string) []string {
	values := []string{}
	allRepos := append([]string(nil), repos...)
	if strings.TrimSpace(repo) != "" {
		allRepos = append(allRepos, repo)
	}
	if len(allRepos) == 0 {
		allRepos = []string{"*"}
	}
	if len(paths) == 0 {
		paths = []string{"*"}
	}
	for _, repoValue := range allRepos {
		for _, pathValue := range paths {
			values = append(values, strings.TrimSpace(repoValue)+"::"+filepath.ToSlash(strings.TrimSpace(pathValue)))
		}
	}
	sort.Strings(values)
	return values
}

func pathValues(pathValue, pattern string, values []string) []string {
	out := append([]string(nil), values...)
	for _, item := range []string{pathValue, pattern} {
		if strings.TrimSpace(item) != "" {
			out = append(out, item)
		}
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	sort.Strings(out)
	return out
}

func declarationSortKey(repo string, repos []string, paths []string) string {
	return strings.Join(append(append([]string{strings.TrimSpace(repo)}, repos...), paths...), "|")
}
