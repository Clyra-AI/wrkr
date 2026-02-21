package fix

import (
	"embed"
	"fmt"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed templates/templates.yaml
var templateFS embed.FS

type Template struct {
	ID           string   `yaml:"id"`
	Category     string   `yaml:"category"`
	Title        string   `yaml:"title"`
	CommitPrefix string   `yaml:"commit_prefix"`
	Hints        []string `yaml:"hints"`
}

type templateDoc struct {
	Templates []Template `yaml:"templates"`
}

var (
	loadTemplatesOnce sync.Once
	cachedTemplates   map[string]Template
	cachedTemplateErr error
)

func templatesByID() (map[string]Template, error) {
	loadTemplatesOnce.Do(func() {
		payload, err := templateFS.ReadFile("templates/templates.yaml")
		if err != nil {
			cachedTemplateErr = fmt.Errorf("read remediation templates: %w", err)
			return
		}

		var doc templateDoc
		if err := yaml.Unmarshal(payload, &doc); err != nil {
			cachedTemplateErr = fmt.Errorf("parse remediation templates: %w", err)
			return
		}
		if len(doc.Templates) == 0 {
			cachedTemplateErr = fmt.Errorf("parse remediation templates: empty catalog")
			return
		}

		out := make(map[string]Template, len(doc.Templates))
		for _, item := range doc.Templates {
			item.ID = strings.TrimSpace(item.ID)
			item.Category = strings.TrimSpace(item.Category)
			item.Title = strings.TrimSpace(item.Title)
			item.CommitPrefix = strings.TrimSpace(item.CommitPrefix)
			item.Hints = normalizeHints(item.Hints)
			if item.ID == "" || item.Category == "" || item.Title == "" || item.CommitPrefix == "" {
				cachedTemplateErr = fmt.Errorf("parse remediation templates: template missing required fields")
				return
			}
			out[item.ID] = item
		}
		cachedTemplates = out
	})

	if cachedTemplateErr != nil {
		return nil, cachedTemplateErr
	}

	copyOut := make(map[string]Template, len(cachedTemplates))
	for k, v := range cachedTemplates {
		copyOut[k] = v
	}
	return copyOut, nil
}

func normalizeHints(in []string) []string {
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
