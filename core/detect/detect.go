package detect

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
)

// Scope is one deterministic repository scan input.
type Scope struct {
	Org  string
	Repo string
	Root string
}

// Options toggles optional detector behavior.
type Options struct {
	Enrich bool
}

// Detector emits canonical findings for one repo scope.
type Detector interface {
	ID() string
	Detect(context.Context, Scope, Options) ([]model.Finding, error)
}

// Registry stores detectors with deterministic execution order.
type Registry struct {
	detectors map[string]Detector
}

func NewRegistry() *Registry {
	return &Registry{detectors: map[string]Detector{}}
}

func (r *Registry) Register(detector Detector) error {
	if detector == nil {
		return fmt.Errorf("detector is required")
	}
	id := strings.TrimSpace(detector.ID())
	if id == "" {
		return fmt.Errorf("detector id is required")
	}
	if _, exists := r.detectors[id]; exists {
		return fmt.Errorf("duplicate detector id %q", id)
	}
	r.detectors[id] = detector
	return nil
}

func (r *Registry) Run(ctx context.Context, scopes []Scope, options Options) ([]model.Finding, error) {
	if len(r.detectors) == 0 || len(scopes) == 0 {
		return nil, nil
	}

	sortedScopes := append([]Scope(nil), scopes...)
	sort.Slice(sortedScopes, func(i, j int) bool {
		if sortedScopes[i].Org != sortedScopes[j].Org {
			return sortedScopes[i].Org < sortedScopes[j].Org
		}
		if sortedScopes[i].Repo != sortedScopes[j].Repo {
			return sortedScopes[i].Repo < sortedScopes[j].Repo
		}
		return sortedScopes[i].Root < sortedScopes[j].Root
	})

	ids := make([]string, 0, len(r.detectors))
	for id := range r.detectors {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	findings := make([]model.Finding, 0)
	for _, scope := range sortedScopes {
		for _, id := range ids {
			items, err := r.detectors[id].Detect(ctx, scope, options)
			if err != nil {
				return nil, fmt.Errorf("run detector %s: %w", id, err)
			}
			findings = append(findings, items...)
		}
	}
	model.SortFindings(findings)
	return findings, nil
}
