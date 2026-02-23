package enrich

import (
	"context"
	"sort"
	"strings"
	"time"
)

const (
	QualityOK          = "ok"
	QualityPartial     = "partial"
	QualityStale       = "stale"
	QualityUnavailable = "unavailable"
)

type AdvisoryProvider interface {
	Lookup(ctx context.Context, pkg string, version string) (AdvisoryResult, error)
}

type RegistryProvider interface {
	Lookup(ctx context.Context, pkg string) (RegistryResult, error)
}

type AdvisoryResult struct {
	Count  int
	Source string
	Schema string
	Fresh  bool
}

type RegistryResult struct {
	Status string
	Source string
	Schema string
	Fresh  bool
}

type Result struct {
	Source         string
	AsOf           string
	Package        string
	Version        string
	AdvisoryCount  int
	RegistryStatus string
	Quality        string
	AdvisorySchema string
	RegistrySchema string
	Errors         []string
}

type Service struct {
	Advisories AdvisoryProvider
	Registry   RegistryProvider
	Clock      func() time.Time
}

func (s Service) Lookup(ctx context.Context, pkg string, version string) Result {
	now := time.Now().UTC().Truncate(time.Second)
	if s.Clock != nil {
		now = s.Clock().UTC().Truncate(time.Second)
	}

	result := Result{
		Package:        strings.TrimSpace(pkg),
		Version:        strings.TrimSpace(version),
		AsOf:           now.Format(time.RFC3339),
		AdvisoryCount:  0,
		RegistryStatus: "unknown",
		Quality:        QualityUnavailable,
		AdvisorySchema: "none",
		RegistrySchema: "none",
	}

	sources := []string{}
	errors := []string{}
	successCount := 0
	staleEvidence := false
	if s.Advisories != nil {
		advisory, err := s.Advisories.Lookup(ctx, result.Package, result.Version)
		if advisory.Source != "" {
			sources = append(sources, "advisory:"+strings.TrimSpace(advisory.Source))
		}
		if err == nil {
			result.AdvisoryCount = advisory.Count
			if strings.TrimSpace(advisory.Schema) != "" {
				result.AdvisorySchema = strings.TrimSpace(advisory.Schema)
			}
			successCount++
			if !advisory.Fresh {
				staleEvidence = true
			}
		} else {
			sources = append(sources, "advisory_error")
			errors = append(errors, "advisory_error")
		}
	}
	if s.Registry != nil {
		registry, err := s.Registry.Lookup(ctx, result.Package)
		if registry.Source != "" {
			sources = append(sources, "registry:"+strings.TrimSpace(registry.Source))
		}
		if err == nil {
			status := strings.TrimSpace(registry.Status)
			if status != "" {
				result.RegistryStatus = status
			}
			if strings.TrimSpace(registry.Schema) != "" {
				result.RegistrySchema = strings.TrimSpace(registry.Schema)
			}
			successCount++
			if !registry.Fresh {
				staleEvidence = true
			}
		} else {
			result.RegistryStatus = "unknown"
			sources = append(sources, "registry_error")
			errors = append(errors, "registry_error")
		}
	}
	if len(sources) == 0 {
		result.Source = "none"
	} else {
		sort.Strings(sources)
		result.Source = strings.Join(sources, ",")
	}
	sort.Strings(errors)
	result.Errors = errors
	switch {
	case successCount == 0:
		result.Quality = QualityUnavailable
	case len(errors) > 0:
		if staleEvidence {
			result.Quality = QualityStale
		} else {
			result.Quality = QualityPartial
		}
	case staleEvidence:
		result.Quality = QualityStale
	default:
		result.Quality = QualityOK
	}
	return result
}
