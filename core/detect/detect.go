package detect

import (
	"context"
	"errors"
	"fmt"
	"os"
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

// DetectorError captures a non-fatal detector failure tied to one scope.
type DetectorError struct {
	Detector string `json:"detector"`
	Org      string `json:"org"`
	Repo     string `json:"repo"`
	Code     string `json:"code"`
	Class    string `json:"class"`
	Message  string `json:"message"`
}

// RunResult contains deterministic findings and non-fatal detector errors.
type RunResult struct {
	Findings       []model.Finding `json:"findings"`
	DetectorErrors []DetectorError `json:"detector_errors,omitempty"`
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

func (r *Registry) Run(ctx context.Context, scopes []Scope, options Options) (RunResult, error) {
	if len(r.detectors) == 0 || len(scopes) == 0 {
		return RunResult{}, nil
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

	result := RunResult{
		Findings:       make([]model.Finding, 0),
		DetectorErrors: make([]DetectorError, 0),
	}
	for _, scope := range sortedScopes {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}
		if rootErr := ValidateScopeRoot(scope.Root); rootErr != nil {
			result.DetectorErrors = append(result.DetectorErrors, buildDetectorError(scope, "scope", rootErr))
			continue
		}
		for _, id := range ids {
			select {
			case <-ctx.Done():
				return result, ctx.Err()
			default:
			}
			items, err := r.detectors[id].Detect(ctx, scope, options)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return result, err
				}
				result.DetectorErrors = append(result.DetectorErrors, buildDetectorError(scope, id, err))
				continue
			}
			result.Findings = append(result.Findings, items...)
		}
	}
	model.SortFindings(result.Findings)
	sort.Slice(result.DetectorErrors, func(i, j int) bool {
		a := result.DetectorErrors[i]
		b := result.DetectorErrors[j]
		if a.Org != b.Org {
			return a.Org < b.Org
		}
		if a.Repo != b.Repo {
			return a.Repo < b.Repo
		}
		if a.Detector != b.Detector {
			return a.Detector < b.Detector
		}
		if a.Code != b.Code {
			return a.Code < b.Code
		}
		return a.Message < b.Message
	})
	if len(result.Findings) == 0 {
		result.Findings = nil
	}
	if len(result.DetectorErrors) == 0 {
		result.DetectorErrors = nil
	}
	return result, nil
}

func buildDetectorError(scope Scope, detector string, err error) DetectorError {
	code, class := classifyDetectorError(err)
	return DetectorError{
		Detector: strings.TrimSpace(detector),
		Org:      strings.TrimSpace(scope.Org),
		Repo:     strings.TrimSpace(scope.Repo),
		Code:     code,
		Class:    class,
		Message:  strings.TrimSpace(err.Error()),
	}
}

func classifyDetectorError(err error) (string, string) {
	switch {
	case err == nil:
		return "detector_error", "runtime"
	case errors.Is(err, os.ErrPermission):
		return "permission_denied", "filesystem"
	case errors.Is(err, os.ErrNotExist):
		return "path_not_found", "filesystem"
	}

	lower := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(lower, "permission denied"):
		return "permission_denied", "filesystem"
	case strings.Contains(lower, "no such file") || strings.Contains(lower, "not found"):
		return "path_not_found", "filesystem"
	case strings.Contains(lower, "invalid extension descriptor"):
		return "invalid_extension_descriptor", "extension"
	case strings.Contains(lower, "not a directory"):
		return "invalid_scope", "filesystem"
	case strings.Contains(lower, "i/o error") || strings.Contains(lower, "input/output"):
		return "io_error", "filesystem"
	default:
		return "detector_error", "runtime"
	}
}
