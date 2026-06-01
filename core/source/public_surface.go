package source

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const publicSurfaceSchemaVersion = "v1"

type PublicSurfaceManifest struct {
	SchemaVersion string           `json:"schema_version" yaml:"schema_version"`
	Name          string           `json:"name,omitempty" yaml:"name,omitempty"`
	Sources       []PublicEvidence `json:"sources" yaml:"sources"`
}

type publicSurfaceInputError struct {
	err error
}

func (e *publicSurfaceInputError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *publicSurfaceInputError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

type publicSurfaceSafetyError struct {
	err error
}

func (e *publicSurfaceSafetyError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *publicSurfaceSafetyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

func IsPublicSurfaceInputError(err error) bool {
	var target *publicSurfaceInputError
	return errors.As(err, &target)
}

func IsPublicSurfaceSafetyError(err error) bool {
	var target *publicSurfaceSafetyError
	return errors.As(err, &target)
}

func LoadPublicSurfaceManifest(path string) (PublicSurfaceManifest, error) {
	trimmedPath := strings.TrimSpace(path)
	if trimmedPath == "" {
		return PublicSurfaceManifest{}, &publicSurfaceInputError{err: fmt.Errorf("public-surface target requires a manifest path")}
	}
	payload, err := os.ReadFile(trimmedPath) // #nosec G304 -- caller selected the explicit local manifest path for public-surface input.
	if err != nil {
		return PublicSurfaceManifest{}, &publicSurfaceInputError{err: fmt.Errorf("read public-surface manifest: %w", err)}
	}

	var manifest PublicSurfaceManifest
	if err := yaml.Unmarshal(payload, &manifest); err != nil {
		return PublicSurfaceManifest{}, &publicSurfaceInputError{err: fmt.Errorf("parse public-surface manifest: %w", err)}
	}
	if strings.TrimSpace(manifest.SchemaVersion) != publicSurfaceSchemaVersion {
		return PublicSurfaceManifest{}, &publicSurfaceInputError{err: fmt.Errorf("public-surface manifest schema_version must be %q", publicSurfaceSchemaVersion)}
	}
	if strings.TrimSpace(manifest.Name) == "" {
		base := filepath.Base(trimmedPath)
		manifest.Name = strings.TrimSuffix(base, filepath.Ext(base))
	}

	manifestDir := filepath.Dir(trimmedPath)
	for idx := range manifest.Sources {
		normalized, normalizeErr := normalizePublicEvidence(manifest.Sources[idx], manifestDir)
		if normalizeErr != nil {
			return PublicSurfaceManifest{}, normalizeErr
		}
		manifest.Sources[idx] = normalized
	}
	manifest.Sources = SortPublicEvidence(manifest.Sources)
	return manifest, nil
}

func normalizePublicEvidence(in PublicEvidence, manifestDir string) (PublicEvidence, error) {
	out := in
	out.ID = strings.TrimSpace(out.ID)
	out.SourceClass = strings.TrimSpace(out.SourceClass)
	out.Title = strings.TrimSpace(out.Title)
	out.PublicRef = strings.TrimSpace(out.PublicRef)
	out.CapturePath = strings.TrimSpace(out.CapturePath)
	out.CapturedAt = strings.TrimSpace(out.CapturedAt)
	out.EvidenceLabel = strings.TrimSpace(out.EvidenceLabel)
	out.Confidence = strings.TrimSpace(out.Confidence)
	out.InferenceRationale = strings.TrimSpace(out.InferenceRationale)
	out.Claims = dedupeAndSortStrings(out.Claims)

	if out.ID == "" {
		return PublicEvidence{}, &publicSurfaceInputError{err: fmt.Errorf("public-surface source id is required")}
	}
	if !validPublicSourceClass(out.SourceClass) {
		return PublicEvidence{}, &publicSurfaceInputError{err: fmt.Errorf("public-surface source %q has unsupported source_class %q", out.ID, out.SourceClass)}
	}
	if publicRefErr := validatePublicRef(out.PublicRef); publicRefErr != nil {
		return PublicEvidence{}, &publicSurfaceInputError{err: fmt.Errorf("public-surface source %q has invalid public_ref: %w", out.ID, publicRefErr)}
	}
	if !validPublicEvidenceLabel(out.EvidenceLabel) {
		return PublicEvidence{}, &publicSurfaceInputError{err: fmt.Errorf("public-surface source %q has unsupported evidence_label %q", out.ID, out.EvidenceLabel)}
	}
	if out.Confidence == "" {
		out.Confidence = "medium"
	}
	if out.Confidence != "high" && out.Confidence != "medium" && out.Confidence != "low" {
		return PublicEvidence{}, &publicSurfaceInputError{err: fmt.Errorf("public-surface source %q has unsupported confidence %q", out.ID, out.Confidence)}
	}
	if out.CapturedAt != "" {
		if _, err := time.Parse(time.RFC3339, out.CapturedAt); err != nil {
			return PublicEvidence{}, &publicSurfaceInputError{err: fmt.Errorf("public-surface source %q has invalid captured_at: %w", out.ID, err)}
		}
	}
	if needsInferenceRationale(out.EvidenceLabel) && out.InferenceRationale == "" {
		return PublicEvidence{}, &publicSurfaceInputError{err: fmt.Errorf("public-surface source %q requires inference_rationale for evidence_label %q", out.ID, out.EvidenceLabel)}
	}
	if out.CapturePath != "" {
		resolved, err := normalizeCapturePath(manifestDir, out.CapturePath)
		if err != nil {
			return PublicEvidence{}, err
		}
		out.CapturePath = resolved
	}
	return out, nil
}

func normalizeCapturePath(manifestDir, capturePath string) (string, error) {
	clean := filepath.Clean(strings.TrimSpace(capturePath))
	if clean == "." || clean == "" {
		return "", &publicSurfaceInputError{err: fmt.Errorf("public-surface capture_path must be non-empty when provided")}
	}
	if filepath.IsAbs(clean) {
		return "", &publicSurfaceSafetyError{err: fmt.Errorf("public-surface capture_path must stay relative to the manifest directory: %s", clean)}
	}
	joined := filepath.Join(manifestDir, clean)
	rel, err := filepath.Rel(manifestDir, joined)
	if err != nil {
		return "", &publicSurfaceSafetyError{err: fmt.Errorf("resolve public-surface capture_path %q: %w", capturePath, err)}
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", &publicSurfaceSafetyError{err: fmt.Errorf("public-surface capture_path escapes the manifest directory: %s", capturePath)}
	}
	return rel, nil
}

func validatePublicRef(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("public_ref is required")
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(parsed.Scheme)) {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("public_ref scheme must be http or https")
	}
}

func validPublicSourceClass(value string) bool {
	switch strings.TrimSpace(value) {
	case PublicSourceClassRepo,
		PublicSourceClassDocs,
		PublicSourceClassSDK,
		PublicSourceClassEngineeringBlog,
		PublicSourceClassReleaseNotes,
		PublicSourceClassStatusPage,
		PublicSourceClassWorkflow:
		return true
	default:
		return false
	}
}

func validPublicEvidenceLabel(value string) bool {
	switch strings.TrimSpace(value) {
	case PublicEvidenceLabelObserved,
		PublicEvidenceLabelInferred,
		PublicEvidenceLabelUnsupportedClaim,
		PublicEvidenceLabelPrivateEvidenceAbsent:
		return true
	default:
		return false
	}
}

func needsInferenceRationale(label string) bool {
	switch strings.TrimSpace(label) {
	case PublicEvidenceLabelInferred, PublicEvidenceLabelUnsupportedClaim:
		return true
	default:
		return false
	}
}

func dedupeAndSortStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		set[trimmed] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
