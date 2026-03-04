package extension

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

const (
	detectorID         = "extension"
	descriptorFilePath = ".wrkr/detectors/extensions.json"
	descriptorVersion  = "v1"
)

var descriptorIDRE = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

type Detector struct{}

func New() Detector { return Detector{} }

func (Detector) ID() string { return detectorID }

type descriptorEnvelope struct {
	Version   string                 `json:"version"`
	Detectors []detectorDescriptorV1 `json:"detectors"`
}

type detectorDescriptorV1 struct {
	ID          string           `json:"id"`
	FindingType string           `json:"finding_type"`
	ToolType    string           `json:"tool_type"`
	Location    string           `json:"location"`
	Severity    string           `json:"severity"`
	Remediation string           `json:"remediation"`
	Permissions []string         `json:"permissions"`
	Evidence    []model.Evidence `json:"evidence"`
}

func (Detector) Detect(_ context.Context, scope detect.Scope, _ detect.Options) ([]model.Finding, error) {
	if err := detect.ValidateScopeRoot(scope.Root); err != nil {
		return nil, err
	}
	if !detect.FileExists(scope.Root, descriptorFilePath) {
		return nil, nil
	}

	var envelope descriptorEnvelope
	if parseErr := detect.ParseJSONFile(detectorID, scope.Root, descriptorFilePath, &envelope); parseErr != nil {
		return nil, fmt.Errorf("invalid extension descriptor parse_error: %s", parseErr.Message)
	}
	if strings.TrimSpace(envelope.Version) != descriptorVersion {
		return nil, fmt.Errorf("invalid extension descriptor version: expected %q", descriptorVersion)
	}
	if len(envelope.Detectors) == 0 {
		return nil, nil
	}

	descriptors := append([]detectorDescriptorV1(nil), envelope.Detectors...)
	sort.Slice(descriptors, func(i, j int) bool {
		return strings.TrimSpace(descriptors[i].ID) < strings.TrimSpace(descriptors[j].ID)
	})

	seen := map[string]struct{}{}
	findings := make([]model.Finding, 0, len(descriptors))
	for _, descriptor := range descriptors {
		id := strings.TrimSpace(descriptor.ID)
		if _, exists := seen[id]; exists {
			return nil, fmt.Errorf("invalid extension descriptor %q: duplicate id", id)
		}
		seen[id] = struct{}{}

		if validateErr := validateDescriptor(descriptor); validateErr != nil {
			return nil, fmt.Errorf("invalid extension descriptor %q: %w", id, validateErr)
		}

		findings = append(findings, model.Finding{
			FindingType: descriptor.FindingType,
			Severity:    strings.ToLower(strings.TrimSpace(descriptor.Severity)),
			ToolType:    descriptor.ToolType,
			Location:    descriptor.Location,
			Repo:        scope.Repo,
			Org:         fallbackOrg(scope.Org),
			Detector:    detectorID,
			Permissions: descriptor.Permissions,
			Remediation: descriptor.Remediation,
			Evidence: append([]model.Evidence{
				{Key: "extension_id", Value: id},
				{Key: "descriptor_version", Value: descriptorVersion},
			}, descriptor.Evidence...),
		})
	}
	model.SortFindings(findings)
	return findings, nil
}

func validateDescriptor(descriptor detectorDescriptorV1) error {
	id := strings.TrimSpace(descriptor.ID)
	if id == "" {
		return errors.New("id is required")
	}
	if !descriptorIDRE.MatchString(id) {
		return errors.New("id must match [a-zA-Z0-9._-]+")
	}
	if strings.TrimSpace(descriptor.FindingType) == "" {
		return errors.New("finding_type is required")
	}
	if strings.TrimSpace(descriptor.ToolType) == "" {
		return errors.New("tool_type is required")
	}
	if strings.TrimSpace(descriptor.Location) == "" {
		return errors.New("location is required")
	}
	switch strings.ToLower(strings.TrimSpace(descriptor.Severity)) {
	case model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow, model.SeverityInfo:
	default:
		return errors.New("severity must be one of critical|high|medium|low|info")
	}
	return nil
}

func fallbackOrg(org string) string {
	if strings.TrimSpace(org) == "" {
		return "local"
	}
	return strings.TrimSpace(org)
}
