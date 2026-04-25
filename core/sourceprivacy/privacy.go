package sourceprivacy

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	RetentionEphemeral       = "ephemeral"
	RetentionRetainForResume = "retain_for_resume"
	RetentionRetain          = "retain"

	SerializedLocationsLogical    = "logical"
	SerializedLocationsFilesystem = "filesystem"

	CleanupNotApplicable = "not_applicable"
	CleanupPending       = "pending"
	CleanupRemoved       = "removed"
	CleanupRetained      = "retained"
	CleanupFailed        = "failed"
)

// Contract is the machine-readable privacy contract emitted with scan-derived artifacts.
type Contract struct {
	RetentionMode              string   `json:"retention_mode" yaml:"retention_mode"`
	MaterializedSourceRetained bool     `json:"materialized_source_retained" yaml:"materialized_source_retained"`
	RawSourceInArtifacts       bool     `json:"raw_source_in_artifacts" yaml:"raw_source_in_artifacts"`
	SerializedLocations        string   `json:"serialized_locations" yaml:"serialized_locations"`
	CleanupStatus              string   `json:"cleanup_status" yaml:"cleanup_status"`
	Warnings                   []string `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

func ParseRetentionMode(raw string) (string, error) {
	switch strings.TrimSpace(raw) {
	case "", RetentionEphemeral:
		return RetentionEphemeral, nil
	case RetentionRetainForResume:
		return RetentionRetainForResume, nil
	case RetentionRetain:
		return RetentionRetain, nil
	default:
		return "", fmt.Errorf("--source-retention must be one of ephemeral, retain_for_resume, or retain")
	}
}

func InitialContract(mode string, hosted bool, allowSourceMaterialization bool) Contract {
	if strings.TrimSpace(mode) == "" {
		mode = RetentionEphemeral
	}
	contract := Contract{
		RetentionMode:              mode,
		MaterializedSourceRetained: false,
		RawSourceInArtifacts:       false,
		SerializedLocations:        SerializedLocationsFilesystem,
		CleanupStatus:              CleanupNotApplicable,
	}
	if hosted {
		contract.SerializedLocations = SerializedLocationsLogical
		contract.CleanupStatus = CleanupPending
	}
	if mode == RetentionRetain || mode == RetentionRetainForResume {
		contract.Warnings = append(contract.Warnings, "hosted source materialization retention was explicitly requested")
	}
	if allowSourceMaterialization {
		contract.Warnings = append(contract.Warnings, "generic hosted source-code materialization was explicitly enabled")
	}
	return Normalize(contract)
}

func Normalize(in Contract) Contract {
	mode, err := ParseRetentionMode(in.RetentionMode)
	if err != nil {
		mode = RetentionEphemeral
	}
	in.RetentionMode = mode
	if strings.TrimSpace(in.SerializedLocations) == "" {
		in.SerializedLocations = SerializedLocationsFilesystem
	}
	if strings.TrimSpace(in.CleanupStatus) == "" {
		in.CleanupStatus = CleanupNotApplicable
	}
	in.RawSourceInArtifacts = false
	in.Warnings = uniqueSortedStrings(in.Warnings)
	return in
}

func MarkRemoved(in Contract) Contract {
	in.MaterializedSourceRetained = false
	in.CleanupStatus = CleanupRemoved
	return Normalize(in)
}

func MarkRetained(in Contract) Contract {
	in.MaterializedSourceRetained = true
	in.CleanupStatus = CleanupRetained
	return Normalize(in)
}

func MarkFailed(in Contract, reason string) Contract {
	in.MaterializedSourceRetained = true
	in.CleanupStatus = CleanupFailed
	if trimmed := strings.TrimSpace(reason); trimmed != "" {
		in.Warnings = append(in.Warnings, "source cleanup failed: "+trimmed)
	}
	return Normalize(in)
}

func ShouldRetainMaterializedSource(mode string, success bool) bool {
	switch strings.TrimSpace(mode) {
	case RetentionRetain:
		return true
	case RetentionRetainForResume:
		return !success
	default:
		return false
	}
}

type Sanitizer struct {
	roots []string
}

func NewSanitizer(roots ...string) Sanitizer {
	normalized := make([]string, 0, len(roots)*2)
	for _, root := range roots {
		trimmed := strings.TrimSpace(root)
		if trimmed == "" {
			continue
		}
		clean := filepath.Clean(trimmed)
		normalized = append(normalized, clean, filepath.ToSlash(clean))
		if abs, err := filepath.Abs(clean); err == nil {
			normalized = append(normalized, abs, filepath.ToSlash(abs))
		}
	}
	return Sanitizer{roots: uniqueSortedStrings(normalized)}
}

func (s Sanitizer) String(value string) string {
	out := strings.TrimSpace(value)
	if out == "" {
		return out
	}
	for _, root := range s.roots {
		if root == "" {
			continue
		}
		out = strings.ReplaceAll(out, root, "$WRKR_SCAN_ROOT")
	}
	out = redactMaterializedSegment(out)
	return out
}

func (s Sanitizer) Strings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, s.String(value))
	}
	return out
}

func ContainsMaterializedSourcePath(value string) bool {
	normalized := filepath.ToSlash(strings.TrimSpace(value))
	return strings.Contains(normalized, ".wrkr/materialized-sources") ||
		strings.Contains(normalized, "/materialized-sources/")
}

func redactMaterializedSegment(value string) string {
	normalized := filepath.ToSlash(value)
	for _, marker := range []string{".wrkr/materialized-sources/", "materialized-sources/"} {
		idx := strings.Index(normalized, marker)
		if idx < 0 {
			continue
		}
		tail := strings.TrimPrefix(normalized[idx+len(marker):], "/")
		if tail == "" {
			return "redacted://materialized-source"
		}
		return "redacted://materialized-source/" + tail
	}
	return value
}

func uniqueSortedStrings(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}
