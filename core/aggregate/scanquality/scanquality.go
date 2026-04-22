package scanquality

import (
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

const ReportVersion = "1"

type Report struct {
	ScanQualityVersion string                 `json:"scan_quality_version"`
	Mode               string                 `json:"mode"`
	SuppressedPaths    []SuppressedPath       `json:"suppressed_paths,omitempty"`
	ParseErrors        []ParseIssue           `json:"parse_errors,omitempty"`
	DetectorErrors     []detect.DetectorError `json:"detector_errors,omitempty"`
}

type SuppressedPath struct {
	Org    string `json:"org,omitempty"`
	Repo   string `json:"repo,omitempty"`
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
}

type ParseIssue struct {
	Org               string `json:"org,omitempty"`
	Repo              string `json:"repo,omitempty"`
	Path              string `json:"path"`
	Detector          string `json:"detector,omitempty"`
	Kind              string `json:"kind"`
	Format            string `json:"format,omitempty"`
	Message           string `json:"message,omitempty"`
	Reason            string `json:"reason,omitempty"`
	RecommendedAction string `json:"recommended_action,omitempty"`
}

type Input struct {
	Mode           string
	Scopes         []detect.Scope
	Findings       []model.Finding
	DetectorErrors []detect.DetectorError
}

func Build(input Input) Report {
	report := Report{
		ScanQualityVersion: ReportVersion,
		Mode:               normalizeMode(input.Mode),
		DetectorErrors:     cloneDetectorErrors(input.DetectorErrors),
	}
	if report.Mode != "deep" {
		report.SuppressedPaths = collectSuppressedPaths(input.Scopes)
	}
	report.ParseErrors = collectParseIssues(input.Findings)
	return report
}

func collectSuppressedPaths(scopes []detect.Scope) []SuppressedPath {
	items := make([]SuppressedPath, 0)
	seen := map[string]struct{}{}
	for _, scope := range scopes {
		root := strings.TrimSpace(scope.Root)
		if root == "" {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return nil
			}
			rel = filepath.ToSlash(rel)
			if rel == "." || rel == "" {
				return nil
			}
			if !detect.IsGeneratedPath(rel) {
				return nil
			}
			kind := "file"
			if d != nil && d.IsDir() {
				kind = "directory"
			}
			key := strings.Join([]string{scope.Org, scope.Repo, rel, kind}, "|")
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				items = append(items, SuppressedPath{
					Org:    strings.TrimSpace(scope.Org),
					Repo:   strings.TrimSpace(scope.Repo),
					Path:   rel,
					Kind:   kind,
					Reason: "generated_or_package_noise",
				})
			}
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Org != items[j].Org {
			return items[i].Org < items[j].Org
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		return items[i].Kind < items[j].Kind
	})
	return items
}

func collectParseIssues(findings []model.Finding) []ParseIssue {
	items := make([]ParseIssue, 0)
	for _, finding := range findings {
		if finding.ParseError == nil {
			continue
		}
		reason := "detector_parse_error"
		recommendedAction := "debug_only"
		if detect.IsGeneratedPath(finding.Location) || detect.IsGeneratedPath(finding.ParseError.Path) {
			reason = "generated_or_package_noise"
			recommendedAction = "suppress"
		}
		items = append(items, ParseIssue{
			Org:               strings.TrimSpace(finding.Org),
			Repo:              strings.TrimSpace(finding.Repo),
			Path:              firstNonEmpty(finding.ParseError.Path, finding.Location),
			Detector:          strings.TrimSpace(finding.ParseError.Detector),
			Kind:              strings.TrimSpace(finding.ParseError.Kind),
			Format:            strings.TrimSpace(finding.ParseError.Format),
			Message:           strings.TrimSpace(finding.ParseError.Message),
			Reason:            reason,
			RecommendedAction: recommendedAction,
		})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Org != items[j].Org {
			return items[i].Org < items[j].Org
		}
		if items[i].Repo != items[j].Repo {
			return items[i].Repo < items[j].Repo
		}
		if items[i].Path != items[j].Path {
			return items[i].Path < items[j].Path
		}
		if items[i].Detector != items[j].Detector {
			return items[i].Detector < items[j].Detector
		}
		return items[i].Message < items[j].Message
	})
	return items
}

func cloneDetectorErrors(in []detect.DetectorError) []detect.DetectorError {
	if len(in) == 0 {
		return nil
	}
	out := append([]detect.DetectorError(nil), in...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Org != out[j].Org {
			return out[i].Org < out[j].Org
		}
		if out[i].Repo != out[j].Repo {
			return out[i].Repo < out[j].Repo
		}
		if out[i].Detector != out[j].Detector {
			return out[i].Detector < out[j].Detector
		}
		return out[i].Message < out[j].Message
	})
	return out
}

func normalizeMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case "quick", "deep":
		return strings.TrimSpace(mode)
	default:
		return "governance"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
