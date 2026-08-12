package executiontopology

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type UnsafePathError struct{ message string }

func (e *UnsafePathError) Error() string { return e.message }

func IsUnsafePathError(err error) bool {
	_, ok := err.(*UnsafePathError)
	return ok
}

const Version = 1

type Mapping struct {
	Kind       string `json:"kind" yaml:"kind"`
	Alias      string `json:"alias" yaml:"alias"`
	SourceRepo string `json:"source_repo" yaml:"source_repo"`
	SourcePath string `json:"source_path" yaml:"source_path"`
	Version    string `json:"version,omitempty" yaml:"version,omitempty"`
}

type Topology struct {
	Version  int       `json:"version" yaml:"version"`
	Mappings []Mapping `json:"mappings" yaml:"mappings"`
	Digest   string    `json:"digest,omitempty" yaml:"-"`
}

func Load(path string) (*Topology, error) {
	clean := filepath.Clean(strings.TrimSpace(path))
	if clean == "." || clean == "" {
		return nil, fmt.Errorf("execution topology path is required")
	}
	if err := rejectSymlinkPathComponents(clean); err != nil {
		return nil, err
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("read execution topology: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, &UnsafePathError{message: "execution topology must be a regular non-symlink file"}
	}
	payload, err := os.ReadFile(clean)
	if err != nil {
		return nil, fmt.Errorf("read execution topology: %w", err)
	}
	var topology Topology
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	decoder.KnownFields(true)
	if err := decoder.Decode(&topology); err != nil {
		return nil, fmt.Errorf("parse execution topology: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("parse execution topology trailing document: %w", err)
		}
		return nil, fmt.Errorf("execution topology must contain exactly one YAML document")
	}
	if topology.Version != Version {
		return nil, fmt.Errorf("execution topology version must be %d", Version)
	}
	if len(topology.Mappings) == 0 {
		return nil, fmt.Errorf("execution topology requires at least one mapping")
	}
	seen := map[string]struct{}{}
	for index := range topology.Mappings {
		mapping := &topology.Mappings[index]
		mapping.Kind = strings.TrimSpace(mapping.Kind)
		mapping.Alias = strings.TrimSpace(mapping.Alias)
		mapping.SourceRepo = strings.TrimSpace(mapping.SourceRepo)
		mapping.SourcePath = normalizePortableRepoPath(mapping.SourcePath)
		mapping.Version = strings.TrimSpace(mapping.Version)
		if mapping.Kind != "jenkins_shared_library" && mapping.Kind != "workflow_alias" && mapping.Kind != "api_runtime" {
			return nil, fmt.Errorf("mapping %d has unsupported kind %q", index, mapping.Kind)
		}
		if mapping.Alias == "" || mapping.SourceRepo == "" || mapping.SourcePath == "." || mapping.SourcePath == "" {
			return nil, fmt.Errorf("mapping %d requires alias, source_repo, and source_path", index)
		}
		if isPortableAbsolutePath(mapping.SourcePath) || mapping.SourcePath == ".." || strings.HasPrefix(mapping.SourcePath, "../") {
			return nil, &UnsafePathError{message: fmt.Sprintf("mapping %d source_path escapes the declared repository", index)}
		}
		key := mapping.Kind + "|" + strings.ToLower(mapping.Alias)
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("mapping %d duplicates alias %q for kind %q", index, mapping.Alias, mapping.Kind)
		}
		seen[key] = struct{}{}
	}
	sort.Slice(topology.Mappings, func(i, j int) bool {
		left := topology.Mappings[i]
		right := topology.Mappings[j]
		return strings.Join([]string{left.Kind, left.Alias, left.SourceRepo, left.SourcePath, left.Version}, "|") < strings.Join([]string{right.Kind, right.Alias, right.SourceRepo, right.SourcePath, right.Version}, "|")
	})
	canonical, err := json.Marshal(struct {
		Version  int       `json:"version"`
		Mappings []Mapping `json:"mappings"`
	}{Version: topology.Version, Mappings: topology.Mappings})
	if err != nil {
		return nil, fmt.Errorf("canonicalize execution topology: %w", err)
	}
	sum := sha256.Sum256(canonical)
	topology.Digest = "sha256:" + hex.EncodeToString(sum[:])
	return &topology, nil
}

func rejectSymlinkPathComponents(input string) error {
	absolute, err := filepath.Abs(input)
	if err != nil {
		return fmt.Errorf("resolve execution topology path: %w", err)
	}
	volume := filepath.VolumeName(absolute)
	remainder := strings.TrimPrefix(absolute, volume)
	remainder = strings.TrimPrefix(remainder, string(filepath.Separator))
	components := strings.Split(remainder, string(filepath.Separator))
	current := volume + string(filepath.Separator)
	for index, component := range components {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		// The top-level OS directory is a trusted platform alias on systems
		// where paths such as /var resolve through a system-managed symlink.
		if index == 0 {
			continue
		}
		info, statErr := os.Lstat(current)
		if statErr != nil {
			return fmt.Errorf("read execution topology path component: %w", statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return &UnsafePathError{message: "execution topology path must not contain symlink components"}
		}
	}
	return nil
}

func normalizePortableRepoPath(raw string) string {
	normalized := strings.ReplaceAll(strings.TrimSpace(raw), "\\", "/")
	return pathpkg.Clean(normalized)
}

func isPortableAbsolutePath(value string) bool {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "//") {
		return true
	}
	return len(trimmed) >= 3 && ((trimmed[0] >= 'a' && trimmed[0] <= 'z') || (trimmed[0] >= 'A' && trimmed[0] <= 'Z')) && trimmed[1] == ':' && trimmed[2] == '/'
}

func (t *Topology) Resolve(kind, alias string) (Mapping, bool) {
	if t == nil {
		return Mapping{}, false
	}
	for _, mapping := range t.Mappings {
		if mapping.Kind == strings.TrimSpace(kind) && strings.EqualFold(mapping.Alias, strings.TrimSpace(alias)) {
			return mapping, true
		}
	}
	return Mapping{}, false
}
