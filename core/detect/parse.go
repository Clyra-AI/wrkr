package detect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/Clyra-AI/wrkr/core/model"
	"gopkg.in/yaml.v3"
)

var errUnsafePath = errors.New("unsafe_path")
var canonicalRootCache sync.Map

func ParseJSONFile(detectorID, root, rel string, dst any) *model.ParseError {
	return parseJSONFile(detectorID, root, rel, dst, false)
}

func ParseJSONFileAllowUnknownFields(detectorID, root, rel string, dst any) *model.ParseError {
	return parseJSONFile(detectorID, root, rel, dst, true)
}

func parseJSONFile(detectorID, root, rel string, dst any, allowUnknownFields bool) *model.ParseError {
	payload, parseErr := readFile(detectorID, root, rel)
	if parseErr != nil {
		parseErr.Format = "json"
		return parseErr
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	if !allowUnknownFields {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(dst); err != nil {
		return newParseError(detectorID, rel, "json", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return newParseError(detectorID, rel, "json", fmt.Errorf("multiple JSON values are not allowed"))
		}
		return newParseError(detectorID, rel, "json", err)
	}
	return nil
}

func ParseYAMLFile(detectorID, root, rel string, dst any) *model.ParseError {
	return parseYAMLFile(detectorID, root, rel, dst, false)
}

func ParseYAMLFileAllowUnknownFields(detectorID, root, rel string, dst any) *model.ParseError {
	return parseYAMLFile(detectorID, root, rel, dst, true)
}

func parseYAMLFile(detectorID, root, rel string, dst any, allowUnknownFields bool) *model.ParseError {
	payload, parseErr := readFile(detectorID, root, rel)
	if parseErr != nil {
		parseErr.Format = "yaml"
		return parseErr
	}

	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	if !allowUnknownFields {
		decoder.KnownFields(true)
	}
	if err := decoder.Decode(dst); err != nil {
		return newParseError(detectorID, rel, "yaml", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		if trailing != nil {
			return newParseError(detectorID, rel, "yaml", fmt.Errorf("multiple YAML documents are not allowed"))
		}
	}
	return nil
}

func ParseTOMLFile(detectorID, root, rel string, dst any) *model.ParseError {
	return parseTOMLFile(detectorID, root, rel, dst, false)
}

func ParseTOMLFileAllowUnknownFields(detectorID, root, rel string, dst any) *model.ParseError {
	return parseTOMLFile(detectorID, root, rel, dst, true)
}

func parseTOMLFile(detectorID, root, rel string, dst any, allowUnknownFields bool) *model.ParseError {
	payload, parseErr := readFile(detectorID, root, rel)
	if parseErr != nil {
		parseErr.Format = "toml"
		return parseErr
	}

	meta, err := toml.Decode(string(payload), dst)
	if err != nil {
		return newParseError(detectorID, rel, "toml", err)
	}
	undecoded := meta.Undecoded()
	if !allowUnknownFields && len(undecoded) > 0 {
		parts := make([]string, 0, len(undecoded))
		for _, item := range undecoded {
			parts = append(parts, item.String())
		}
		sort.Strings(parts)
		return newParseError(detectorID, rel, "toml", fmt.Errorf("unknown keys: %s", strings.Join(parts, ",")))
	}
	return nil
}

func FileExists(root, rel string) bool {
	info, err := statWithinRoot(root, rel)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func FileExistsWithinRoot(detectorID, root, rel string) (bool, *model.ParseError) {
	candidate := filepath.Join(strings.TrimSpace(root), filepath.FromSlash(rel))
	candidateInfo, lstatErr := os.Lstat(candidate)
	if lstatErr != nil {
		if os.IsNotExist(lstatErr) {
			return false, nil
		}
		return false, newReadParseError(detectorID, rel, "", lstatErr)
	}

	info, err := statWithinRoot(root, rel)
	if err != nil {
		if os.IsNotExist(err) && candidateInfo.Mode()&os.ModeSymlink == 0 {
			return false, nil
		}
		return false, newReadParseError(detectorID, rel, "", err)
	}
	return !info.IsDir(), nil
}

func DirExists(root, rel string) bool {
	info, err := statWithinRoot(root, rel)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func Glob(root, pattern string) ([]string, error) {
	if strings.ContainsAny(pattern, "*?[") {
		prefix := globLiteralPrefix(pattern)
		if prefix != "." {
			path, info, err := resolveWithinRoot(root, prefix)
			if err != nil {
				if os.IsNotExist(err) {
					return []string{}, nil
				}
				return nil, err
			}
			if !info.IsDir() {
				return nil, fmt.Errorf("glob prefix is not a directory: %s", filepath.ToSlash(prefix))
			}
			_ = path
		}
	}
	items, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		rel, relErr := filepath.Rel(root, item)
		if relErr != nil {
			return nil, relErr
		}
		out = append(out, filepath.ToSlash(rel))
	}
	sort.Strings(out)
	return out, nil
}

func globLiteralPrefix(pattern string) string {
	parts := strings.Split(filepath.ToSlash(pattern), "/")
	prefix := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.ContainsAny(part, "*?[") {
			break
		}
		if part == "" {
			continue
		}
		prefix = append(prefix, part)
	}
	if len(prefix) == 0 {
		return "."
	}
	return filepath.ToSlash(filepath.Join(prefix...))
}

func WalkFiles(root string) ([]string, error) {
	files := make([]string, 0)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func ReadFileWithinRoot(detectorID, root, rel string) ([]byte, *model.ParseError) {
	path, info, err := resolveWithinRoot(root, rel)
	if err != nil {
		return nil, newReadParseError(detectorID, rel, "", err)
	}
	if info.IsDir() {
		return nil, newReadParseError(detectorID, rel, "", fs.ErrNotExist)
	}
	// #nosec G304 -- helper resolves file paths to the selected repository root before reading.
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, newReadParseError(detectorID, rel, "", err)
	}
	return payload, nil
}

func OpenFileWithinRoot(detectorID, root, rel string) (*os.File, *model.ParseError) {
	path, info, err := resolveWithinRoot(root, rel)
	if err != nil {
		return nil, newReadParseError(detectorID, rel, "", err)
	}
	if info.IsDir() {
		return nil, newReadParseError(detectorID, rel, "", fs.ErrNotExist)
	}
	// #nosec G304 -- helper resolves file paths to the selected repository root before opening.
	file, err := os.Open(path)
	if err != nil {
		return nil, newReadParseError(detectorID, rel, "", err)
	}
	return file, nil
}

func readFile(detectorID, root, rel string) ([]byte, *model.ParseError) {
	return ReadFileWithinRoot(detectorID, root, rel)
}

func statWithinRoot(root, rel string) (fs.FileInfo, error) {
	_, info, err := resolveWithinRoot(root, rel)
	return info, err
}

func resolveWithinRoot(root, rel string) (string, fs.FileInfo, error) {
	rootPath := strings.TrimSpace(root)
	if rootPath == "" {
		return "", nil, fmt.Errorf("scope root is required")
	}
	candidate := filepath.Join(rootPath, filepath.FromSlash(rel))
	if _, err := os.Lstat(candidate); err != nil {
		return "", nil, err
	}
	canonicalRoot, err := canonicalRoot(rootPath)
	if err != nil {
		return "", nil, err
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", nil, err
	}
	if !isWithinRoot(canonicalRoot, resolved) {
		return "", nil, fmt.Errorf("%w: %s", errUnsafePath, filepath.ToSlash(rel))
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", nil, err
	}
	return resolved, info, nil
}

func isWithinRoot(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func canonicalRoot(root string) (string, error) {
	if cached, ok := canonicalRootCache.Load(root); ok {
		return cached.(string), nil
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	canonicalRootCache.Store(root, resolved)
	return resolved, nil
}

func newReadParseError(detectorID, rel, format string, err error) *model.ParseError {
	kind := "parse_error"
	if os.IsNotExist(err) {
		kind = "file_not_found"
	}
	if errors.Is(err, errUnsafePath) {
		kind = "unsafe_path"
	}
	return &model.ParseError{
		Kind:     kind,
		Format:   format,
		Path:     filepath.ToSlash(rel),
		Detector: strings.TrimSpace(detectorID),
		Message:  strings.TrimSpace(err.Error()),
	}
}

func newParseError(detectorID, rel, format string, err error) *model.ParseError {
	return newReadParseError(detectorID, rel, format, err)
}
