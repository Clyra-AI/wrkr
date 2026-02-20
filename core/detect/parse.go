package detect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Clyra-AI/wrkr/core/model"
	"gopkg.in/yaml.v3"
)

func ParseJSONFile(detectorID, root, rel string, dst any) *model.ParseError {
	payload, parseErr := readFile(root, rel)
	if parseErr != nil {
		parseErr.Format = "json"
		return parseErr
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
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
	payload, parseErr := readFile(root, rel)
	if parseErr != nil {
		parseErr.Format = "yaml"
		return parseErr
	}

	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	decoder.KnownFields(true)
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
	payload, parseErr := readFile(root, rel)
	if parseErr != nil {
		parseErr.Format = "toml"
		return parseErr
	}

	meta, err := toml.Decode(string(payload), dst)
	if err != nil {
		return newParseError(detectorID, rel, "toml", err)
	}
	undecoded := meta.Undecoded()
	if len(undecoded) > 0 {
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
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func DirExists(root, rel string) bool {
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		return false
	}
	return info.IsDir()
}

func Glob(root, pattern string) ([]string, error) {
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

func readFile(root, rel string) ([]byte, *model.ParseError) {
	path := filepath.Join(root, filepath.FromSlash(rel))
	// #nosec G304 -- detector reads files within user-selected repo roots.
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, newParseError("", rel, "", err)
	}
	return payload, nil
}

func newParseError(detectorID, rel, format string, err error) *model.ParseError {
	kind := "parse_error"
	if os.IsNotExist(err) {
		kind = "file_not_found"
	}
	return &model.ParseError{
		Kind:     kind,
		Format:   format,
		Path:     filepath.ToSlash(rel),
		Detector: strings.TrimSpace(detectorID),
		Message:  strings.TrimSpace(err.Error()),
	}
}
