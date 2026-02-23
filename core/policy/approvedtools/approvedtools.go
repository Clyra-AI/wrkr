package approvedtools

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

const SchemaVersionV1 = "v1"
const schemaURL = "https://wrkr.dev/schemas/v1/policy/approved-tools.schema.json"

//go:embed schema/approved-tools.schema.json
var approvedToolsSchemaJSON []byte

var (
	compiledSchema     *jsonschema.Schema
	compiledSchemaErr  error
	compiledSchemaOnce sync.Once
)

type MatchSet struct {
	Exact  []string `yaml:"exact" json:"exact"`
	Prefix []string `yaml:"prefix" json:"prefix"`
}

type Approved struct {
	ToolIDs   MatchSet `yaml:"tool_ids" json:"tool_ids"`
	AgentIDs  MatchSet `yaml:"agent_ids" json:"agent_ids"`
	ToolTypes MatchSet `yaml:"tool_types" json:"tool_types"`
	Orgs      MatchSet `yaml:"orgs" json:"orgs"`
	Repos     MatchSet `yaml:"repos" json:"repos"`
}

type Config struct {
	SchemaVersion string   `yaml:"schema_version" json:"schema_version"`
	Approved      Approved `yaml:"approved" json:"approved"`
}

type ToolCandidate struct {
	ToolID   string
	AgentID  string
	ToolType string
	Org      string
	Repos    []string
}

func Load(path string) (Config, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- explicit local policy path provided by user.
	if err != nil {
		return Config{}, fmt.Errorf("read approved tools policy %s: %w", path, err)
	}
	if err := validateSchema(payload, path); err != nil {
		return Config{}, err
	}
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse approved tools policy %s: %w", path, err)
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) Normalize() {
	c.SchemaVersion = strings.ToLower(strings.TrimSpace(c.SchemaVersion))
	c.Approved.ToolIDs = normalizeMatchSet(c.Approved.ToolIDs)
	c.Approved.AgentIDs = normalizeMatchSet(c.Approved.AgentIDs)
	c.Approved.ToolTypes = normalizeMatchSet(c.Approved.ToolTypes)
	c.Approved.Orgs = normalizeMatchSet(c.Approved.Orgs)
	c.Approved.Repos = normalizeMatchSet(c.Approved.Repos)
}

func (c Config) Validate() error {
	if c.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("approved tools schema_version must be %q", SchemaVersionV1)
	}
	return nil
}

func (c Config) HasRules() bool {
	sets := []MatchSet{
		c.Approved.ToolIDs,
		c.Approved.AgentIDs,
		c.Approved.ToolTypes,
		c.Approved.Orgs,
		c.Approved.Repos,
	}
	for _, set := range sets {
		if len(set.Exact) > 0 || len(set.Prefix) > 0 {
			return true
		}
	}
	return false
}

func (c Config) Match(candidate ToolCandidate) bool {
	if !c.HasRules() {
		return false
	}
	if c.Approved.ToolIDs.Match(candidate.ToolID) {
		return true
	}
	if c.Approved.AgentIDs.Match(candidate.AgentID) {
		return true
	}
	if c.Approved.ToolTypes.Match(candidate.ToolType) {
		return true
	}
	if c.Approved.Orgs.Match(candidate.Org) {
		return true
	}
	for _, repo := range candidate.Repos {
		if c.Approved.Repos.Match(repo) {
			return true
		}
	}
	return false
}

func (m MatchSet) Match(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return false
	}
	for _, exact := range m.Exact {
		if normalized == exact {
			return true
		}
	}
	for _, prefix := range m.Prefix {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	return false
}

func normalizeMatchSet(in MatchSet) MatchSet {
	return MatchSet{
		Exact:  normalizeStrings(in.Exact),
		Prefix: normalizeStrings(in.Prefix),
	}
}

func normalizeStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		trimmed := strings.ToLower(strings.TrimSpace(item))
		if trimmed == "" {
			continue
		}
		if _, exists := seen[trimmed]; exists {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	sort.Strings(out)
	return out
}

func validateSchema(payload []byte, path string) error {
	raw := any(nil)
	if err := yaml.Unmarshal(payload, &raw); err != nil {
		return fmt.Errorf("parse approved tools policy %s: %w", path, err)
	}
	normalized, err := normalizeYAML(raw)
	if err != nil {
		return fmt.Errorf("normalize approved tools policy %s: %w", path, err)
	}
	jsonPayload, err := json.Marshal(normalized)
	if err != nil {
		return fmt.Errorf("marshal approved tools policy %s: %w", path, err)
	}
	var doc any
	if err := json.Unmarshal(jsonPayload, &doc); err != nil {
		return fmt.Errorf("decode approved tools policy json %s: %w", path, err)
	}
	schema, err := getCompiledSchema()
	if err != nil {
		return fmt.Errorf("compile approved tools schema: %w", err)
	}
	if err := schema.Validate(doc); err != nil {
		return fmt.Errorf("validate approved tools policy %s: %w", path, err)
	}
	return nil
}

func getCompiledSchema() (*jsonschema.Schema, error) {
	compiledSchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		if err := compiler.AddResource(schemaURL, bytes.NewReader(approvedToolsSchemaJSON)); err != nil {
			compiledSchemaErr = err
			return
		}
		compiledSchema, compiledSchemaErr = compiler.Compile(schemaURL)
	})
	return compiledSchema, compiledSchemaErr
}

func normalizeYAML(in any) (any, error) {
	switch value := in.(type) {
	case nil, string, bool, int, int8, int16, int32, int64, float32, float64:
		return value, nil
	case map[string]any:
		out := make(map[string]any, len(value))
		for k, item := range value {
			normalized, err := normalizeYAML(item)
			if err != nil {
				return nil, err
			}
			out[k] = normalized
		}
		return out, nil
	case map[any]any:
		out := make(map[string]any, len(value))
		for k, item := range value {
			key, ok := k.(string)
			if !ok {
				return nil, fmt.Errorf("non-string key %T", k)
			}
			normalized, err := normalizeYAML(item)
			if err != nil {
				return nil, err
			}
			out[key] = normalized
		}
		return out, nil
	case []any:
		out := make([]any, 0, len(value))
		for _, item := range value {
			normalized, err := normalizeYAML(item)
			if err != nil {
				return nil, err
			}
			out = append(out, normalized)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported YAML value type %T", value)
	}
}
