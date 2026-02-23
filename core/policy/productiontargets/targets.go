package productiontargets

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
const schemaURL = "https://wrkr.dev/schemas/v1/policy/production-targets.schema.json"

//go:embed schema/production-targets.schema.json
var productionTargetsSchemaJSON []byte

var (
	compiledSchema     *jsonschema.Schema
	compiledSchemaErr  error
	compiledSchemaOnce sync.Once
)

var defaultWritePermissions = []string{
	"db.write",
	"deploy.write",
	"filesystem.write",
	"infra.write",
	"repo.contents.write",
}

func DefaultWritePermissions() []string {
	return append([]string(nil), defaultWritePermissions...)
}

type MatchSet struct {
	Exact  []string `yaml:"exact" json:"exact"`
	Prefix []string `yaml:"prefix" json:"prefix"`
}

type Targets struct {
	Repos             MatchSet `yaml:"repos" json:"repos"`
	MCPServers        MatchSet `yaml:"mcp_servers" json:"mcp_servers"`
	Hosts             MatchSet `yaml:"hosts" json:"hosts"`
	WorkflowEnvKeys   MatchSet `yaml:"workflow_env_keys" json:"workflow_env_keys"`
	WorkflowEnvValues MatchSet `yaml:"workflow_env_values" json:"workflow_env_values"`
}

type Config struct {
	SchemaVersion    string   `yaml:"schema_version" json:"schema_version"`
	Targets          Targets  `yaml:"targets" json:"targets"`
	WritePermissions []string `yaml:"write_permissions" json:"write_permissions"`
}

func Load(path string) (Config, error) {
	payload, err := os.ReadFile(path) // #nosec G304 -- explicit local policy path provided by user.
	if err != nil {
		return Config{}, fmt.Errorf("read production targets %s: %w", path, err)
	}
	if err := validateSchema(payload, path); err != nil {
		return Config{}, err
	}
	var cfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("parse production targets %s: %w", path, err)
	}
	cfg.Normalize()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) Normalize() {
	c.SchemaVersion = strings.ToLower(strings.TrimSpace(c.SchemaVersion))
	c.Targets.Repos = normalizeMatchSet(c.Targets.Repos)
	c.Targets.MCPServers = normalizeMatchSet(c.Targets.MCPServers)
	c.Targets.Hosts = normalizeMatchSet(c.Targets.Hosts)
	c.Targets.WorkflowEnvKeys = normalizeMatchSet(c.Targets.WorkflowEnvKeys)
	c.Targets.WorkflowEnvValues = normalizeMatchSet(c.Targets.WorkflowEnvValues)
	c.WritePermissions = normalizeStrings(c.WritePermissions)
	if len(c.WritePermissions) == 0 {
		c.WritePermissions = append([]string(nil), defaultWritePermissions...)
	}
}

func (c Config) Validate() error {
	if c.SchemaVersion != SchemaVersionV1 {
		return fmt.Errorf("production targets schema_version must be %q", SchemaVersionV1)
	}
	return nil
}

func (c Config) HasTargets() bool {
	sets := []MatchSet{
		c.Targets.Repos,
		c.Targets.MCPServers,
		c.Targets.Hosts,
		c.Targets.WorkflowEnvKeys,
		c.Targets.WorkflowEnvValues,
	}
	for _, set := range sets {
		if len(set.Exact) > 0 || len(set.Prefix) > 0 {
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
		return fmt.Errorf("parse production targets %s: %w", path, err)
	}
	normalized, err := normalizeYAML(raw)
	if err != nil {
		return fmt.Errorf("normalize production targets %s: %w", path, err)
	}
	jsonPayload, err := json.Marshal(normalized)
	if err != nil {
		return fmt.Errorf("marshal production targets %s: %w", path, err)
	}
	var doc any
	if err := json.Unmarshal(jsonPayload, &doc); err != nil {
		return fmt.Errorf("decode production targets json %s: %w", path, err)
	}
	schema, err := getCompiledSchema()
	if err != nil {
		return fmt.Errorf("compile production target schema: %w", err)
	}
	if err := schema.Validate(doc); err != nil {
		return fmt.Errorf("validate production targets %s: %w", path, err)
	}
	return nil
}

func getCompiledSchema() (*jsonschema.Schema, error) {
	compiledSchemaOnce.Do(func() {
		compiler := jsonschema.NewCompiler()
		if err := compiler.AddResource(schemaURL, bytes.NewReader(productionTargetsSchemaJSON)); err != nil {
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
