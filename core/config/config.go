package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const CurrentVersion = "v1"

// TargetMode identifies the default scan target source.
type TargetMode string

const (
	TargetRepo TargetMode = "repo"
	TargetOrg  TargetMode = "org"
	TargetPath TargetMode = "path"
)

// Target identifies a scan source target.
type Target struct {
	Mode  TargetMode `json:"mode"`
	Value string     `json:"value"`
}

// AuthProfile holds token data for one privilege profile.
type AuthProfile struct {
	Token string `json:"token,omitempty"`
}

// AuthProfiles stores split privileges for scan and fix paths.
type AuthProfiles struct {
	Scan AuthProfile `json:"scan"`
	Fix  AuthProfile `json:"fix"`
}

// Config is the persisted wrkr init configuration.
type Config struct {
	Version       string       `json:"version"`
	Auth          AuthProfiles `json:"auth"`
	DefaultTarget Target       `json:"default_target"`
}

func Default() Config {
	return Config{
		Version: CurrentVersion,
		Auth: AuthProfiles{
			Scan: AuthProfile{},
			Fix:  AuthProfile{},
		},
	}
}

func Validate(cfg Config) error {
	if cfg.Version == "" {
		return errors.New("config version is required")
	}
	if cfg.Version != CurrentVersion {
		return fmt.Errorf("unsupported config version %q", cfg.Version)
	}
	if err := ValidateTarget(cfg.DefaultTarget.Mode, cfg.DefaultTarget.Value); err != nil {
		return err
	}
	return nil
}

func ValidateTarget(mode TargetMode, value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("target value is required")
	}
	switch mode {
	case TargetRepo:
		parts := strings.Split(value, "/")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("repo target must be owner/repo, got %q", value)
		}
	case TargetOrg:
		if strings.Contains(value, "/") {
			return fmt.Errorf("org target must not contain '/': %q", value)
		}
	case TargetPath:
		if strings.TrimSpace(value) == "" {
			return errors.New("path target must be non-empty")
		}
	default:
		return fmt.Errorf("unsupported target mode %q", mode)
	}
	return nil
}

// ResolvePath computes the config path from explicit path, env, or home default.
func ResolvePath(explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return explicit, nil
	}
	if fromEnv := strings.TrimSpace(os.Getenv("WRKR_CONFIG_PATH")); fromEnv != "" {
		return fromEnv, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home: %w", err)
	}
	return filepath.Join(home, ".wrkr", "config.json"), nil
}

// Save writes config deterministically.
func Save(path string, cfg Config) error {
	if err := Validate(cfg); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("mkdir config dir: %w", err)
	}
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// Load reads config from disk.
func Load(path string) (Config, error) {
	// #nosec G304 -- caller controls config path resolution; reading that explicit path is intended.
	payload, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	cfg := Default()
	if err := json.Unmarshal(payload, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
