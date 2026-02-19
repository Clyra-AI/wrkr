package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Clyra-AI/wrkr/core/config"
)

func runInit(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)

	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	nonInteractive := fs.Bool("non-interactive", false, "disable prompts and require flags")
	repo := fs.String("repo", "", "default scan target owner/repo")
	org := fs.String("org", "", "default scan target org")
	path := fs.String("path", "", "default scan target local path")
	scanToken := fs.String("scan-token", "", "read-only token for scan profile")
	fixToken := fs.String("fix-token", "", "read-write token for fix profile")
	configPathFlag := fs.String("config", "", "config file path override")

	if err := fs.Parse(args); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}

	configPath, err := config.ResolvePath(*configPathFlag)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	mode, value, err := resolveTarget(*repo, *org, *path)
	if err != nil {
		if !*nonInteractive {
			mode, value, err = promptForTarget(stdout)
		}
		if err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
		}
	}

	if !*nonInteractive {
		reader := bufio.NewReader(os.Stdin)
		if strings.TrimSpace(*scanToken) == "" {
			_, _ = fmt.Fprint(stdout, "Scan token (optional): ")
			line, _ := reader.ReadString('\n')
			*scanToken = strings.TrimSpace(line)
		}
		if strings.TrimSpace(*fixToken) == "" {
			_, _ = fmt.Fprint(stdout, "Fix token (optional): ")
			line, _ := reader.ReadString('\n')
			*fixToken = strings.TrimSpace(line)
		}
	}

	cfg := config.Default()
	cfg.Auth.Scan.Token = strings.TrimSpace(*scanToken)
	cfg.Auth.Fix.Token = strings.TrimSpace(*fixToken)
	cfg.DefaultTarget = config.Target{Mode: mode, Value: strings.TrimSpace(value)}

	if err := config.Save(configPath, cfg); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"status":      "ok",
			"config_path": configPath,
			"default_target": map[string]any{
				"mode":  cfg.DefaultTarget.Mode,
				"value": cfg.DefaultTarget.Value,
			},
			"auth_profiles": map[string]any{
				"scan": map[string]any{"token_configured": cfg.Auth.Scan.Token != ""},
				"fix":  map[string]any{"token_configured": cfg.Auth.Fix.Token != ""},
			},
		})
		return exitSuccess
	}

	_, _ = fmt.Fprintf(stdout, "wrkr init wrote config: %s\n", configPath)
	return exitSuccess
}

func promptForTarget(stdout io.Writer) (config.TargetMode, string, error) {
	reader := bufio.NewReader(os.Stdin)
	_, _ = fmt.Fprint(stdout, "Default target mode (repo|org|path): ")
	modeRaw, _ := reader.ReadString('\n')
	modeRaw = strings.TrimSpace(modeRaw)
	_, _ = fmt.Fprint(stdout, "Default target value: ")
	value, _ := reader.ReadString('\n')
	value = strings.TrimSpace(value)
	mode := config.TargetMode(modeRaw)
	if err := config.ValidateTarget(mode, value); err != nil {
		return "", "", err
	}
	return mode, value, nil
}

func resolveTarget(repo, org, path string) (config.TargetMode, string, error) {
	targets := make([]config.Target, 0, 3)
	if strings.TrimSpace(repo) != "" {
		targets = append(targets, config.Target{Mode: config.TargetRepo, Value: strings.TrimSpace(repo)})
	}
	if strings.TrimSpace(org) != "" {
		targets = append(targets, config.Target{Mode: config.TargetOrg, Value: strings.TrimSpace(org)})
	}
	if strings.TrimSpace(path) != "" {
		targets = append(targets, config.Target{Mode: config.TargetPath, Value: strings.TrimSpace(path)})
	}

	if len(targets) != 1 {
		return "", "", fmt.Errorf("exactly one target source is required: use one of --repo, --org, --path")
	}
	if err := config.ValidateTarget(targets[0].Mode, targets[0].Value); err != nil {
		return "", "", err
	}
	return targets[0].Mode, targets[0].Value, nil
}
