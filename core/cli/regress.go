package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/regress"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runRegress(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		return emitError(stderr, wantsJSONOutput(args), "invalid_input", "regress subcommand is required", exitInvalidInput)
	}
	if isHelpFlag(args[0]) {
		_, _ = fmt.Fprintln(stderr, "Usage of wrkr regress: regress <init|run> [flags]")
		return exitSuccess
	}

	switch args[0] {
	case "init":
		return runRegressInit(args[1:], stdout, stderr)
	case "run":
		return runRegressRun(args[1:], stdout, stderr)
	default:
		return emitError(stderr, wantsJSONOutput(args), "invalid_input", "unsupported regress subcommand", exitInvalidInput)
	}
}

func runRegressInit(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("regress init", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	baselineScanPath := fs.String("baseline", "", "state snapshot path used to initialize baseline")
	outputPath := fs.String("output", "", "baseline artifact output path")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "regress init does not accept positional arguments", exitInvalidInput)
	}

	scanPath := state.ResolvePath(strings.TrimSpace(*baselineScanPath))
	snapshot, err := state.Load(scanPath)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	baseline := regress.BuildBaseline(snapshot, time.Now().UTC().Truncate(time.Second))
	targetPath := strings.TrimSpace(*outputPath)
	if targetPath == "" {
		targetPath = defaultBaselinePath(scanPath)
	}
	if err := regress.SaveBaseline(targetPath, baseline); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	resolvedPath := filepath.Clean(targetPath)
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(map[string]any{
			"status":        "ok",
			"baseline_path": resolvedPath,
			"tool_count":    len(baseline.Tools),
		})
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr regress baseline initialized %s (%d tools)\n", resolvedPath, len(baseline.Tools))
	return exitSuccess
}

func runRegressRun(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("regress run", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	baselinePath := fs.String("baseline", "", "baseline artifact path")
	statePathFlag := fs.String("state", "", "state file path override")
	summaryMD := fs.Bool("summary-md", false, "emit deterministic markdown drift summary artifact")
	summaryMDPath := fs.String("summary-md-path", "wrkr-regress-summary.md", "regress summary markdown output path")
	reportTemplate := fs.String("template", "operator", "summary template [exec|operator|audit|public]")
	reportShareProfile := fs.String("share-profile", "internal", "summary share profile [internal|public]")
	reportTop := fs.Int("top", 5, "number of top findings included in regress summary artifact")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "regress run does not accept positional arguments", exitInvalidInput)
	}
	if strings.TrimSpace(*baselinePath) == "" {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--baseline is required", exitInvalidInput)
	}

	baseline, err := regress.LoadBaseline(strings.TrimSpace(*baselinePath))
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	resolvedStatePath := state.ResolvePath(*statePathFlag)
	snapshot, err := state.Load(resolvedStatePath)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	result := regress.Compare(baseline, snapshot)
	result.BaselinePath = filepath.Clean(strings.TrimSpace(*baselinePath))
	if *summaryMD {
		template, shareProfile, parseErr := parseReportTemplateShare(*reportTemplate, *reportShareProfile)
		if parseErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", parseErr.Error(), exitInvalidInput)
		}
		var loadedManifest *manifest.Manifest
		manifestPath := manifest.ResolvePath(resolvedStatePath)
		if m, loadErr := manifest.Load(manifestPath); loadErr == nil {
			loadedManifest = &m
		}
		baselineCopy := baseline
		resultCopy := result
		_, mdOutPath, _, summaryErr := generateReportArtifacts(reportArtifactOptions{
			StatePath:     resolvedStatePath,
			Snapshot:      snapshot,
			Baseline:      &baselineCopy,
			RegressResult: &resultCopy,
			Manifest:      loadedManifest,
			Top:           *reportTop,
			Template:      template,
			ShareProfile:  shareProfile,
			WriteMarkdown: true,
			MarkdownPath:  *summaryMDPath,
		})
		if summaryErr != nil {
			if isArtifactPathError(summaryErr) {
				return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", summaryErr.Error(), exitInvalidInput)
			}
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", summaryErr.Error(), exitRuntime)
		}
		result.SummaryMDPath = mdOutPath
	}
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(result)
	} else if result.Drift {
		_, _ = fmt.Fprintf(stdout, "wrkr regress drift detected (%d reasons)\n", result.ReasonCount)
		if result.SummaryMDPath != "" {
			_, _ = fmt.Fprintf(stdout, "regress summary: %s\n", result.SummaryMDPath)
		}
	} else {
		_, _ = fmt.Fprintln(stdout, "wrkr regress no drift")
		if result.SummaryMDPath != "" {
			_, _ = fmt.Fprintf(stdout, "regress summary: %s\n", result.SummaryMDPath)
		}
	}

	if result.Drift {
		return exitRegressionDrift
	}
	return exitSuccess
}

func defaultBaselinePath(scanPath string) string {
	return filepath.Join(filepath.Dir(scanPath), "wrkr-regress-baseline.json")
}
