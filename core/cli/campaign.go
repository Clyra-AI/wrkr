package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/source"
	"gopkg.in/yaml.v3"
)

func runCampaign(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 0 {
		return emitError(stderr, wantsJSONOutput(args), "invalid_input", "campaign subcommand is required", exitInvalidInput)
	}
	if isHelpFlag(args[0]) {
		_, _ = fmt.Fprintln(stderr, "Usage of wrkr campaign: campaign <aggregate> [flags]")
		return exitSuccess
	}
	switch args[0] {
	case "aggregate":
		return runCampaignAggregate(args[1:], stdout, stderr)
	default:
		return emitError(stderr, wantsJSONOutput(args), "invalid_input", "unsupported campaign subcommand", exitInvalidInput)
	}
}

type campaignScanArtifact struct {
	Status          string                       `json:"status"`
	PartialResult   bool                         `json:"partial_result,omitempty"`
	SourceDegraded  bool                         `json:"source_degraded,omitempty"`
	SourceErrors    []source.RepoFailure         `json:"source_errors,omitempty"`
	Target          source.Target                `json:"target"`
	SourceManifest  source.Manifest              `json:"source_manifest"`
	Inventory       *agginventory.Inventory      `json:"inventory,omitempty"`
	PrivilegeBudget agginventory.PrivilegeBudget `json:"privilege_budget"`
	Findings        []source.Finding             `json:"findings"`
}

func runCampaignAggregate(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("campaign aggregate", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	inputGlob := fs.String("input-glob", "", "glob for scan --json artifacts")
	outputPath := fs.String("output", "", "optional output path for campaign artifact JSON")
	md := fs.Bool("md", false, "write a campaign markdown artifact")
	mdPath := fs.String("md-path", "wrkr-campaign-public.md", "campaign markdown output path")
	template := fs.String("template", "public", "campaign render template [public]")
	segmentMetadataPath := fs.String("segment-metadata", "", "optional segment metadata policy (YAML)")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "campaign aggregate does not accept positional arguments", exitInvalidInput)
	}

	glob := strings.TrimSpace(*inputGlob)
	if glob == "" {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--input-glob is required", exitInvalidInput)
	}
	paths, err := filepath.Glob(glob)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", fmt.Sprintf("invalid --input-glob: %v", err), exitInvalidInput)
	}
	if len(paths) == 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", fmt.Sprintf("no scan artifacts matched %q", glob), exitInvalidInput)
	}
	sort.Strings(paths)

	inputs := make([]reportcore.CampaignScanInput, 0, len(paths))
	for _, scanPath := range paths {
		// #nosec G304 -- scan artifact paths come from explicit user glob input.
		payload, readErr := os.ReadFile(scanPath)
		if readErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("read scan artifact %s: %v", scanPath, readErr), exitRuntime)
		}
		var raw map[string]any
		if err := json.Unmarshal(payload, &raw); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", fmt.Sprintf("parse scan artifact %s: %v", scanPath, err), exitInvalidInput)
		}
		var parsed campaignScanArtifact
		if err := json.Unmarshal(payload, &parsed); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", fmt.Sprintf("parse scan artifact %s: %v", scanPath, err), exitInvalidInput)
		}
		if artifactErr := validateCampaignScanArtifact(scanPath, raw, parsed); artifactErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", artifactErr.Error(), exitInvalidInput)
		}
		inputs = append(inputs, reportcore.CampaignScanInput{
			Path:            filepath.ToSlash(filepath.Clean(scanPath)),
			Target:          parsed.Target,
			SourceManifest:  parsed.SourceManifest,
			Inventory:       parsed.Inventory,
			PrivilegeBudget: parsed.PrivilegeBudget,
			Findings:        parsed.Findings,
		})
	}

	segmentMetadata, metadataErr := loadCampaignSegmentMetadata(strings.TrimSpace(*segmentMetadataPath))
	if metadataErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", metadataErr.Error(), exitInvalidInput)
	}
	artifact := reportcore.AggregateCampaignWithOptions(inputs, time.Now().UTC().Truncate(time.Second), reportcore.CampaignOptions{
		SegmentMetadata: segmentMetadata,
	})
	artifact.InputGlob = glob
	envelope := map[string]any{
		"status":   "ok",
		"campaign": artifact,
	}

	if strings.TrimSpace(*outputPath) != "" {
		resolved, resolveErr := resolveArtifactOutputPath(*outputPath)
		if resolveErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", resolveErr.Error(), exitInvalidInput)
		}
		payload, marshalErr := json.MarshalIndent(artifact, "", "  ")
		if marshalErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", marshalErr.Error(), exitRuntime)
		}
		payload = append(payload, '\n')
		if writeErr := os.WriteFile(resolved, payload, 0o600); writeErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("write campaign artifact: %v", writeErr), exitRuntime)
		}
		envelope["output_path"] = resolved
	}
	if *md {
		if strings.TrimSpace(*template) != "public" {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--template must be public", exitInvalidInput)
		}
		resolvedMDPath, resolveErr := resolveArtifactOutputPath(*mdPath)
		if resolveErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", resolveErr.Error(), exitInvalidInput)
		}
		markdown := reportcore.RenderCampaignPublicMarkdown(artifact)
		if err := os.WriteFile(resolvedMDPath, []byte(markdown), 0o600); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", fmt.Sprintf("write campaign markdown: %v", err), exitRuntime)
		}
		envelope["md_path"] = resolvedMDPath
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(envelope)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr campaign aggregate complete (%d scans)\n", artifact.Methodology.ScanCount)
	return exitSuccess
}

func validateCampaignScanArtifact(scanPath string, raw map[string]any, parsed campaignScanArtifact) error {
	if strings.TrimSpace(parsed.Status) != "ok" {
		return fmt.Errorf("scan artifact %s status must be ok", scanPath)
	}
	incompleteReasons := make([]string, 0, 3)
	if parsed.PartialResult {
		incompleteReasons = append(incompleteReasons, "partial_result=true")
	}
	if parsed.SourceDegraded {
		incompleteReasons = append(incompleteReasons, "source_degraded=true")
	}
	if len(parsed.SourceErrors) > 0 {
		incompleteReasons = append(incompleteReasons, fmt.Sprintf("source_errors=%d", len(parsed.SourceErrors)))
	}
	if len(incompleteReasons) > 0 {
		return fmt.Errorf("scan artifact %s must be complete; found %s", scanPath, strings.Join(incompleteReasons, ", "))
	}
	if err := validateCampaignTargetObject(scanPath, "target", raw["target"]); err != nil {
		return err
	}
	sourceManifest, ok := raw["source_manifest"].(map[string]any)
	if !ok {
		return fmt.Errorf("scan artifact %s missing source_manifest object", scanPath)
	}
	if err := validateCampaignTargetObject(scanPath, "source_manifest.target", sourceManifest["target"]); err != nil {
		return err
	}
	if repos, ok := sourceManifest["repos"].([]any); !ok || repos == nil {
		return fmt.Errorf("scan artifact %s missing source_manifest.repos array", scanPath)
	}
	if _, ok := raw["inventory"].(map[string]any); !ok {
		return fmt.Errorf("scan artifact %s missing inventory object", scanPath)
	}
	if _, ok := raw["privilege_budget"].(map[string]any); !ok {
		return fmt.Errorf("scan artifact %s missing privilege_budget object", scanPath)
	}
	if _, ok := raw["findings"].([]any); !ok {
		return fmt.Errorf("scan artifact %s missing findings array", scanPath)
	}
	return nil
}

func validateCampaignTargetObject(scanPath string, label string, value any) error {
	target, ok := value.(map[string]any)
	if !ok {
		return fmt.Errorf("scan artifact %s missing %s object", scanPath, label)
	}
	mode, _ := target["mode"].(string)
	if strings.TrimSpace(mode) == "" {
		return fmt.Errorf("scan artifact %s missing %s.mode", scanPath, label)
	}
	rawValue, _ := target["value"].(string)
	if campaignTargetRequiresValue(mode) && strings.TrimSpace(rawValue) == "" {
		return fmt.Errorf("scan artifact %s missing %s.value", scanPath, label)
	}
	return nil
}

func campaignTargetRequiresValue(mode string) bool {
	switch strings.TrimSpace(mode) {
	case "my_setup", source.TargetModeMulti:
		return false
	default:
		return true
	}
}

type campaignSegmentMetadataFile struct {
	SchemaVersion string                        `yaml:"schema_version"`
	Orgs          map[string]campaignSegmentOrg `yaml:"orgs"`
}

type campaignSegmentOrg struct {
	Industry string `yaml:"industry"`
	SizeBand string `yaml:"size_band"`
}

func loadCampaignSegmentMetadata(path string) (map[string]reportcore.SegmentMetadata, error) {
	if strings.TrimSpace(path) == "" {
		return map[string]reportcore.SegmentMetadata{}, nil
	}
	// #nosec G304 -- explicit user-provided metadata file path.
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read segment metadata %s: %w", path, err)
	}
	var cfg campaignSegmentMetadataFile
	decoder := yaml.NewDecoder(bytes.NewReader(payload))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse segment metadata %s: %w", path, err)
	}
	if strings.ToLower(strings.TrimSpace(cfg.SchemaVersion)) != "v1" {
		return nil, fmt.Errorf("segment metadata schema_version must be v1")
	}
	out := map[string]reportcore.SegmentMetadata{}
	for org, item := range cfg.Orgs {
		normalizedOrg := strings.ToLower(strings.TrimSpace(org))
		if normalizedOrg == "" {
			continue
		}
		industry := strings.ToLower(strings.TrimSpace(item.Industry))
		if !validIndustry(industry) {
			return nil, fmt.Errorf("segment metadata org %s has unsupported industry %q", org, item.Industry)
		}
		sizeBand := strings.ToLower(strings.TrimSpace(item.SizeBand))
		if !validSizeBand(sizeBand) {
			return nil, fmt.Errorf("segment metadata org %s has unsupported size_band %q", org, item.SizeBand)
		}
		out[normalizedOrg] = reportcore.SegmentMetadata{
			Industry: industry,
			SizeBand: sizeBand,
		}
	}
	return out, nil
}

func validIndustry(in string) bool {
	switch in {
	case "fintech", "healthcare", "public_sector", "education", "unknown":
		return true
	default:
		return false
	}
}

func validSizeBand(in string) bool {
	switch in {
	case "small", "medium", "large", "unknown":
		return true
	default:
		return false
	}
}
