package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/lifecycle"
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runLifecycle(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("lifecycle", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}
	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	orgFilter := fs.String("org", "", "filter by org")
	statePathFlag := fs.String("state", "", "state file path override")
	summaryMD := fs.Bool("summary-md", false, "emit deterministic lifecycle markdown summary artifact")
	summaryMDPath := fs.String("summary-md-path", "wrkr-lifecycle-summary.md", "lifecycle summary markdown output path")
	reportTemplate := fs.String("template", "audit", "summary template [exec|operator|audit|public]")
	reportShareProfile := fs.String("share-profile", "internal", "summary share profile [internal|public]")
	reportTop := fs.Int("top", 5, "number of top findings included in lifecycle summary artifact")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}

	resolvedStatePath := state.ResolvePath(*statePathFlag)
	loaded, err := manifest.Load(manifest.ResolvePath(resolvedStatePath))
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	snapshot, snapshotErr := state.Load(resolvedStatePath)
	if snapshotErr != nil && !errors.Is(snapshotErr, iofs.ErrNotExist) {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", snapshotErr.Error(), exitRuntime)
	}
	loaded.Identities = model.FilterLegacyArtifactIdentityRecords(loaded.Identities)

	identities := make([]manifest.IdentityRecord, 0, len(loaded.Identities))
	for _, item := range loaded.Identities {
		if strings.TrimSpace(*orgFilter) != "" && item.Org != strings.TrimSpace(*orgFilter) {
			continue
		}
		identities = append(identities, item)
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].AgentID < identities[j].AgentID })

	summaryOutPath := ""
	if *summaryMD {
		template, shareProfile, parseErr := parseReportTemplateShare(*reportTemplate, *reportShareProfile)
		if parseErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", parseErr.Error(), exitInvalidInput)
		}
		manifestCopy := loaded
		artifacts, summaryErr := generateReportArtifacts(reportArtifactOptions{
			StatePath:     resolvedStatePath,
			Snapshot:      snapshot,
			Manifest:      &manifestCopy,
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
		summaryOutPath = artifacts.MarkdownPath
	}

	payload := map[string]any{
		"status":     "ok",
		"updated_at": loaded.UpdatedAt,
		"org":        strings.TrimSpace(*orgFilter),
		"identities": identities,
		"gaps":       lifecycleGapsForCLI(snapshot),
	}
	if summaryOutPath != "" {
		payload["summary_md_path"] = summaryOutPath
	}
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	_, _ = fmt.Fprintf(stdout, "wrkr lifecycle identities=%d\n", len(identities))
	if summaryOutPath != "" {
		_, _ = fmt.Fprintf(stdout, "lifecycle summary: %s\n", summaryOutPath)
	}
	return exitSuccess
}

func lifecycleGapsForCLI(snapshot state.Snapshot) []lifecycle.Gap {
	if len(snapshot.LifecycleGaps) > 0 {
		return snapshot.LifecycleGaps
	}
	return lifecycle.DetectGaps(lifecycle.GapInput{
		Identities:  snapshot.Identities,
		Inventory:   snapshot.Inventory,
		Transitions: snapshot.Transitions,
	})
}
