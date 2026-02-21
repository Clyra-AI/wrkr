package cli

import (
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
	"github.com/Clyra-AI/wrkr/core/manifest"
	"github.com/Clyra-AI/wrkr/core/regress"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

type reportPayload struct {
	Status             string               `json:"status"`
	GeneratedAt        string               `json:"generated_at"`
	TopFindings        []risk.ScoredFinding `json:"top_findings"`
	TotalTools         int                  `json:"total_tools"`
	ToolTypeBreakdown  []toolTypeCount      `json:"tool_type_breakdown"`
	ComplianceGapCount int                  `json:"compliance_gap_count"`
	Summary            reportcore.Summary   `json:"summary"`
	MDPath             string               `json:"md_path,omitempty"`
	PDFPath            string               `json:"pdf_path,omitempty"`
}

type toolTypeCount struct {
	ToolType string `json:"tool_type"`
	Count    int    `json:"count"`
}

func runReport(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	explain := fs.Bool("explain", false, "emit rationale")
	pdf := fs.Bool("pdf", false, "write a deterministic PDF summary")
	pdfPath := fs.String("pdf-path", "wrkr-report.pdf", "pdf output path")
	md := fs.Bool("md", false, "write a deterministic markdown summary")
	mdPath := fs.String("md-path", "wrkr-report.md", "markdown output path")
	templateRaw := fs.String("template", string(reportcore.TemplateOperator), "report template [exec|operator|audit|public]")
	shareProfileRaw := fs.String("share-profile", string(reportcore.ShareProfileInternal), "share profile [internal|public]")
	topN := fs.Int("top", 5, "number of top findings")
	statePathFlag := fs.String("state", "", "state file path override")
	baselinePath := fs.String("baseline", "", "optional regress baseline for drift summary")
	previousStatePath := fs.String("previous-state", "", "optional previous state for risk trend delta")

	if err := fs.Parse(args); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "report does not accept positional arguments", exitInvalidInput)
	}

	template, shareProfile, parseErr := parseReportTemplateShare(*templateRaw, *shareProfileRaw)
	if parseErr != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", parseErr.Error(), exitInvalidInput)
	}

	resolvedStatePath := state.ResolvePath(*statePathFlag)
	snapshot, err := state.Load(resolvedStatePath)
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	var previousSnapshot *state.Snapshot
	if strings.TrimSpace(*previousStatePath) != "" {
		loaded, loadErr := state.Load(strings.TrimSpace(*previousStatePath))
		if loadErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", loadErr.Error(), exitRuntime)
		}
		previousSnapshot = &loaded
	}

	var baseline *regress.Baseline
	var regressResult *regress.Result
	if strings.TrimSpace(*baselinePath) != "" {
		loadedBaseline, loadErr := regress.LoadBaseline(strings.TrimSpace(*baselinePath))
		if loadErr != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", loadErr.Error(), exitRuntime)
		}
		comparison := regress.Compare(loadedBaseline, snapshot)
		baseline = &loadedBaseline
		regressResult = &comparison
	}

	var loadedManifest *manifest.Manifest
	manifestPath := manifest.ResolvePath(resolvedStatePath)
	if m, loadErr := manifest.Load(manifestPath); loadErr == nil {
		loadedManifest = &m
	}

	summary, mdOutPath, pdfOutPath, err := generateReportArtifacts(reportArtifactOptions{
		StatePath:        resolvedStatePath,
		Snapshot:         snapshot,
		PreviousSnapshot: previousSnapshot,
		Baseline:         baseline,
		RegressResult:    regressResult,
		Manifest:         loadedManifest,
		Top:              *topN,
		Template:         template,
		ShareProfile:     shareProfile,
		WriteMarkdown:    *md,
		MarkdownPath:     *mdPath,
		WritePDF:         *pdf,
		PDFPath:          *pdfPath,
	})
	if err != nil {
		if isArtifactPathError(err) {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
		}
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	riskReport := snapshot.RiskReport
	if riskReport == nil {
		generated := risk.Score(snapshot.Findings, *topN, parseReportGeneratedAt(summary.GeneratedAt))
		riskReport = &generated
	}
	top := reportcore.SelectTopFindings(*riskReport, *topN)
	if shareProfile == reportcore.ShareProfilePublic {
		top = reportcore.PublicSanitizeFindings(top)
	}

	totalTools, typeBreakdown := inventorySummary(snapshot.Inventory)
	payload := reportPayload{
		Status:             "ok",
		GeneratedAt:        summary.GeneratedAt,
		TopFindings:        top,
		TotalTools:         totalTools,
		ToolTypeBreakdown:  typeBreakdown,
		ComplianceGapCount: profileGapCount(snapshot),
		Summary:            summary,
	}

	payload.MDPath = mdOutPath
	payload.PDFPath = pdfOutPath

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	if *explain {
		_, _ = fmt.Fprintf(stdout, "wrkr report template=%s share_profile=%s top=%d score=%.2f grade=%s\n", summary.Template, summary.ShareProfile, len(top), summary.Headline.Score, summary.Headline.Grade)
		if payload.MDPath != "" {
			_, _ = fmt.Fprintf(stdout, "md: %s\n", payload.MDPath)
		}
		if payload.PDFPath != "" {
			_, _ = fmt.Fprintf(stdout, "pdf: %s\n", payload.PDFPath)
		}
		return exitSuccess
	}
	if payload.MDPath != "" || payload.PDFPath != "" {
		_, _ = fmt.Fprintln(stdout, "wrkr report complete")
		return exitSuccess
	}
	_, _ = fmt.Fprintln(stdout, "wrkr report complete")
	return exitSuccess
}

func parseReportGeneratedAt(raw string) time.Time {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(raw))
	if err == nil {
		return parsed.UTC().Truncate(time.Second)
	}
	return time.Now().UTC().Truncate(time.Second)
}

func inventorySummary(inv *agginventory.Inventory) (int, []toolTypeCount) {
	if inv == nil {
		return 0, []toolTypeCount{}
	}
	byType := map[string]int{}
	for _, tool := range inv.Tools {
		byType[tool.ToolType]++
	}
	keys := make([]string, 0, len(byType))
	for toolType := range byType {
		keys = append(keys, toolType)
	}
	sort.Strings(keys)
	breakdown := make([]toolTypeCount, 0, len(keys))
	for _, toolType := range keys {
		breakdown = append(breakdown, toolTypeCount{ToolType: toolType, Count: byType[toolType]})
	}
	return len(inv.Tools), breakdown
}

func profileGapCount(snapshot state.Snapshot) int {
	if snapshot.Profile == nil {
		return 0
	}
	return len(snapshot.Profile.Fails)
}

func resolveArtifactOutputPath(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("artifact output path must not be empty")
	}
	clean := filepath.Clean(trimmed)
	if info, err := os.Lstat(clean); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("artifact output path must not be a symlink: %s", clean)
		}
		if info.IsDir() {
			return "", fmt.Errorf("artifact output path must be a file path, not a directory: %s", clean)
		}
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("stat artifact output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(clean), 0o750); err != nil {
		return "", fmt.Errorf("mkdir artifact output dir: %w", err)
	}
	return clean, nil
}
