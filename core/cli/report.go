package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	agginventory "github.com/Clyra-AI/wrkr/core/aggregate/inventory"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/state"
)

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
	pdf := fs.Bool("pdf", false, "write a one-page PDF summary")
	pdfPath := fs.String("pdf-path", "wrkr-report.pdf", "pdf output path")
	topN := fs.Int("top", 5, "number of top findings")
	statePathFlag := fs.String("state", "", "state file path override")

	if err := fs.Parse(args); err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", err.Error(), exitInvalidInput)
	}

	snapshot, err := state.Load(state.ResolvePath(*statePathFlag))
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}
	report := snapshot.RiskReport
	if report == nil {
		generated := risk.Score(snapshot.Findings, *topN, time.Now().UTC().Truncate(time.Second))
		report = &generated
	}

	top := selectTopFindings(*report, *topN)
	totalTools, typeBreakdown := inventorySummary(snapshot.Inventory)
	complianceGapCount := profileGapCount(snapshot)
	payload := map[string]any{
		"status":               "ok",
		"generated_at":         report.GeneratedAt,
		"top_findings":         top,
		"total_tools":          totalTools,
		"tool_type_breakdown":  typeBreakdown,
		"compliance_gap_count": complianceGapCount,
	}

	if *pdf {
		resolvedPDFPath := strings.TrimSpace(*pdfPath)
		if resolvedPDFPath == "" {
			return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "--pdf-path must not be empty", exitInvalidInput)
		}
		lines := buildPDFSummaryLines(report.GeneratedAt, totalTools, typeBreakdown, complianceGapCount, top)
		if err := writeReportPDF(resolvedPDFPath, lines); err != nil {
			return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
		}
		payload["pdf_path"] = filepath.Clean(resolvedPDFPath)
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	if *explain {
		_, _ = fmt.Fprintf(stdout, "wrkr report top=%d tools=%d compliance_gaps=%d\n", len(top), totalTools, complianceGapCount)
		for idx, item := range top {
			reasons := strings.Join(item.Reasons, ", ")
			_, _ = fmt.Fprintf(stdout, "%d. %.2f %s [%s] %s\n", idx+1, item.Score, item.Finding.FindingType, item.Finding.Location, reasons)
		}
		if *pdf {
			_, _ = fmt.Fprintf(stdout, "pdf: %s\n", filepath.Clean(strings.TrimSpace(*pdfPath)))
		}
		return exitSuccess
	}
	if *pdf {
		_, _ = fmt.Fprintf(stdout, "wrkr report complete (pdf=%s)\n", filepath.Clean(strings.TrimSpace(*pdfPath)))
		return exitSuccess
	}
	_, _ = fmt.Fprintln(stdout, "wrkr report complete")
	return exitSuccess
}

func selectTopFindings(report risk.Report, requested int) []risk.ScoredFinding {
	source := report.TopN
	if len(source) == 0 && len(report.Ranked) > 0 {
		source = report.Ranked
	}
	if requested >= 0 && requested > len(source) && len(report.Ranked) > len(source) {
		source = report.Ranked
	}
	if requested < 0 {
		return append([]risk.ScoredFinding(nil), source...)
	}
	if requested > len(source) {
		requested = len(source)
	}
	return append([]risk.ScoredFinding(nil), source[:requested]...)
}

func inventorySummary(inv *agginventory.Inventory) (int, []map[string]any) {
	if inv == nil {
		return 0, []map[string]any{}
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
	breakdown := make([]map[string]any, 0, len(keys))
	for _, toolType := range keys {
		breakdown = append(breakdown, map[string]any{
			"tool_type": toolType,
			"count":     byType[toolType],
		})
	}
	return len(inv.Tools), breakdown
}

func profileGapCount(snapshot state.Snapshot) int {
	if snapshot.Profile == nil {
		return 0
	}
	return len(snapshot.Profile.Fails)
}

func buildPDFSummaryLines(generatedAt string, totalTools int, typeBreakdown []map[string]any, complianceGapCount int, top []risk.ScoredFinding) []string {
	lines := []string{
		"Wrkr Board Summary",
		fmt.Sprintf("Generated: %s", generatedAt),
		fmt.Sprintf("Total AI tools: %d", totalTools),
		"Tool breakdown:",
	}
	for _, item := range typeBreakdown {
		toolType, _ := item["tool_type"].(string)
		count, _ := item["count"].(int)
		lines = append(lines, fmt.Sprintf("- %s: %d", toolType, count))
	}
	lines = append(lines, fmt.Sprintf("Compliance gaps: %d", complianceGapCount))
	lines = append(lines, "Top risks:")
	for idx, item := range top {
		lines = append(lines, fmt.Sprintf("%d) %.2f %s %s", idx+1, item.Score, item.Finding.FindingType, item.Finding.Location))
	}
	return lines
}
