package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

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
	payload := map[string]any{
		"status":       "ok",
		"generated_at": report.GeneratedAt,
		"top_findings": top,
	}

	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}
	if *explain {
		_, _ = fmt.Fprintf(stdout, "wrkr report top=%d\n", len(top))
		for idx, item := range top {
			reasons := strings.Join(item.Reasons, ", ")
			_, _ = fmt.Fprintf(stdout, "%d. %.2f %s [%s] %s\n", idx+1, item.Score, item.Finding.FindingType, item.Finding.Location, reasons)
		}
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
