package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/state"
)

func runMCPList(args []string, stdout io.Writer, stderr io.Writer) int {
	jsonRequested := wantsJSONOutput(args)
	fs := flag.NewFlagSet("mcp-list", flag.ContinueOnError)
	if jsonRequested {
		fs.SetOutput(io.Discard)
	} else {
		fs.SetOutput(stderr)
	}

	jsonOut := fs.Bool("json", false, "emit machine-readable output")
	statePathFlag := fs.String("state", "", "state file path override")
	gaitTrustPath := fs.String("gait-trust", "", "optional local Gait trust overlay path")
	repoFilter := fs.String("repo", "", "optional repo filter")
	expectedServer := fs.String("expect-server", "", "optional expected MCP server name for miss diagnostics")

	if code, handled := parseFlags(fs, args, stderr, jsonRequested || *jsonOut); handled {
		return code
	}
	if fs.NArg() != 0 {
		return emitError(stderr, jsonRequested || *jsonOut, "invalid_input", "mcp-list does not accept positional arguments", exitInvalidInput)
	}

	snapshot, err := state.Load(state.ResolvePath(*statePathFlag))
	if err != nil {
		return emitError(stderr, jsonRequested || *jsonOut, "runtime_failure", err.Error(), exitRuntime)
	}

	expectedServers := []string{}
	if strings.TrimSpace(*expectedServer) != "" {
		expectedServers = append(expectedServers, strings.TrimSpace(*expectedServer))
	}
	payload := reportcore.BuildMCPListWithOptions(snapshot, reportcore.MCPListOptions{
		GeneratedAt:         reportcore.ResolveGeneratedAtForCLI(snapshot, time.Time{}),
		OverlayPath:         *gaitTrustPath,
		AllowAmbientOverlay: true,
		RepoFilter:          *repoFilter,
		ExpectedServers:     expectedServers,
	})
	if *jsonOut {
		_ = json.NewEncoder(stdout).Encode(payload)
		return exitSuccess
	}

	if len(payload.Rows) == 0 {
		_, _ = fmt.Fprintln(stdout, renderMCPAbsenceLine(payload))
		if strings.TrimSpace(payload.AbsenceImpact) != "" {
			_, _ = fmt.Fprintf(stdout, "coverage impact: %s\n", strings.TrimSpace(payload.AbsenceImpact))
		}
		return exitSuccess
	}

	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SERVER\tTRANSPORT\tTRUST\tPRIVILEGES\tNOTE")
	for _, row := range payload.Rows {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			row.ServerName,
			row.Transport,
			row.TrustStatus,
			strings.Join(row.PrivilegeSurface, ","),
			row.RiskNote,
		)
	}
	_ = tw.Flush()

	for _, warning := range payload.Warnings {
		_, _ = fmt.Fprintln(stderr, warning)
	}
	for _, diagnostic := range payload.Diagnostics {
		label := diagnostic.Repo
		if strings.TrimSpace(diagnostic.ExpectedServer) != "" {
			label = fmt.Sprintf("%s expected=%s", label, diagnostic.ExpectedServer)
		}
		_, _ = fmt.Fprintf(stderr, "mcp-list diagnostic repo=%s status=%s\n", label, diagnostic.Status)
	}
	return exitSuccess
}

func renderMCPAbsenceLine(payload reportcore.MCPList) string {
	switch strings.TrimSpace(payload.AbsenceStatus) {
	case reportcore.MCPTrustUnavailable:
		return "wrkr mcp-list MCP coverage status is unavailable"
	case "not_found_with_complete_coverage":
		return "wrkr mcp-list no MCP servers found (absence_status=not_found_with_complete_coverage)"
	case "candidate_parse_failed":
		return "wrkr mcp-list MCP server evidence not found because candidate surfaces failed to parse (absence_status=candidate_parse_failed)"
	case "unsupported_surface":
		return "wrkr mcp-list MCP server evidence not found on unsupported surfaces (absence_status=unsupported_surface)"
	case "not_found_with_reduced_coverage":
		return "wrkr mcp-list MCP server evidence not found with reduced coverage (absence_status=not_found_with_reduced_coverage)"
	case "not_scanned":
		return "wrkr mcp-list MCP coverage was not scanned, so no absence claim is supported (absence_status=not_scanned)"
	default:
		return "wrkr mcp-list MCP server evidence not found (absence_status=unknown)"
	}
}
