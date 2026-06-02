package siteassets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/cli"
)

const (
	ScenarioRelPath              = "scenarios/wrkr/scan-mixed-org/repos"
	ManifestFilename             = "site-asset-manifest.json"
	AgentActionBOMFilename       = "sample-agent-action-bom.json"
	ControlPathGraphFilename     = "sample-control-path-graph.json"
	RedactedReportFilename       = "sample-redacted-report.md"
	LabDataFilename              = "interactive-lab-data.json"
	ArchitectureBoundaryFilename = "architecture-boundary.json"
	LocalPrivatePostureFilename  = "local-private-posture.md"
	manifestSchemaVersion        = "v1"
	manifestGeneratorVersion     = "1"
	websiteShareProfile          = "customer-redacted"
	customerRedactedShareProfile = "customer-redacted"
	publicAgentActionBOMTemplate = "agent-action-bom"
	publicExecutiveTemplate      = "ciso"
	evidenceFrameworks           = "eu-ai-act,soc2"
)

var publishedFilenames = []string{
	AgentActionBOMFilename,
	ArchitectureBoundaryFilename,
	ControlPathGraphFilename,
	InteractiveLabDataFilename(),
	LocalPrivatePostureFilename,
	ManifestFilename,
	RedactedReportFilename,
}

type AssetSet struct {
	Files map[string][]byte
}

type manifest struct {
	SchemaVersion    string         `json:"schema_version"`
	GeneratorVersion string         `json:"generator_version"`
	ScenarioPath     string         `json:"scenario_path"`
	Files            []manifestFile `json:"files"`
	Commands         []string       `json:"commands"`
	Notes            []string       `json:"notes"`
}

type manifestFile struct {
	Path         string `json:"path"`
	Description  string `json:"description"`
	ShareProfile string `json:"share_profile,omitempty"`
	Template     string `json:"template,omitempty"`
	SHA256       string `json:"sha256"`
}

type boundaryData struct {
	DeploymentMode string         `json:"deployment_mode"`
	SourcePrivacy  map[string]any `json:"source_privacy"`
	Source         map[string]any `json:"source"`
	Detection      map[string]any `json:"detection"`
	Aggregation    map[string]any `json:"aggregation"`
	Proof          map[string]any `json:"proof"`
}

type labData struct {
	DeploymentMode        string         `json:"deployment_mode"`
	ExecutiveRollup       map[string]any `json:"executive_rollup"`
	GovernedUsageMetrics  map[string]any `json:"governed_usage_metrics"`
	ToolTypeBreakdown     []any          `json:"tool_type_breakdown"`
	TopFindings           []any          `json:"top_findings"`
	TopActionPaths        []any          `json:"top_action_paths"`
	ControlBacklogSummary map[string]any `json:"control_backlog_summary"`
	ProofSummary          map[string]any `json:"proof_summary"`
}

func InteractiveLabDataFilename() string {
	return LabDataFilename
}

func PublishedFilenames() []string {
	out := make([]string, len(publishedFilenames))
	copy(out, publishedFilenames)
	return out
}

func Generate(repoRoot, outputDir string) error {
	assetSet, err := Build(repoRoot)
	if err != nil {
		return err
	}
	outputDir = strings.TrimSpace(outputDir)
	if outputDir == "" {
		return fmt.Errorf("output directory is required")
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}
	for _, name := range PublishedFilenames() {
		payload, ok := assetSet.Files[name]
		if !ok {
			return fmt.Errorf("generated asset %q is missing", name)
		}
		path := filepath.Join(outputDir, name)
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

func Build(repoRoot string) (AssetSet, error) {
	repoRoot = strings.TrimSpace(repoRoot)
	if repoRoot == "" {
		return AssetSet{}, fmt.Errorf("repo root is required")
	}

	tmpDir, err := os.MkdirTemp("", "wrkr-site-assets-")
	if err != nil {
		return AssetSet{}, fmt.Errorf("create temp dir: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	scenarioRoot := filepath.Join(repoRoot, ScenarioRelPath)
	statePath := filepath.Join(tmpDir, "site-assets-state.json")
	reportEvidencePath := filepath.Join(tmpDir, "site-assets-public-evidence.json")
	redactedReportPath := filepath.Join(tmpDir, "site-assets-redacted.md")
	evidenceOutputDir := filepath.Join(tmpDir, "evidence")

	scanPayload, err := runJSON([]string{"scan", "--path", scenarioRoot, "--state", statePath, "--quiet", "--json"})
	if err != nil {
		return AssetSet{}, fmt.Errorf("scan site-asset fixture: %w", err)
	}
	publicBOMPayload, err := runJSON([]string{
		"report",
		"--state", statePath,
		"--template", publicAgentActionBOMTemplate,
		"--share-profile", websiteShareProfile,
		"--json",
	})
	if err != nil {
		return AssetSet{}, fmt.Errorf("build public BOM asset: %w", err)
	}
	if _, err := runJSON([]string{
		"report",
		"--state", statePath,
		"--template", publicExecutiveTemplate,
		"--share-profile", websiteShareProfile,
		"--evidence-json",
		"--evidence-json-path", reportEvidencePath,
		"--json",
	}); err != nil {
		return AssetSet{}, fmt.Errorf("build public evidence asset: %w", err)
	}
	if _, err := runJSON([]string{
		"report",
		"--state", statePath,
		"--template", publicExecutiveTemplate,
		"--share-profile", customerRedactedShareProfile,
		"--md",
		"--md-path", redactedReportPath,
		"--json",
	}); err != nil {
		return AssetSet{}, fmt.Errorf("build redacted markdown asset: %w", err)
	}
	evidencePayload, err := runJSON([]string{
		"evidence",
		"--frameworks", evidenceFrameworks,
		"--state", statePath,
		"--output", evidenceOutputDir,
		"--json",
	})
	if err != nil {
		return AssetSet{}, fmt.Errorf("build evidence posture asset: %w", err)
	}

	reportEvidencePayload, err := readJSONFile(reportEvidencePath)
	if err != nil {
		return AssetSet{}, fmt.Errorf("read public evidence bundle: %w", err)
	}
	redactedReport, err := os.ReadFile(redactedReportPath)
	if err != nil {
		return AssetSet{}, fmt.Errorf("read redacted markdown asset: %w", err)
	}

	summary := requireObject(publicBOMPayload, "summary")
	agentActionBOM := requireObject(publicBOMPayload, "agent_action_bom")
	controlPathGraph := requireObject(reportEvidencePayload, "control_path_graph")
	controlBacklog := requireObject(reportEvidencePayload, "control_backlog")
	evidenceProof := requireObject(reportEvidencePayload, "proof")
	sourcePrivacy := requireObject(evidencePayload, "source_privacy")

	files := map[string][]byte{}
	files[AgentActionBOMFilename], err = marshalJSON(projectAgentActionBOM(agentActionBOM))
	if err != nil {
		return AssetSet{}, fmt.Errorf("marshal %s: %w", AgentActionBOMFilename, err)
	}
	files[ControlPathGraphFilename], err = marshalJSON(controlPathGraph)
	if err != nil {
		return AssetSet{}, fmt.Errorf("marshal %s: %w", ControlPathGraphFilename, err)
	}
	files[RedactedReportFilename] = normalizePublishedMarkdown(redactedReport)
	files[LabDataFilename], err = marshalJSON(buildLabData(scanPayload, publicBOMPayload, summary, controlBacklog, evidenceProof))
	if err != nil {
		return AssetSet{}, fmt.Errorf("marshal %s: %w", LabDataFilename, err)
	}
	files[ArchitectureBoundaryFilename], err = marshalJSON(buildBoundaryData(scanPayload, summary, evidencePayload, sourcePrivacy))
	if err != nil {
		return AssetSet{}, fmt.Errorf("marshal %s: %w", ArchitectureBoundaryFilename, err)
	}
	files[LocalPrivatePostureFilename] = renderLocalPrivatePosture(evidencePayload, sourcePrivacy)

	if err := ValidateFiles(files); err != nil {
		return AssetSet{}, err
	}

	manifestPayload, err := marshalJSON(buildManifest(files))
	if err != nil {
		return AssetSet{}, fmt.Errorf("marshal %s: %w", ManifestFilename, err)
	}
	files[ManifestFilename] = manifestPayload

	return AssetSet{Files: files}, nil
}

func ValidateFiles(files map[string][]byte) error {
	for name, payload := range files {
		text := string(payload)
		forbiddenSubstrings := []string{
			"/Users/",
			"\\Users\\",
			"ghp_",
			"sk_live_",
			"AKIA",
			"-----BEGIN ",
			"proof://",
			"graph://",
			"@acme/",
			"@local/",
		}
		for _, forbidden := range forbiddenSubstrings {
			if strings.Contains(text, forbidden) {
				return fmt.Errorf("generated site asset %s contains forbidden value %q", name, forbidden)
			}
		}
	}
	return nil
}

func buildManifest(files map[string][]byte) manifest {
	entries := []manifestFile{
		{
			Path:         AgentActionBOMFilename,
			Description:  "Customer-redacted Agent Action BOM sample derived from the multi-repo scan fixture.",
			ShareProfile: websiteShareProfile,
			Template:     publicAgentActionBOMTemplate,
			SHA256:       digest(files[AgentActionBOMFilename]),
		},
		{
			Path:         ControlPathGraphFilename,
			Description:  "Customer-redacted Control Path Graph sample for website graph rendering and demos.",
			ShareProfile: websiteShareProfile,
			Template:     publicExecutiveTemplate,
			SHA256:       digest(files[ControlPathGraphFilename]),
		},
		{
			Path:         RedactedReportFilename,
			Description:  "Customer-redacted executive markdown report suitable for public-facing demos.",
			ShareProfile: customerRedactedShareProfile,
			Template:     publicExecutiveTemplate,
			SHA256:       digest(files[RedactedReportFilename]),
		},
		{
			Path:         LabDataFilename,
			Description:  "Interactive lab summary data projected from deterministic report and evidence outputs.",
			ShareProfile: websiteShareProfile,
			Template:     publicExecutiveTemplate,
			SHA256:       digest(files[LabDataFilename]),
		},
		{
			Path:         ArchitectureBoundaryFilename,
			Description:  "Architecture boundary page data derived from source, detection, aggregation, and proof summaries.",
			ShareProfile: websiteShareProfile,
			Template:     publicExecutiveTemplate,
			SHA256:       digest(files[ArchitectureBoundaryFilename]),
		},
		{
			Path:        LocalPrivatePostureFilename,
			Description: "Local/private posture explanation projected from evidence deployment-mode and source-privacy metadata.",
			SHA256:      digest(files[LocalPrivatePostureFilename]),
		},
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Path < entries[j].Path
	})
	return manifest{
		SchemaVersion:    manifestSchemaVersion,
		GeneratorVersion: manifestGeneratorVersion,
		ScenarioPath:     ScenarioRelPath,
		Files:            entries,
		Commands: []string{
			fmt.Sprintf("wrkr scan --path %s --state ./.tmp/site-assets-state.json --quiet --json", ScenarioRelPath),
			fmt.Sprintf("wrkr report --state ./.tmp/site-assets-state.json --template %s --share-profile %s --json", publicAgentActionBOMTemplate, websiteShareProfile),
			fmt.Sprintf("wrkr report --state ./.tmp/site-assets-state.json --template %s --share-profile %s --evidence-json --evidence-json-path ./.tmp/site-assets-public-evidence.json --json", publicExecutiveTemplate, websiteShareProfile),
			fmt.Sprintf("wrkr report --state ./.tmp/site-assets-state.json --template %s --share-profile %s --md --md-path ./.tmp/site-assets-redacted.md --json", publicExecutiveTemplate, customerRedactedShareProfile),
			fmt.Sprintf("wrkr evidence --frameworks %s --state ./.tmp/site-assets-state.json --output ./.tmp/site-assets-evidence --json", evidenceFrameworks),
		},
		Notes: []string{
			"These assets are generated from fake multi-repo fixture data only.",
			"Do not hand-edit generated files; regenerate them from the commands above.",
			"Published outputs must stay free of raw owner handles, proof refs, graph refs, secret-like strings, and machine-local filesystem paths.",
		},
	}
}

func buildBoundaryData(scanPayload, summary, evidencePayload, sourcePrivacy map[string]any) boundaryData {
	return boundaryData{
		DeploymentMode: stringValue(evidencePayload["deployment_mode"]),
		SourcePrivacy: map[string]any{
			"retention_mode":          sourcePrivacy["retention_mode"],
			"materialized_retained":   sourcePrivacy["materialized_source_retained"],
			"raw_source_in_artifacts": sourcePrivacy["raw_source_in_artifacts"],
			"serialized_locations":    sourcePrivacy["serialized_locations"],
			"cleanup_status":          sourcePrivacy["cleanup_status"],
		},
		Source: map[string]any{
			"targets":            arrayLength(scanPayload["targets"]),
			"deployment_mode":    evidencePayload["deployment_mode"],
			"local_private_note": "Wrkr keeps scan data local by default and emits portable, redacted artifacts only when explicitly requested.",
		},
		Detection: map[string]any{
			"total_tools":          scanPayload["total_tools"],
			"tool_type_breakdown":  scanPayload["tool_type_breakdown"],
			"compliance_gap_count": scanPayload["compliance_gap_count"],
		},
		Aggregation: map[string]any{
			"action_paths":             arrayLength(scanPayload["action_paths"]),
			"executive_rollup_groups":  objectInt(summary["executive_rollup"], "total_groups"),
			"governed_metrics_present": summary["governed_usage_metrics"] != nil,
			"control_backlog_items":    objectInt(summary["control_backlog"], "total_items"),
		},
		Proof: map[string]any{
			"chain_present": objectInt(summary["proof"], "record_count") > 0,
			"record_count":  objectInt(summary["proof"], "record_count"),
		},
	}
}

func buildLabData(scanPayload, reportPayload, summary, controlBacklog, proof map[string]any) labData {
	return labData{
		DeploymentMode:        stringValue(reportPayload["deployment_mode"]),
		ExecutiveRollup:       cloneObject(requireObject(summary, "executive_rollup")),
		GovernedUsageMetrics:  cloneObject(requireObject(summary, "governed_usage_metrics")),
		ToolTypeBreakdown:     cloneArray(scanPayload["tool_type_breakdown"]),
		TopFindings:           projectTopFindings(limitArray(cloneArray(reportPayload["top_findings"]), 5)),
		TopActionPaths:        projectTopActionPaths(limitArray(cloneArray(reportPayload["action_paths"]), 5)),
		ControlBacklogSummary: cloneObject(requireObject(controlBacklog, "summary")),
		ProofSummary:          projectProofSummary(proof),
	}
}

func projectProofSummary(proof map[string]any) map[string]any {
	return map[string]any{
		"chain_present": proof["record_count"] != nil && objectInt(proof, "record_count") > 0,
		"record_count":  proof["record_count"],
	}
}

func projectAgentActionBOM(agentActionBOM map[string]any) map[string]any {
	summary := requireObject(agentActionBOM, "summary")
	items := cloneArray(agentActionBOM["items"])
	projectedItems := make([]any, 0, len(items))
	for _, raw := range items {
		row := requireObjectFromAny(raw)
		projectedItems = append(projectedItems, map[string]any{
			"path_id":                    row["path_id"],
			"repo":                       row["repo"],
			"location":                   row["location"],
			"action_path_type":           row["action_path_type"],
			"control_state":              row["control_state"],
			"queue":                      row["queue"],
			"risk_zone":                  row["risk_zone"],
			"target_class":               row["target_class"],
			"autonomy_tier":              row["autonomy_tier"],
			"delegation_readiness_state": row["delegation_readiness_state"],
			"control_resolution_state":   row["control_resolution_state"],
			"approval_evidence_state":    row["approval_evidence_state"],
			"owner_evidence_state":       row["owner_evidence_state"],
			"proof_evidence_state":       row["proof_evidence_state"],
			"runtime_evidence_state":     row["runtime_evidence_state"],
			"confidence_lane":            row["confidence_lane"],
			"evidence_strength":          row["evidence_strength"],
			"recommended_action":         row["recommended_action"],
		})
	}
	projectedSummary := map[string]any{
		"total_items":              summary["total_items"],
		"control_first_items":      summary["control_first_items"],
		"standing_privilege_items": summary["standing_privilege_items"],
		"runtime_proven_items":     summary["runtime_proven_items"],
		"coverage_confidence":      summary["coverage_confidence"],
		"scan_coverage":            summary["scan_coverage"],
		"delegation_readiness":     summary["delegation_readiness"],
		"executive_rollup":         summary["executive_rollup"],
		"governed_usage_metrics":   summary["governed_usage_metrics"],
		"primary_view":             summary["primary_view"],
	}
	fingerprint := map[string]any{
		"schema_version": agentActionBOM["schema_version"],
		"summary":        projectedSummary,
		"items":          projectedItems,
	}
	return map[string]any{
		"bom_id":         stableOpaqueID("bom", fingerprint),
		"schema_version": agentActionBOM["schema_version"],
		"summary":        projectedSummary,
		"items":          projectedItems,
	}
}

func renderLocalPrivatePosture(evidencePayload, sourcePrivacy map[string]any) []byte {
	lines := []string{
		"# Local/Private Data Posture",
		"",
		fmt.Sprintf("- Deployment mode: `%s`", stringValue(evidencePayload["deployment_mode"])),
		"- Default posture: Wrkr keeps source data in the customer environment unless operators explicitly ask for shareable artifacts.",
		fmt.Sprintf("- Source retention: `%s`", stringValue(sourcePrivacy["retention_mode"])),
		fmt.Sprintf("- Materialized source retained: `%t`", boolValue(sourcePrivacy["materialized_source_retained"])),
		fmt.Sprintf("- Raw source serialized into artifacts: `%t`", boolValue(sourcePrivacy["raw_source_in_artifacts"])),
		fmt.Sprintf("- Serialized locations policy: `%s`", stringValue(sourcePrivacy["serialized_locations"])),
		fmt.Sprintf("- Cleanup status: `%s`", stringValue(sourcePrivacy["cleanup_status"])),
		"- Safe publication rule: generated website assets must come from fake fixtures and public-share or redacted report surfaces only.",
		"",
	}
	return []byte(strings.Join(lines, "\n"))
}

func runJSON(args []string) (map[string]any, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := cli.Run(args, &stdout, &stderr); code != 0 {
		return nil, fmt.Errorf("command %v failed with exit %d: %s", args, code, strings.TrimSpace(stderr.String()))
	}
	payload := map[string]any{}
	if err := json.Unmarshal(stdout.Bytes(), &payload); err != nil {
		return nil, fmt.Errorf("parse command output for %v: %w", args, err)
	}
	return payload, nil
}

func readJSONFile(path string) (map[string]any, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if err := json.Unmarshal(payload, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func marshalJSON(value any) ([]byte, error) {
	payload, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(payload, '\n'), nil
}

func normalizePublishedMarkdown(payload []byte) []byte {
	lines := strings.Split(strings.TrimRight(string(payload), "\n"), "\n")
	for idx, line := range lines {
		if strings.HasPrefix(line, "- Generated at: ") {
			lines[idx] = "- Generated at: 2026-01-01T00:00:00Z"
			continue
		}
		lines[idx] = replaceVolatileHeadHash(lines[idx])
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

func replaceVolatileHeadHash(line string) string {
	if strings.Contains(line, "head=sha256:") {
		start := strings.Index(line, "head=sha256:")
		if start >= 0 {
			end := start + len("head=sha256:")
			for end < len(line) {
				ch := line[end]
				if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
					break
				}
				end++
			}
			line = line[:start] + "head=sha256:demo-proof-head" + line[end:]
		}
	}
	if strings.Contains(line, "head_hash=sha256:") {
		start := strings.Index(line, "head_hash=sha256:")
		if start >= 0 {
			end := start + len("head_hash=sha256:")
			for end < len(line) {
				ch := line[end]
				if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
					break
				}
				end++
			}
			line = line[:start] + "head_hash=sha256:demo-proof-head" + line[end:]
		}
	}
	return line
}

func digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func stableOpaqueID(prefix string, value any) string {
	payload, _ := json.Marshal(value)
	sum := sha256.Sum256(payload)
	return prefix + "-" + hex.EncodeToString(sum[:6])
}

func requireObject(value map[string]any, key string) map[string]any {
	nested, ok := value[key].(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return nested
}

func objectInt(value any, key string) int {
	return int(floatValue(requireObjectFromAny(value)[key]))
}

func requireObjectFromAny(value any) map[string]any {
	nested, ok := value.(map[string]any)
	if !ok {
		return map[string]any{}
	}
	return nested
}

func cloneObject(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}

func cloneArray(value any) []any {
	items, ok := value.([]any)
	if !ok {
		return []any{}
	}
	out := make([]any, len(items))
	copy(out, items)
	return out
}

func limitArray(items []any, limit int) []any {
	if len(items) <= limit {
		return items
	}
	out := make([]any, limit)
	copy(out, items[:limit])
	return out
}

func projectTopFindings(items []any) []any {
	projected := make([]any, 0, len(items))
	for _, raw := range items {
		row := requireObjectFromAny(raw)
		finding := requireObjectFromAny(row["finding"])
		projected = append(projected, map[string]any{
			"risk_score":   row["risk_score"],
			"finding_type": finding["finding_type"],
			"severity":     finding["severity"],
			"tool_type":    finding["tool_type"],
			"location":     finding["location"],
		})
	}
	return projected
}

func projectTopActionPaths(items []any) []any {
	projected := make([]any, 0, len(items))
	for _, raw := range items {
		row := requireObjectFromAny(raw)
		projected = append(projected, map[string]any{
			"path_id":                  row["path_id"],
			"repo":                     row["repo"],
			"location":                 row["location"],
			"action_path_type":         row["action_path_type"],
			"recommended_action":       row["recommended_action"],
			"control_resolution_state": row["control_resolution_state"],
			"risk_zone":                row["risk_zone"],
			"target_class":             row["target_class"],
		})
	}
	return projected
}

func stringValue(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func boolValue(value any) bool {
	flag, _ := value.(bool)
	return flag
}

func floatValue(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	default:
		return 0
	}
}

func arrayLength(value any) int {
	items, ok := value.([]any)
	if !ok {
		return 0
	}
	return len(items)
}
