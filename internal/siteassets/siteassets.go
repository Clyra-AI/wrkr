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
	"strconv"
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

type publishedIDMaps struct {
	Path     map[string]string
	Repo     map[string]string
	Location map[string]string
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
	if err := os.MkdirAll(outputDir, 0o750); err != nil {
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
	redactedReport, err := os.ReadFile(redactedReportPath) // #nosec G304 -- path is derived from the Build temp dir, not caller-controlled input.
	if err != nil {
		return AssetSet{}, fmt.Errorf("read redacted markdown asset: %w", err)
	}

	summary := requireObject(publicBOMPayload, "summary")
	agentActionBOM := requireObject(publicBOMPayload, "agent_action_bom")
	publishedIDs := buildPublishedIDMaps(cloneArray(agentActionBOM["items"]))
	controlPathGraph := requireObject(reportEvidencePayload, "control_path_graph")
	controlBacklog := requireObject(reportEvidencePayload, "control_backlog")
	evidenceProof := requireObject(reportEvidencePayload, "proof")
	sourcePrivacy := requireObject(evidencePayload, "source_privacy")

	files := map[string][]byte{}
	files[AgentActionBOMFilename], err = marshalJSON(normalizePublishedValue(projectAgentActionBOM(agentActionBOM, publishedIDs)))
	if err != nil {
		return AssetSet{}, fmt.Errorf("marshal %s: %w", AgentActionBOMFilename, err)
	}
	files[ControlPathGraphFilename], err = marshalJSON(normalizePublishedValue(projectControlPathGraph(controlPathGraph)))
	if err != nil {
		return AssetSet{}, fmt.Errorf("marshal %s: %w", ControlPathGraphFilename, err)
	}
	files[RedactedReportFilename] = normalizePublishedMarkdown(redactedReport)
	files[LabDataFilename], err = marshalJSON(normalizePublishedValue(buildLabData(scanPayload, publicBOMPayload, summary, controlBacklog, evidenceProof, publishedIDs)))
	if err != nil {
		return AssetSet{}, fmt.Errorf("marshal %s: %w", LabDataFilename, err)
	}
	files[ArchitectureBoundaryFilename], err = marshalJSON(normalizePublishedValue(buildBoundaryData(scanPayload, summary, evidencePayload, sourcePrivacy)))
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

func buildLabData(scanPayload, reportPayload, summary, controlBacklog, proof map[string]any, ids publishedIDMaps) labData {
	exampleSelectionKeyByRawPathID, projectedPathIDsByExampleSelectionKey := buildExecutiveRollupExampleProjectionMaps(cloneArray(requireObject(requireObject(reportPayload, "agent_action_bom"), "items")))
	return labData{
		DeploymentMode:        stringValue(reportPayload["deployment_mode"]),
		ExecutiveRollup:       projectExecutiveRollup(requireObject(summary, "executive_rollup"), ids, exampleSelectionKeyByRawPathID, projectedPathIDsByExampleSelectionKey),
		GovernedUsageMetrics:  cloneObject(requireObject(summary, "governed_usage_metrics")),
		ToolTypeBreakdown:     cloneArray(scanPayload["tool_type_breakdown"]),
		TopFindings:           projectTopFindings(limitArray(cloneArray(reportPayload["top_findings"]), 5)),
		TopActionPaths:        projectTopActionPaths(limitArray(cloneArray(reportPayload["action_paths"]), 5), ids),
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

func projectAgentActionBOM(agentActionBOM map[string]any, ids publishedIDMaps) map[string]any {
	summary := requireObject(agentActionBOM, "summary")
	items := cloneArray(agentActionBOM["items"])
	projectedItems := make([]map[string]any, 0, len(items))
	exampleSelectionKeyByRawPathID, projectedPathIDsByExampleSelectionKey := buildExecutiveRollupExampleProjectionMaps(items)
	for _, raw := range items {
		row := requireObjectFromAny(raw)
		repoID, pathID, locationID := publishedIDsForRow(row)
		projectedItems = append(projectedItems, map[string]any{
			"path_id":                    pathID,
			"repo":                       repoID,
			"location":                   locationID,
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
	sort.Slice(projectedItems, func(i, j int) bool {
		left := stringValue(projectedItems[i]["path_id"])
		right := stringValue(projectedItems[j]["path_id"])
		if left != right {
			return left < right
		}
		return stringValue(projectedItems[i]["location"]) < stringValue(projectedItems[j]["location"])
	})
	projectedItemsAny := make([]any, len(projectedItems))
	for idx, item := range projectedItems {
		projectedItemsAny[idx] = item
	}
	projectedSummary := map[string]any{
		"total_items":              summary["total_items"],
		"control_first_items":      summary["control_first_items"],
		"standing_privilege_items": summary["standing_privilege_items"],
		"runtime_proven_items":     summary["runtime_proven_items"],
		"coverage_confidence":      summary["coverage_confidence"],
		"scan_coverage":            summary["scan_coverage"],
		"delegation_readiness":     summary["delegation_readiness"],
		"executive_rollup":         projectExecutiveRollup(requireObject(summary, "executive_rollup"), ids, exampleSelectionKeyByRawPathID, projectedPathIDsByExampleSelectionKey),
		"governed_usage_metrics":   summary["governed_usage_metrics"],
		"primary_view":             projectPrimaryView(requireObject(summary, "primary_view"), ids),
	}
	fingerprint := map[string]any{
		"schema_version": agentActionBOM["schema_version"],
		"summary":        projectedSummary,
		"items":          projectedItemsAny,
	}
	return map[string]any{
		"bom_id":         stableOpaqueID("bom", fingerprint),
		"schema_version": agentActionBOM["schema_version"],
		"summary":        projectedSummary,
		"items":          projectedItemsAny,
	}
}

func buildExecutiveRollupExampleProjectionMaps(items []any) (map[string]string, map[string][]string) {
	exampleSelectionKeyByRawPathID := map[string]string{}
	projectedPathIDsByExampleSelectionKey := map[string][]string{}
	for _, raw := range items {
		row := requireObjectFromAny(raw)
		rawPathID := stringValue(row["path_id"])
		if rawPathID == "" {
			continue
		}
		_, pathID, _ := publishedIDsForRow(row)
		if pathID == "" {
			continue
		}
		selectionKey := executiveRollupExampleSelectionKey(row)
		if selectionKey == "" {
			continue
		}
		exampleSelectionKeyByRawPathID[rawPathID] = selectionKey
		projectedPathIDsByExampleSelectionKey[selectionKey] = append(projectedPathIDsByExampleSelectionKey[selectionKey], pathID)
	}
	return exampleSelectionKeyByRawPathID, projectedPathIDsByExampleSelectionKey
}

func projectControlPathGraph(graph map[string]any) map[string]any {
	out := cloneObject(graph)
	pathIDMap := projectControlPathGraphPathIDs(cloneArray(graph["nodes"]), cloneArray(graph["edges"]))
	nodes := projectControlPathGraphNodes(cloneArray(graph["nodes"]), pathIDMap)
	nodeIDMap := map[string]string{}
	projectedNodes := make([]any, 0, len(nodes))
	assignControlPathNodeIDs(nodes, nodeIDMap)
	for _, node := range nodes {
		projectedNodes = append(projectedNodes, node.row)
	}
	out["nodes"] = projectedNodes
	out["edges"] = projectControlPathGraphEdges(cloneArray(graph["edges"]), pathIDMap, nodeIDMap)
	return out
}

type projectedControlPathNode struct {
	oldID string
	row   map[string]any
}

func projectControlPathGraphPathIDs(nodes []any, edges []any) map[string]string {
	type pathProjection struct {
		oldID       string
		fingerprint string
	}
	paths := map[string]map[string]any{}
	for _, raw := range nodes {
		row := requireObjectFromAny(raw)
		pathID := stringValue(row["path_id"])
		if pathID == "" {
			continue
		}
		item := cloneObject(row)
		delete(item, "node_id")
		delete(item, "path_id")
		paths[pathID] = appendPathFingerprint(paths[pathID], "nodes", item)
	}
	for _, raw := range edges {
		row := requireObjectFromAny(raw)
		pathID := stringValue(row["path_id"])
		if pathID == "" {
			continue
		}
		item := cloneObject(row)
		delete(item, "edge_id")
		delete(item, "path_id")
		delete(item, "from_node_id")
		delete(item, "to_node_id")
		paths[pathID] = appendPathFingerprint(paths[pathID], "edges", item)
	}
	projected := make([]pathProjection, 0, len(paths))
	for oldID, fingerprint := range paths {
		projected = append(projected, pathProjection{oldID: oldID, fingerprint: canonicalJSONKey(fingerprint)})
	}
	sort.Slice(projected, func(i, j int) bool {
		if projected[i].fingerprint != projected[j].fingerprint {
			return projected[i].fingerprint < projected[j].fingerprint
		}
		return projected[i].oldID < projected[j].oldID
	})
	out := map[string]string{}
	for idx, path := range projected {
		out[path.oldID] = ordinalOpaqueID("path", idx+1)
	}
	return out
}

func appendPathFingerprint(current map[string]any, key string, value map[string]any) map[string]any {
	if current == nil {
		current = map[string]any{}
	}
	items := cloneArray(current[key])
	items = append(items, normalizePublishedValue(value))
	sort.Slice(items, func(i, j int) bool {
		return canonicalJSONKey(items[i]) < canonicalJSONKey(items[j])
	})
	current[key] = items
	return current
}

func projectControlPathGraphNodes(items []any, pathIDMap map[string]string) []projectedControlPathNode {
	out := make([]projectedControlPathNode, 0, len(items))
	for _, raw := range items {
		row := cloneObject(requireObjectFromAny(raw))
		oldID := stringValue(row["node_id"])
		if mapped := pathIDMap[stringValue(row["path_id"])]; mapped != "" {
			row["path_id"] = mapped
		}
		out = append(out, projectedControlPathNode{oldID: oldID, row: row})
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].row
		right := out[j].row
		if stringValue(left["path_id"]) != stringValue(right["path_id"]) {
			return stringValue(left["path_id"]) < stringValue(right["path_id"])
		}
		if stringValue(left["kind"]) != stringValue(right["kind"]) {
			return stringValue(left["kind"]) < stringValue(right["kind"])
		}
		if stringValue(left["lineage_segment"]) != stringValue(right["lineage_segment"]) {
			return stringValue(left["lineage_segment"]) < stringValue(right["lineage_segment"])
		}
		if stringValue(left["label"]) != stringValue(right["label"]) {
			return stringValue(left["label"]) < stringValue(right["label"])
		}
		return canonicalJSONKey(controlPathNodeFingerprint(left)) < canonicalJSONKey(controlPathNodeFingerprint(right))
	})
	return out
}

func assignControlPathNodeIDs(nodes []projectedControlPathNode, nodeIDMap map[string]string) {
	for idx := range nodes {
		newID := ordinalOpaqueID("node", idx+1)
		if nodes[idx].oldID != "" {
			nodeIDMap[nodes[idx].oldID] = newID
		}
		nodes[idx].row["node_id"] = newID
		canonicalizePublishedGraphNode(nodes[idx].row, idx+1)
	}
}

func projectControlPathGraphEdges(items []any, pathIDMap map[string]string, nodeIDMap map[string]string) []any {
	out := make([]any, 0, len(items))
	for _, raw := range items {
		row := cloneObject(requireObjectFromAny(raw))
		if mapped := pathIDMap[stringValue(row["path_id"])]; mapped != "" {
			row["path_id"] = mapped
		}
		if mapped := nodeIDMap[stringValue(row["from_node_id"])]; mapped != "" {
			row["from_node_id"] = mapped
		}
		if mapped := nodeIDMap[stringValue(row["to_node_id"])]; mapped != "" {
			row["to_node_id"] = mapped
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		left := requireObjectFromAny(out[i])
		right := requireObjectFromAny(out[j])
		if stringValue(left["path_id"]) != stringValue(right["path_id"]) {
			return stringValue(left["path_id"]) < stringValue(right["path_id"])
		}
		if stringValue(left["kind"]) != stringValue(right["kind"]) {
			return stringValue(left["kind"]) < stringValue(right["kind"])
		}
		if stringValue(left["from_node_id"]) != stringValue(right["from_node_id"]) {
			return stringValue(left["from_node_id"]) < stringValue(right["from_node_id"])
		}
		if stringValue(left["to_node_id"]) != stringValue(right["to_node_id"]) {
			return stringValue(left["to_node_id"]) < stringValue(right["to_node_id"])
		}
		return canonicalJSONKey(controlPathEdgeFingerprint(left)) < canonicalJSONKey(controlPathEdgeFingerprint(right))
	})
	for idx := range out {
		row := requireObjectFromAny(out[idx])
		row["edge_id"] = ordinalOpaqueID("edge", idx+1)
		canonicalizePublishedGraphEdge(row)
	}
	return out
}

func canonicalizePublishedGraphNode(row map[string]any, nodeOrdinal int) {
	pathOrdinal := ordinalFromOpaqueID(stringValue(row["path_id"]))
	if pathOrdinal == 0 {
		pathOrdinal = nodeOrdinal
	}
	canonicalizeGraphString(row, "label", "label", nodeOrdinal)
	canonicalizeGraphString(row, "org", "org", pathOrdinal)
	canonicalizeGraphString(row, "repo", "repo", pathOrdinal)
	canonicalizeGraphString(row, "location", "loc", pathOrdinal)
	canonicalizeGraphString(row, "agent_id", "agent", pathOrdinal)
	canonicalizeGraphString(row, "config_source", "loc", pathOrdinal)
	canonicalizeGraphString(row, "config_fingerprint", "cfg", pathOrdinal)
	canonicalizeGraphStringSlice(row, "evidence_refs", "evidence")
	canonicalizeGraphStringSlice(row, "source_refs", "source")
	canonicalizeGraphStringSlice(row, "attack_path_refs", "attack")
	canonicalizeGraphStringSlice(row, "source_finding_keys", "finding")
}

func canonicalizePublishedGraphEdge(row map[string]any) {
	canonicalizeGraphStringSlice(row, "evidence_refs", "evidence")
	canonicalizeGraphStringSlice(row, "source_refs", "source")
	canonicalizeGraphStringSlice(row, "attack_path_refs", "attack")
	canonicalizeGraphStringSlice(row, "source_finding_keys", "finding")
}

func canonicalizeGraphString(row map[string]any, key string, prefix string, ordinal int) {
	if stringValue(row[key]) == "" {
		return
	}
	row[key] = ordinalOpaqueID(prefix, ordinal)
}

func canonicalizeGraphStringSlice(row map[string]any, key string, prefix string) {
	if _, ok := row[key]; !ok {
		return
	}
	items := cloneArray(row[key])
	out := make([]any, 0, len(items))
	for idx, item := range items {
		if stringValue(item) == "" {
			continue
		}
		out = append(out, ordinalOpaqueID(prefix, idx+1))
	}
	if len(out) == 0 {
		delete(row, key)
		return
	}
	row[key] = out
}

func controlPathNodeFingerprint(row map[string]any) map[string]any {
	return map[string]any{
		"path_id":                    row["path_id"],
		"kind":                       row["kind"],
		"lineage_segment":            row["lineage_segment"],
		"label":                      row["label"],
		"tool_type":                  row["tool_type"],
		"location":                   row["location"],
		"agent_id":                   row["agent_id"],
		"boundary_label":             row["boundary_label"],
		"purpose":                    row["purpose"],
		"purpose_source":             row["purpose_source"],
		"purpose_confidence":         row["purpose_confidence"],
		"version":                    row["version"],
		"version_source":             row["version_source"],
		"config_fingerprint":         row["config_fingerprint"],
		"config_source":              row["config_source"],
		"status":                     row["status"],
		"credential_authority":       row["credential_authority"],
		"authority_bindings":         row["authority_bindings"],
		"mutable_endpoint_semantics": row["mutable_endpoint_semantics"],
	}
}

func controlPathEdgeFingerprint(row map[string]any) map[string]any {
	return map[string]any{
		"path_id":        row["path_id"],
		"kind":           row["kind"],
		"boundary_label": row["boundary_label"],
		"from_node_id":   row["from_node_id"],
		"to_node_id":     row["to_node_id"],
	}
}

func canonicalJSONKey(value any) string {
	payload, _ := json.Marshal(normalizePublishedValue(value))
	return string(payload)
}

func ordinalOpaqueID(prefix string, ordinal int) string {
	return fmt.Sprintf("%s-%06d", prefix, ordinal)
}

func ordinalFromOpaqueID(value string) int {
	_, suffix, ok := strings.Cut(strings.TrimSpace(value), "-")
	if !ok {
		return 0
	}
	ordinal, err := strconv.Atoi(suffix)
	if err != nil {
		return 0
	}
	return ordinal
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
	payload, err := os.ReadFile(path) // #nosec G304 -- helper only reads files materialized under the Build temp dir.
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

func buildPublishedIDMaps(items []any) publishedIDMaps {
	out := publishedIDMaps{
		Path:     map[string]string{},
		Repo:     map[string]string{},
		Location: map[string]string{},
	}
	for _, raw := range items {
		row := requireObjectFromAny(raw)
		repoID, pathID, locationID := publishedIDsForRow(row)
		if rawPathID := stringValue(row["path_id"]); rawPathID != "" {
			out.Path[rawPathID] = pathID
		}
		if rawRepo := stringValue(row["repo"]); rawRepo != "" {
			out.Repo[rawRepo] = repoID
		}
		for _, key := range []string{"location", "config_source"} {
			if rawLocation := stringValue(row[key]); rawLocation != "" {
				out.Location[rawLocation] = locationID
			}
		}
	}
	return out
}

func publishedIDsForRow(row map[string]any) (repoID, pathID, locationID string) {
	stableRepoFingerprint := map[string]any{
		"action_path_type": row["action_path_type"],
		"target_class":     row["target_class"],
		"tool_type":        row["tool_type"],
		"purpose":          row["purpose"],
		"queue":            row["queue"],
		"risk_zone":        row["risk_zone"],
		"confidence_lane":  row["confidence_lane"],
		"autonomy_tier":    row["autonomy_tier"],
	}
	repoID = stableOpaqueID("repo", stableRepoFingerprint)
	stablePathFingerprint := map[string]any{
		"repo":                       repoID,
		"action_path_type":           row["action_path_type"],
		"control_state":              row["control_state"],
		"control_resolution_state":   row["control_resolution_state"],
		"queue":                      row["queue"],
		"risk_zone":                  row["risk_zone"],
		"target_class":               row["target_class"],
		"autonomy_tier":              row["autonomy_tier"],
		"delegation_readiness_state": row["delegation_readiness_state"],
		"approval_evidence_state":    row["approval_evidence_state"],
		"owner_evidence_state":       row["owner_evidence_state"],
		"proof_evidence_state":       row["proof_evidence_state"],
		"runtime_evidence_state":     row["runtime_evidence_state"],
		"confidence_lane":            row["confidence_lane"],
		"evidence_strength":          row["evidence_strength"],
		"recommended_action":         row["recommended_action"],
	}
	pathID = stableOpaqueID("path", stablePathFingerprint)
	locationID = stableOpaqueID("loc", map[string]any{
		"repo":                     repoID,
		"path_id":                  pathID,
		"control_resolution_state": row["control_resolution_state"],
		"action_path_type":         row["action_path_type"],
	})
	return repoID, pathID, locationID
}

func normalizeOpaqueRef(value string, ids publishedIDMaps) string {
	switch {
	case ids.Path[value] != "":
		return ids.Path[value]
	case ids.Repo[value] != "":
		return ids.Repo[value]
	case ids.Location[value] != "":
		return ids.Location[value]
	default:
		return value
	}
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

func projectTopActionPaths(items []any, ids publishedIDMaps) []any {
	projected := make([]any, 0, len(items))
	for _, raw := range items {
		row := requireObjectFromAny(raw)
		repoID, pathID, locationID := publishedIDsForRow(row)
		projected = append(projected, map[string]any{
			"path_id":                  pathID,
			"repo":                     repoID,
			"location":                 locationID,
			"action_path_type":         row["action_path_type"],
			"recommended_action":       row["recommended_action"],
			"control_resolution_state": row["control_resolution_state"],
			"risk_zone":                row["risk_zone"],
			"target_class":             row["target_class"],
		})
	}
	return projected
}

func projectExecutiveRollup(executiveRollup map[string]any, ids publishedIDMaps, exampleSelectionKeyByRawPathID map[string]string, projectedPathIDsByExampleSelectionKey map[string][]string) map[string]any {
	out := cloneObject(executiveRollup)
	groups := cloneArray(executiveRollup["groups"])
	projectedGroups := make([]any, 0, len(groups))
	for _, raw := range groups {
		group := cloneObject(requireObjectFromAny(raw))
		projectedRefStrings := projectExecutiveRollupTopExampleRefs(cloneArray(group["top_example_refs"]), ids, exampleSelectionKeyByRawPathID, projectedPathIDsByExampleSelectionKey)
		projectedRefs := make([]any, 0, len(projectedRefStrings))
		for _, ref := range projectedRefStrings {
			projectedRefs = append(projectedRefs, ref)
		}
		group["top_example_refs"] = projectedRefs
		projectedGroups = append(projectedGroups, group)
	}
	out["groups"] = projectedGroups
	return out
}

func projectExecutiveRollupTopExampleRefs(refs []any, ids publishedIDMaps, exampleSelectionKeyByRawPathID map[string]string, projectedPathIDsByExampleSelectionKey map[string][]string) []string {
	selectionKeys := map[string]struct{}{}
	for _, ref := range refs {
		if key := strings.TrimSpace(exampleSelectionKeyByRawPathID[stringValue(ref)]); key != "" {
			selectionKeys[key] = struct{}{}
		}
	}
	candidateSet := map[string]struct{}{}
	for key := range selectionKeys {
		for _, pathID := range projectedPathIDsByExampleSelectionKey[key] {
			if strings.TrimSpace(pathID) != "" {
				candidateSet[strings.TrimSpace(pathID)] = struct{}{}
			}
		}
	}
	projectedRefStrings := make([]string, 0, len(candidateSet))
	for pathID := range candidateSet {
		projectedRefStrings = append(projectedRefStrings, pathID)
	}
	if len(projectedRefStrings) == 0 {
		for _, ref := range refs {
			projectedRefStrings = append(projectedRefStrings, normalizeOpaqueRef(stringValue(ref), ids))
		}
	}
	sort.Strings(projectedRefStrings)
	if len(projectedRefStrings) > 3 {
		projectedRefStrings = append([]string(nil), projectedRefStrings[:3]...)
	}
	return projectedRefStrings
}

func projectPrimaryView(primaryView map[string]any, ids publishedIDMaps) map[string]any {
	if len(primaryView) == 0 {
		return map[string]any{}
	}
	return map[string]any{
		"path_id":                     normalizeOpaqueRef(stringValue(primaryView["path_id"]), ids),
		"approval_evidence_state":     primaryView["approval_evidence_state"],
		"autonomy_tier":               primaryView["autonomy_tier"],
		"boundary_label":              primaryView["boundary_label"],
		"control_resolution_state":    primaryView["control_resolution_state"],
		"credential_evidence_state":   primaryView["credential_evidence_state"],
		"delegation_readiness_state":  primaryView["delegation_readiness_state"],
		"evidence_completeness_label": primaryView["evidence_completeness_label"],
		"evidence_completeness_score": primaryView["evidence_completeness_score"],
		"owner_evidence_state":        primaryView["owner_evidence_state"],
		"proof_evidence_state":        primaryView["proof_evidence_state"],
		"recommended_action_contract": normalizePublishedValue(primaryView["recommended_action_contract"]),
		"recommended_control":         primaryView["recommended_control"],
		"recommended_governed_path":   normalizePublishedValue(primaryView["recommended_governed_path"]),
		"runtime_evidence_state":      primaryView["runtime_evidence_state"],
		"selection_reason":            primaryView["selection_reason"],
		"target_evidence_state":       primaryView["target_evidence_state"],
		"today_path":                  normalizePublishedValue(primaryView["today_path"]),
		"unresolved_evidence":         normalizePublishedValue(primaryView["unresolved_evidence"]),
	}
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

func normalizePublishedValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = normalizePublishedValue(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for idx, item := range typed {
			out[idx] = normalizePublishedValue(item)
		}
		return out
	case string:
		return strings.ReplaceAll(typed, "\\", "/")
	default:
		return value
	}
}

func executiveRollupExampleSelectionKey(row map[string]any) string {
	fingerprint := map[string]any{
		"action_class":               executiveRollupExampleActionClass(row),
		"action_path_type":           row["action_path_type"],
		"approval_evidence_state":    row["approval_evidence_state"],
		"autonomy_tier":              row["autonomy_tier"],
		"boundary_label":             row["boundary_label"],
		"confidence_lane":            row["confidence_lane"],
		"control_resolution_state":   row["control_resolution_state"],
		"control_state":              row["control_state"],
		"credential_access":          row["credential_access"],
		"credential_authority_ref":   row["credential_authority_ref"],
		"credential_evidence_state":  row["credential_evidence_state"],
		"delegation_readiness_state": row["delegation_readiness_state"],
		"matched_production_targets": arrayLength(row["matched_production_targets"]),
		"owner_evidence_state":       row["owner_evidence_state"],
		"production_write":           row["production_write"],
		"proof_evidence_state":       row["proof_evidence_state"],
		"queue":                      row["queue"],
		"risk_zone":                  row["risk_zone"],
		"runtime_evidence_state":     row["runtime_evidence_state"],
		"target_class":               row["target_class"],
		"target_evidence_state":      row["target_evidence_state"],
	}
	payload, err := json.Marshal(fingerprint)
	if err != nil {
		return ""
	}
	return string(payload)
}

func executiveRollupExampleActionClass(row map[string]any) string {
	values := stringArray(row["action_classes"])
	sort.Strings(values)
	for _, candidate := range []string{"deploy", "write", "repo_write", "admin", "delete", "credential_access"} {
		for _, value := range values {
			if value == candidate {
				return candidate
			}
		}
	}
	switch {
	case boolValue(row["production_write"]):
		return "deploy"
	case boolValue(row["credential_access"]):
		return "credential_access"
	case len(values) > 0:
		return values[0]
	default:
		return "unknown"
	}
}

func stringArray(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text := stringValue(item); text != "" {
			out = append(out, text)
		}
	}
	return out
}
