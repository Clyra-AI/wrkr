package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/evidence"
	reportcore "github.com/Clyra-AI/wrkr/core/report"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestWave6ReportJSONIncludesExecutiveRollupAndGovernedUsageMetrics(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed to seed state: %d", code)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"report",
		"--state", statePath,
		"--template", "agent-action-bom",
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected report to succeed, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary payload, got %T", payload["summary"])
	}
	if _, ok := summary["executive_rollup"].(map[string]any); !ok {
		t.Fatalf("expected summary executive_rollup, got %v", summary["executive_rollup"])
	}
	summaryMetrics, ok := summary["governed_usage_metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary governed_usage_metrics, got %v", summary["governed_usage_metrics"])
	}
	if summaryMetrics["audit_exports"] == nil {
		t.Fatalf("expected audit_exports metric, got %v", summaryMetrics)
	}

	bom, ok := payload["agent_action_bom"].(map[string]any)
	if !ok {
		t.Fatalf("expected top-level agent_action_bom, got %T", payload["agent_action_bom"])
	}
	bomSummary, ok := bom["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected BOM summary, got %T", bom["summary"])
	}
	if _, ok := bomSummary["executive_rollup"].(map[string]any); !ok {
		t.Fatalf("expected BOM executive_rollup, got %v", bomSummary["executive_rollup"])
	}
	if bomSummary["governed_usage_metrics"] == nil {
		t.Fatalf("expected BOM governed_usage_metrics, got %v", bomSummary["governed_usage_metrics"])
	}
}

func TestWave6EvidenceJSONIncludesGovernedUsageMetrics(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed to seed state: %d", code)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"evidence",
		"--state", statePath,
		"--frameworks", "soc2",
		"--output", filepath.Join(tmp, "wrkr-evidence"),
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected evidence to succeed, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse evidence payload: %v", err)
	}
	metrics, ok := payload["governed_usage_metrics"].(map[string]any)
	if !ok {
		t.Fatalf("expected governed_usage_metrics, got %T", payload["governed_usage_metrics"])
	}
	if metrics["audit_exports"] == nil {
		t.Fatalf("expected audit_exports metric, got %v", metrics)
	}
}

func TestBuildEvidenceJSONPayloadCarriesCompositionRefs(t *testing.T) {
	t.Parallel()

	payload := buildEvidenceJSONPayload(evidence.BuildResult{
		OutputDir:            "/tmp/wrkr-evidence",
		Frameworks:           []string{"soc2"},
		ManifestPath:         "/tmp/wrkr-evidence/manifest.json",
		ArtifactManifestPath: "/tmp/wrkr-evidence/artifact-manifest.json",
		ChainPath:            "/tmp/proof-chain.json",
		FrameworkCoverage:    map[string]float64{"soc2": 100},
		CoverageNote:         evidence.CoverageNote{Basis: "evidenced_controls_only"},
		ReportArtifacts:      []string{"/tmp/wrkr-evidence/reports/report-evidence.json"},
		CompositionRefs: []reportcore.CompositionCorrelationRef{{
			CompositionID:              "cap-release-prod",
			ResolutionKey:              "rk-release-prod",
			PathIDs:                    []string{"apc-build", "apc-deploy"},
			WorkflowChainRefs:          []string{"workflow_chain:wfc-release"},
			ProposedActionContractRefs: []string{"pac-release-prod"},
		}},
	}, "/tmp/state.json")

	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	refs, ok := decoded["composition_refs"].([]any)
	if !ok || len(refs) != 1 {
		t.Fatalf("expected top-level composition_refs in evidence payload, got %T %v", decoded["composition_refs"], decoded["composition_refs"])
	}
	ref, ok := refs[0].(map[string]any)
	if !ok {
		t.Fatalf("expected composition_refs entry object, got %T", refs[0])
	}
	if ref["composition_id"] != "cap-release-prod" {
		t.Fatalf("expected composition_id in evidence payload, got %v", ref["composition_id"])
	}
}

func TestBuildEvidenceJSONPayloadBoundsBOMAndPreservesPrimaryPath(t *testing.T) {
	t.Parallel()

	items := make([]reportcore.AgentActionBOMItem, 0, evidenceJSONInlineBOMItemsCap+2)
	compositions := make([]risk.ComposedActionPath, 0, evidenceJSONInlineCompositionsCap+2)
	for idx := 0; idx < evidenceJSONInlineBOMItemsCap+2; idx++ {
		items = append(items, reportcore.AgentActionBOMItem{PathID: fmt.Sprintf("path-%d", idx)})
	}
	for idx := 0; idx < evidenceJSONInlineCompositionsCap+2; idx++ {
		compositions = append(compositions, risk.ComposedActionPath{CompositionID: fmt.Sprintf("composition-%d", idx)})
	}
	primaryPath := items[len(items)-1].PathID
	primaryComposition := compositions[len(compositions)-1].CompositionID
	payload := buildEvidenceJSONPayload(evidence.BuildResult{
		AgentActionBOM: &reportcore.AgentActionBOM{
			Items:               items,
			ComposedActionPaths: compositions,
			Summary: reportcore.AgentActionBOMSummary{
				PrimaryView: &reportcore.AgentActionBOMPrimaryView{
					PathID:        primaryPath,
					CompositionID: primaryComposition,
				},
			},
		},
	}, "/tmp/state.json")

	bom, ok := payload["agent_action_bom"].(*reportcore.AgentActionBOM)
	if !ok || bom == nil {
		t.Fatalf("expected bounded Agent Action BOM, got %T", payload["agent_action_bom"])
	}
	if len(bom.Items) != evidenceJSONInlineBOMItemsCap || !containsBOMPath(bom.Items, primaryPath) {
		t.Fatalf("expected %d-item preview containing primary path %q, got %+v", evidenceJSONInlineBOMItemsCap, primaryPath, bom.Items)
	}
	if len(bom.ComposedActionPaths) != evidenceJSONInlineCompositionsCap {
		t.Fatalf("expected %d-composition preview, got %+v", evidenceJSONInlineCompositionsCap, bom.ComposedActionPaths)
	}
	if bom.ComposedActionPaths[len(bom.ComposedActionPaths)-1].CompositionID != primaryComposition {
		t.Fatalf("expected primary composition %q in preview, got %+v", primaryComposition, bom.ComposedActionPaths)
	}
	suppressed, ok := payload["suppressed_counts"].(*reportcore.SuppressedCounts)
	if !ok || suppressed.AgentActionBOM != 2 || suppressed.ComposedActionPaths != 2 {
		t.Fatalf("expected BOM/composition suppression counts, got %#v", payload["suppressed_counts"])
	}
}
