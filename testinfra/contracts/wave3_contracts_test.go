package contracts

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/ingest"
)

func TestWave3SchemaExamplesValidate(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)

	t.Run("provider provenance sidecar", func(t *testing.T) {
		t.Parallel()

		payload, err := os.ReadFile(filepath.Join(repoRoot, "testinfra", "contracts", "fixtures", "wave3", "pr-mr-provenance.json"))
		if err != nil {
			t.Fatalf("read provenance fixture: %v", err)
		}
		if err := attribution.ValidateProvenanceJSON(payload); err != nil {
			t.Fatalf("provenance fixture must validate: %v", err)
		}
	})

	t.Run("agentic evidence packet sidecar", func(t *testing.T) {
		t.Parallel()

		payload, err := os.ReadFile(filepath.Join(repoRoot, "testinfra", "contracts", "fixtures", "wave3", "agentic-evidence-packets.json"))
		if err != nil {
			t.Fatalf("read evidence packet fixture: %v", err)
		}
		if err := ingest.ValidateEvidencePacketJSON(payload); err != nil {
			t.Fatalf("evidence packet fixture must validate: %v", err)
		}
	})
}

func TestWave3SchemasDeclareProvenancePacketsAndRecentReview(t *testing.T) {
	t.Parallel()

	repoRoot := mustFindRepoRoot(t)

	agentSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "agent-action-bom.schema.json"))
	agentProps := schemaDefinitionProperties(t, agentSchema, "item")
	for _, key := range []string{"evidence_packet_status", "evidence_packet_result", "evidence_packet_missing_evidence_state", "evidence_packet_refs"} {
		if _, ok := agentProps[key].(map[string]any); !ok {
			t.Fatalf("agent action bom schema missing %s: %v", key, agentProps)
		}
	}
	introduced := schemaDefinitionProperties(t, agentSchema, "introducedBy")
	if _, ok := introduced["provenance"].(map[string]any); !ok {
		t.Fatalf("agent action bom introduced_by missing provenance: %v", introduced)
	}

	reportSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "report", "report-summary.schema.json"))
	reportProps := reportSchema["properties"].(map[string]any)
	for _, key := range []string{"evidence_packets", "recent_pr_review"} {
		if _, ok := reportProps[key].(map[string]any); !ok {
			t.Fatalf("report summary schema missing %s: %v", key, reportProps)
		}
	}

	riskSchema := mustReadJSON(t, filepath.Join(repoRoot, "schemas", "v1", "risk", "risk-report.schema.json"))
	riskProps := schemaDefinitionProperties(t, riskSchema, "actionPath")
	if _, ok := riskProps["evidence_packet_status"].(map[string]any); !ok {
		t.Fatalf("risk report actionPath missing evidence_packet_status: %v", riskProps)
	}
}
