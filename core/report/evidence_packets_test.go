package report

import (
	"encoding/json"
	"testing"

	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/risk"
)

func TestBuildAgentActionBOMCarriesEvidencePacketProjection(t *testing.T) {
	t.Parallel()

	bom := BuildAgentActionBOM(Summary{
		ActionPaths: []risk.ActionPath{{
			PathID:             "apc-release-1",
			Org:                "acme",
			Repo:               "acme/payments",
			ToolType:           "compiled_action",
			Location:           ".github/workflows/release.yml",
			EvidencePacketRefs: []string{"pkt-1"},
		}},
		EvidencePackets: &ingest.EvidencePacketSummary{
			Correlations: []ingest.EvidencePacketCorrelation{{
				PacketID:             "pkt-1",
				PathID:               "apc-release-1",
				Status:               ingest.CorrelationStatusMatched,
				Result:               "complete",
				MissingEvidenceState: "complete",
			}},
		},
	})
	if bom == nil || len(bom.Items) != 1 {
		t.Fatalf("expected one BOM item, got %+v", bom)
	}
	if bom.Items[0].EvidencePacketStatus != ingest.CorrelationStatusMatched || bom.Items[0].EvidencePacketResult != "complete" {
		t.Fatalf("expected evidence packet projection on BOM item, got %+v", bom.Items[0])
	}
	if len(bom.Items[0].EvidencePacketRefs) != 1 || bom.Items[0].EvidencePacketRefs[0] != "pkt-1" {
		t.Fatalf("expected packet refs on BOM item, got %+v", bom.Items[0])
	}
}

func TestRenderEvidenceBundleJSONIncludesEvidencePackets(t *testing.T) {
	t.Parallel()

	payload, err := RenderEvidenceBundleJSON(Summary{
		GeneratedAt:  "2026-05-26T15:00:00Z",
		Template:     string(TemplateAgentActionBOM),
		ShareProfile: string(ShareProfileInternal),
		EvidencePackets: &ingest.EvidencePacketSummary{
			TotalPackets:   1,
			MatchedPackets: 1,
			Correlations: []ingest.EvidencePacketCorrelation{{
				PacketID: "pkt-1",
				PathID:   "apc-release-1",
				Status:   ingest.CorrelationStatusMatched,
			}},
		},
	})
	if err != nil {
		t.Fatalf("render evidence bundle: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("parse evidence bundle: %v", err)
	}
	if _, ok := decoded["evidence_packets"].(map[string]any); !ok {
		t.Fatalf("expected evidence_packets in bundle, got %T", decoded["evidence_packets"])
	}
}
