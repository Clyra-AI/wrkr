package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/attribution"
	"github.com/Clyra-AI/wrkr/core/ingest"
	"github.com/Clyra-AI/wrkr/core/risk"
	"github.com/Clyra-AI/wrkr/core/source"
	"github.com/Clyra-AI/wrkr/core/state"
)

func TestRunIngestAcceptsEvidencePacketBundle(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	if err := state.Save(statePath, state.Snapshot{
		Target: source.Target{Mode: "path"},
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID:   "apc-release-1",
				Repo:     "acme/payments",
				Location: ".github/workflows/release.yml",
				IntroducedBy: &attribution.Result{
					Reference: "pr/42",
					PRNumber:  42,
				},
			}},
		},
	}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	inputPath := filepath.Join(root, "packets.json")
	payload := []byte(`{
  "schema_version": "v1",
  "generated_at": "2026-05-26T15:00:00Z",
  "packets": [
    {
      "source": "review_export",
      "repo": "acme/payments",
      "workflow": ".github/workflows/release.yml",
      "pull_request_ref": "pr/42",
      "observed_at": "2026-05-26T14:59:00Z"
    }
  ]
}`)
	if err := os.WriteFile(inputPath, payload, 0o600); err != nil {
		t.Fatalf("write packet input: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"ingest", "--state", statePath, "--input", inputPath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%s", code, errOut.String())
	}

	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("parse ingest output: %v", err)
	}
	if got["artifact_kind"] != "evidence_packets" {
		t.Fatalf("expected evidence_packets artifact kind, got %v", got["artifact_kind"])
	}
	if _, err := os.Stat(ingest.DefaultEvidencePacketPath(statePath)); err != nil {
		t.Fatalf("expected managed evidence packet artifact: %v", err)
	}
}

func TestRunIngestDoesNotMisclassifyRuntimeEvidenceContainingPacketsString(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	statePath := filepath.Join(root, "state.json")
	if err := state.Save(statePath, state.Snapshot{
		Target: source.Target{Mode: "path"},
		RiskReport: &risk.Report{
			ActionPaths: []risk.ActionPath{{
				PathID: "apc-runtime-1",
				Repo:   "acme/payments",
			}},
		},
	}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	inputPath := filepath.Join(root, "runtime-evidence.json")
	payload := []byte(`{
  "schema_version": "v1",
  "generated_at": "2026-05-26T15:00:00Z",
  "records": [
    {
      "path_id": "apc-runtime-1",
      "source": "packets",
      "observed_at": "2026-05-26T14:59:00Z",
      "evidence_class": "policy_decision"
    }
  ]
}`)
	if err := os.WriteFile(inputPath, payload, 0o600); err != nil {
		t.Fatalf("write runtime evidence input: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"ingest", "--state", statePath, "--input", inputPath, "--json"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected exit 0, got %d stderr=%s", code, errOut.String())
	}

	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("parse ingest output: %v", err)
	}
	if got["artifact_kind"] != nil {
		t.Fatalf("expected runtime evidence path, got %v", got)
	}
	if _, err := os.Stat(ingest.DefaultPath(statePath)); err != nil {
		t.Fatalf("expected managed runtime evidence artifact: %v", err)
	}
}
