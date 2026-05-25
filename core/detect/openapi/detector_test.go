package openapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
	detectortest "github.com/Clyra-AI/wrkr/internal/testutil/detectors"
)

func TestOpenAPITargetClassHintAddsCustomerDataSignal(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeOpenAPITestFile(t, root, "openapi.yaml", `
openapi: 3.1.0
info:
  title: Payments API
  version: 1.0.0
paths:
  /v1/payments:
    post:
      summary: Create payment
      operationId: createPayment
      responses:
        "200":
          description: ok
  /v1/refunds/{id}:
    post:
      summary: Issue refund
      operationId: issueRefund
      responses:
        "200":
          description: ok
  /v1/balance:
    get:
      summary: Read balance
      operationId: readBalance
      responses:
        "200":
          description: ok
`)

	findings := detectortest.RunFixture(t, root, "local", "payments", New())
	if len(findings) == 0 {
		t.Fatal("expected openapi detector findings")
	}

	joined := strings.Join(mutableEndpointEvidence(findings), "\n")
	for _, want := range []string{
		"payment|high|openapi|POST /v1/payments",
		"refund|high|openapi|POST /v1/refunds/{id}",
		"read|high|openapi|GET /v1/balance",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected mutable endpoint evidence %q in findings, got %q", want, joined)
		}
	}
	if !strings.Contains(strings.Join(targetClassHints(findings), "\n"), "customer_data_adjacent") {
		t.Fatalf("expected openapi detector target class hint, got %+v", findings)
	}
}

func writeOpenAPITestFile(t *testing.T, root, rel, content string) {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func mutableEndpointEvidence(findings []model.Finding) []string {
	out := []string{}
	for _, finding := range findings {
		for _, evidence := range finding.Evidence {
			if evidence.Key == "mutable_endpoint_semantic" && evidence.Value != "" {
				out = append(out, evidence.Value)
			}
		}
	}
	return out
}

func targetClassHints(findings []model.Finding) []string {
	out := []string{}
	for _, finding := range findings {
		for _, evidence := range finding.Evidence {
			if evidence.Key == "target_class_hint" && evidence.Value != "" {
				out = append(out, evidence.Value)
			}
		}
	}
	return out
}
