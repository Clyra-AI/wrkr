package openapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/executiontopology"
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

func TestGenericNameSpecIsDiscoveredButOrdinaryJSONIsNot(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeOpenAPITestFile(t, root, "proto-spec/service.json", `{
  "openapi": "3.1.0",
  "paths": {"/v1/accounts": {"delete": {"operationId": "deleteAccount"}}}
}`)
	writeOpenAPITestFile(t, root, "config/settings.json", `{"app_id":"example","private_key":"example"}`)
	findings := detectortest.RunFixture(t, root, "local", "payments", New())
	foundSpec := false
	for _, finding := range findings {
		if finding.Location == "proto-spec/service.json" && finding.FindingType == "openapi_specification" {
			foundSpec = true
		}
		if finding.Location == "config/settings.json" {
			t.Fatalf("ordinary JSON must not enter OpenAPI output: %+v", finding)
		}
	}
	if !foundSpec {
		t.Fatalf("expected generic-name OpenAPI specification, got %+v", findings)
	}
}

func TestLocalSwaggerConsumerIsCorrelatedWithoutPromotingRuntimeProof(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeOpenAPITestFile(t, root, "proto-spec/service.swagger.json", `{"swagger":"2.0","paths":{"/v1/jobs":{"post":{"operationId":"runJob"}}}}`)
	writeOpenAPITestFile(t, root, "ui/swagger-config.js", `window.ui = SwaggerUIBundle({url: "/proto-spec/service.swagger.json"})`)
	findings := detectortest.RunFixture(t, root, "local", "payments", New())
	found := false
	foundTyped := false
	for _, finding := range findings {
		if finding.Location != "proto-spec/service.swagger.json" {
			continue
		}
		for _, evidence := range finding.Evidence {
			if evidence.Key == "spec_consumer_ref" && evidence.Value == "ui/swagger-config.js" {
				found = true
			}
			if evidence.Key == "runtime_evidence_state" {
				t.Fatalf("static consumer must not claim runtime proof: %+v", finding)
			}
		}
		for _, relationship := range finding.ExecutionRelationships {
			if relationship.Kind == "api_spec_consumer" && relationship.Callee == "ui/swagger-config.js" && relationship.ResolutionState == "resolved_local" {
				foundTyped = true
			}
		}
	}
	if !found || !foundTyped {
		t.Fatalf("expected local Swagger consumer correlation, got %+v", findings)
	}
}

func TestConsumerLineageFanoutIsBoundedAndReported(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeOpenAPITestFile(t, root, "proto-spec/service.json", `{"openapi":"3.1.0","paths":{"/v1/jobs":{"post":{"operationId":"runJob"}}}}`)
	for index := 0; index < maxSpecLineageFanout+1; index++ {
		writeOpenAPITestFile(t, root, fmt.Sprintf("ui/%03d/swagger-config.js", index), `SwaggerUIBundle({url: "../../proto-spec/service.json"})`)
	}
	detector := New()
	findings, err := detector.Detect(context.Background(), detect.Scope{Org: "local", Repo: "payments", Root: root}, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.FindingType != "openapi_specification" || finding.Location != "proto-spec/service.json" {
			continue
		}
		consumers := 0
		truncated := false
		for _, relationship := range finding.ExecutionRelationships {
			if relationship.Kind == "api_spec_consumer" {
				consumers++
			}
		}
		for _, evidence := range finding.Evidence {
			truncated = truncated || (evidence.Key == "spec_lineage_state" && evidence.Value == "consumer_fanout_limited:64")
		}
		if consumers != maxSpecLineageFanout || !truncated {
			t.Fatalf("consumer lineage must be bounded with an explicit receipt: consumers=%d finding=%+v", consumers, finding)
		}
		receipts := detector.SurfaceCoverage(detect.Scope{Root: root}, detect.Options{})
		if len(receipts) != 1 || receipts[0].Partial == 0 || receipts[0].Suppressed == 0 || !containsOpenAPIValue(receipts[0].ReasonCodes, "spec_consumer:fanout_limited") {
			t.Fatalf("consumer truncation must reduce scan coverage: %+v", receipts)
		}
		return
	}
	t.Fatalf("expected specification finding: %+v", findings)
}

func TestGeneratorDeclarationIsTypedAndNotTreatedAsRuntimeEvidence(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeOpenAPITestFile(t, root, "build/api/service.json", `{"openapi":"3.1.0","paths":{"/v1/jobs":{"post":{"operationId":"runJob"}}}}`)
	writeOpenAPITestFile(t, root, "tools/openapi-generator-config.json", `{"generatorName":"typescript-fetch","outputSpec":"../build/api/service.json"}`)
	findings := detectortest.RunFixture(t, root, "local", "payments", New())
	for _, finding := range findings {
		if finding.Location != "build/api/service.json" || finding.FindingType != "openapi_specification" {
			continue
		}
		generator, consumer := false, false
		for _, relationship := range finding.ExecutionRelationships {
			generator = generator || (relationship.Kind == "api_spec_generator" && relationship.Caller == "tools/openapi-generator-config.json" && relationship.Callee == "build/api/service.json" && relationship.ResolutionState == "resolved_local")
			consumer = consumer || relationship.Kind == "api_spec_consumer"
		}
		if !generator || consumer {
			t.Fatalf("expected generator-only static relationship, got %+v", finding.ExecutionRelationships)
		}
		for _, evidence := range finding.Evidence {
			if evidence.Key == "runtime_evidence_state" {
				t.Fatalf("generator declaration must not claim runtime proof: %+v", finding)
			}
		}
		return
	}
	t.Fatalf("expected generated specification finding, got %+v", findings)
}

func TestTopologyAddsDeclaredRuntimeRelationshipWithoutRuntimeProof(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeOpenAPITestFile(t, root, "proto-spec/service.json", `{"openapi":"3.1.0","paths":{"/v1/jobs":{"post":{"operationId":"runJob"}}}}`)
	topology := &executiontopology.Topology{Version: 1, Digest: "sha256:test", Mappings: []executiontopology.Mapping{{Kind: "api_runtime", Alias: "proto-spec/service.json", SourceRepo: "acme/runtime", SourcePath: "gateway/service"}}}
	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "payments", Root: root}, detect.Options{ExecutionTopology: topology})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.FindingType != "openapi_specification" {
			continue
		}
		for _, relationship := range finding.ExecutionRelationships {
			if relationship.Kind == "api_runtime" {
				if relationship.ResolutionState != "resolved_declared" || relationship.Origin != "customer_topology" || relationship.Confidence != "medium" {
					t.Fatalf("unexpected runtime relationship: %+v", relationship)
				}
				for _, evidence := range finding.Evidence {
					if evidence.Key == "runtime_evidence_state" {
						t.Fatalf("declared topology must not claim runtime proof: %+v", finding)
					}
				}
				return
			}
		}
	}
	t.Fatalf("expected topology-declared runtime relationship, got %+v", findings)
}

func TestSpecRefsReportLocalRemoteAndCycleStates(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeOpenAPITestFile(t, root, "specs/service.json", `{
  "openapi":"3.1.0",
  "paths":{"/v1/jobs":{"post":{"operationId":"runJob"}}},
  "components":{"schemas":{
    "Local":{"$ref":"models/common.json#/Job"},
    "Remote":{"$ref":"https://schemas.example.test/job.json"}
  }}
}`)
	writeOpenAPITestFile(t, root, "specs/models/common.json", `{"Job":{"$ref":"../service.json#/components/schemas/Local"}}`)
	detector := New()
	findings, err := detector.Detect(context.Background(), detect.Scope{Org: "local", Repo: "payments", Root: root}, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, finding := range findings {
		if finding.FindingType == "openapi_specification" && finding.Location == "specs/service.json" {
			for _, evidence := range finding.Evidence {
				if evidence.Key == "spec_ref_state" {
					joined += evidence.Value + "\n"
				}
			}
		}
	}
	for _, want := range []string{"resolved_local:", "unresolved_remote:", "cycle_blocked:"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing ref state %q in %s", want, joined)
		}
	}
	receipts := detector.SurfaceCoverage(detect.Scope{Root: root}, detect.Options{})
	if len(receipts) != 1 || receipts[0].Resolved == 0 || receipts[0].Unresolved == 0 || receipts[0].Partial == 0 {
		t.Fatalf("expected resolved and unresolved ref coverage, got %+v", receipts)
	}
}

func TestRemoteSpecRefReceiptDoesNotPersistCredentials(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeOpenAPITestFile(t, root, "openapi.json", `{
  "openapi":"3.1.0",
  "paths":{},
  "components":{"schemas":{"Remote":{"$ref":"https://user:supersecret@example.test/schema.json?token=abc123"}}}
}`)
	detector := New()
	findings, err := detector.Detect(context.Background(), detect.Scope{Org: "local", Repo: "payments", Root: root}, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(findings)
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, forbidden := range []string{"supersecret", "abc123", "user:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("remote reference receipt leaked %q: %s", forbidden, text)
		}
	}
	if !strings.Contains(text, "unresolved_remote:sha256:") {
		t.Fatalf("expected non-reversible remote reference receipt, got %s", text)
	}
}

func TestRecognizedGeneratedSpecIsSelectedWithoutDeepMode(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeOpenAPITestFile(t, root, "build/api/service.json", `{"openapi":"3.1.0","paths":{"/v1/jobs":{"post":{"operationId":"runJob"}}}}`)
	detector := New()
	findings, err := detector.Detect(context.Background(), detect.Scope{Org: "local", Repo: "payments", Root: root}, detect.Options{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	foundOrigin := false
	for _, finding := range findings {
		if finding.Location == "build/api/service.json" && finding.FindingType == "openapi_specification" {
			found = true
			for _, evidence := range finding.Evidence {
				if evidence.Key == "spec_origin" && evidence.Value == "generated_selected" {
					foundOrigin = true
				}
			}
		}
	}
	if !found || !foundOrigin {
		t.Fatalf("expected bounded detector-specific generated spec selection, got %+v", findings)
	}
}

func TestGeneratedSpecRecoverySkipsDependencyTrees(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeOpenAPITestFile(t, root, "node_modules/example/dist/openapi.json", `{"openapi":"3.1.0","paths":{"/admin":{"delete":{"operationId":"deleteAdmin"}}}}`)
	writeOpenAPITestFile(t, root, "vendor/example/build/openapi.json", `{"openapi":"3.1.0","paths":{"/admin":{"delete":{"operationId":"deleteAdmin"}}}}`)
	findings := detectortest.RunFixture(t, root, "local", "payments", New())
	if len(findings) != 0 {
		t.Fatalf("dependency-tree generated specs must not enter customer findings: %+v", findings)
	}
}

func TestGeneratedSpecDiscoverySkipsGitMetadataBeforeBudget(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	for index := 0; index < maxGeneratedDiscoveryEntries+8; index++ {
		writeOpenAPITestFile(t, root, fmt.Sprintf(".git/objects/%04d", index), "object")
	}
	writeOpenAPITestFile(t, root, "build/api/service.json", `{"openapi":"3.1.0","paths":{}}`)
	selected, receipt := discoverGeneratedSpecs(root, nil)
	if len(selected) != 1 || selected[0].Rel != "build/api/service.json" || receipt.suppressed != 0 {
		t.Fatalf("VCS metadata must not consume generated discovery budget: selected=%+v receipt=%+v", selected, receipt)
	}
}

func TestConsumerCorrelationUsesFullArtifactPath(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeOpenAPITestFile(t, root, "specs/a/openapi.json", `{"openapi":"3.1.0","paths":{}}`)
	writeOpenAPITestFile(t, root, "specs/b/openapi.json", `{"openapi":"3.1.0","paths":{}}`)
	writeOpenAPITestFile(t, root, "ui/swagger-config.js", `SwaggerUIBundle({url: "../specs/a/openapi.json"})`)
	findings := detectortest.RunFixture(t, root, "local", "payments", New())
	consumers := map[string]int{}
	for _, finding := range findings {
		if finding.FindingType != "openapi_specification" {
			continue
		}
		for _, evidence := range finding.Evidence {
			if evidence.Key == "spec_consumer_ref" {
				consumers[finding.Location]++
			}
		}
	}
	if consumers["specs/a/openapi.json"] != 1 || consumers["specs/b/openapi.json"] != 0 {
		t.Fatalf("consumer must join only to its path-qualified artifact: %+v", consumers)
	}
}

func TestSpecRefTraversalUsesGlobalFileBudget(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	refs := make([]string, 0, maxSpecRefFiles+8)
	for index := 0; index < maxSpecRefFiles+8; index++ {
		name := fmt.Sprintf("models/model-%03d.json", index)
		refs = append(refs, fmt.Sprintf("\"Model%03d\":{\"$ref\":\"%s#/Model\"}", index, name))
		writeOpenAPITestFile(t, root, name, `{"Model":{"type":"string"}}`)
	}
	writeOpenAPITestFile(t, root, "service.json", `{"openapi":"3.1.0","components":{"schemas":{`+strings.Join(refs, ",")+`}},"paths":{}}`)

	receipt := resolveSpecRefs(root, "service.json")
	if receipt.filesRead != maxSpecRefFiles || !receipt.partial || !containsOpenAPIValue(receipt.reasons, "spec_ref:fanout_limited") {
		t.Fatalf("global reference budget was not enforced: %+v", receipt)
	}
}

func TestSpecRefTraversalReportsDocumentReferenceLimit(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	refs := make([]string, 0, 4097)
	for index := 0; index < 4097; index++ {
		refs = append(refs, fmt.Sprintf(`"Ref%04d":{"$ref":"#/components/schemas/Present"}`, index))
	}
	writeOpenAPITestFile(t, root, "service.json", `{"openapi":"3.1.0","components":{"schemas":{"Present":{"type":"string"},`+strings.Join(refs, ",")+`}},"paths":{}}`)
	receipt := resolveSpecRefs(root, "service.json")
	if !receipt.partial || receipt.unresolved == 0 || !containsOpenAPIValue(receipt.reasons, "spec_ref:reference_limit") || !containsOpenAPIValue(receipt.states, "reference_truncated:service.json") {
		t.Fatalf("reference truncation must reduce coverage explicitly: %+v", receipt)
	}
}

func TestMissingLocalSpecRefIsNotReportedResolved(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeOpenAPITestFile(t, root, "service.json", `{"openapi":"3.1.0","components":{"schemas":{"MissingA":{"$ref":"models/missing.json#/MissingA"},"MissingB":{"$ref":"models/missing.json#/MissingB"}}},"paths":{}}`)
	receipt := resolveSpecRefs(root, "service.json")
	if receipt.resolved != 0 || receipt.unresolved == 0 || !containsOpenAPIValue(receipt.states, "unresolved_local:models/missing.json") {
		t.Fatalf("missing local reference must remain unresolved: %+v", receipt)
	}
}

func TestMissingInternalSpecRefFragmentIsUnresolved(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeOpenAPITestFile(t, root, "service.json", `{"openapi":"3.1.0","components":{"schemas":{"Present":{"type":"string"},"Alias":{"$ref":"#/components/schemas/Missing"}}},"paths":{}}`)
	receipt := resolveSpecRefs(root, "service.json")
	if receipt.resolved != 0 || receipt.unresolved != 1 || !receipt.partial || !containsOpenAPIValue(receipt.states, "unresolved_fragment:#/components/schemas/Missing") || !containsOpenAPIValue(receipt.reasons, "spec_ref:missing_fragment") {
		t.Fatalf("missing internal fragment must reduce reference coverage: %+v", receipt)
	}
}

func TestGenericOversizedStructuredFileIsRejectedBeforeParsing(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeOpenAPITestFile(t, root, "large.json", strings.Repeat(" ", (1<<20)+1))
	candidate, parseErr := isOpenAPICandidate(root, "large.json")
	if parseErr != nil || candidate {
		t.Fatalf("oversized generic file must be skipped without parsing: candidate=%v err=%+v", candidate, parseErr)
	}
}

func TestGeneratedSpecDiscoveryRecordsTraversalFailure(t *testing.T) {
	t.Parallel()

	_, receipt := discoverGeneratedSpecs(filepath.Join(t.TempDir(), "missing"), nil)
	if receipt.partial == 0 || !containsOpenAPIValue(receipt.reasons, "generated_spec_discovery:walk_error") {
		t.Fatalf("generated discovery failure must reduce detector coverage: %+v", receipt)
	}
}

func containsOpenAPIValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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
