package mcpgateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestDetectGatewayPostureProtectedAndUnprotected(t *testing.T) {
	t.Parallel()

	t.Run("protected_with_explicit_rule", func(t *testing.T) {
		t.Parallel()

		root := t.TempDir()
		writeFile(t, root, ".mcp.json", `{"mcpServers":{"alpha":{"command":"npx","args":["-y","alpha@1"]}}}`)
		writeFile(t, root, "mcp-gateway.yaml", "gateway:\n  default_action: deny\n  rules:\n    - name: alpha\n      action: allow\n")

		findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "svc", Root: root}, detect.Options{})
		if err != nil {
			t.Fatalf("detect gateway posture: %v", err)
		}
		posture := mustFindPostureFinding(t, findings)
		if coverage := evidenceValue(posture, "coverage"); coverage != CoverageProtected {
			t.Fatalf("expected protected coverage, got %q", coverage)
		}
		if reason := evidenceValue(posture, "reason_code"); reason != reasonExplicitAllow {
			t.Fatalf("expected explicit allow reason, got %q", reason)
		}
	})

	t.Run("unprotected_with_default_allow", func(t *testing.T) {
		t.Parallel()

		root := t.TempDir()
		writeFile(t, root, ".mcp.json", `{"mcpServers":{"alpha":{"command":"npx","args":["-y","alpha@1"]}}}`)
		writeFile(t, root, "mcp-gateway.yaml", "gateway:\n  default_action: allow\n")

		findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "svc", Root: root}, detect.Options{})
		if err != nil {
			t.Fatalf("detect gateway posture: %v", err)
		}
		posture := mustFindPostureFinding(t, findings)
		if coverage := evidenceValue(posture, "coverage"); coverage != CoverageUnprotected {
			t.Fatalf("expected unprotected coverage, got %q", coverage)
		}
		if reason := evidenceValue(posture, "reason_code"); reason != reasonDefaultAllow {
			t.Fatalf("expected default allow reason, got %q", reason)
		}
	})
}

func TestDetectGatewayAmbiguousConfigFailsClosed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".mcp.json", `{"mcpServers":{"alpha":{"command":"npx","args":["-y","alpha@1"]}}}`)
	writeFile(t, root, "mcp-gateway.yaml", "gateway:\n  default_action: deny\n")
	writeFile(t, root, "mcpgateway.yaml", "gateway:\n  default_action: allow\n")

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect gateway posture: %v", err)
	}

	parseErrorCount := 0
	for _, finding := range findings {
		if finding.FindingType == "parse_error" {
			parseErrorCount++
		}
	}
	if parseErrorCount == 0 {
		t.Fatal("expected parse_error finding for ambiguous gateway config")
	}
	posture := mustFindPostureFinding(t, findings)
	if coverage := evidenceValue(posture, "coverage"); coverage != CoverageUnknown {
		t.Fatalf("expected unknown coverage when policy is ambiguous, got %q", coverage)
	}
	if reason := evidenceValue(posture, "reason_code"); reason != reasonPolicyAmbiguous {
		t.Fatalf("expected policy ambiguous reason code, got %q", reason)
	}
}

func TestEvaluateCoverageNoGatewayContext(t *testing.T) {
	t.Parallel()

	result := EvaluateCoverage(Policy{}, "alpha")
	if result.Coverage != CoverageUnknown {
		t.Fatalf("expected unknown coverage without gateway context, got %q", result.Coverage)
	}
	if result.ReasonCode != reasonNoContext {
		t.Fatalf("expected no-context reason code, got %q", result.ReasonCode)
	}
}

func mustFindPostureFinding(t *testing.T, findings []model.Finding) model.Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.FindingType == "mcp_gateway_posture" {
			return finding
		}
	}
	t.Fatalf("expected mcp_gateway_posture finding, got %#v", findings)
	return model.Finding{}
}

func evidenceValue(finding model.Finding, key string) string {
	for _, item := range finding.Evidence {
		if item.Key == key {
			return item.Value
		}
	}
	return ""
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}
