package a2a

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Clyra-AI/wrkr/core/detect"
	"github.com/Clyra-AI/wrkr/core/model"
)

func TestDetectA2AAgentCardValid(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".well-known/agent.json", `{"name":"support-agent","capabilities":["search","triage"],"auth_schemes":["oauth2"],"protocols":["http"]}`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect a2a agent cards: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.FindingType != "a2a_agent_card" {
		t.Fatalf("expected a2a_agent_card finding, got %q", finding.FindingType)
	}
	if value := evidenceValue(finding, "agent_name"); value != "support-agent" {
		t.Fatalf("expected normalized agent name support-agent, got %q", value)
	}
}

func TestDetectA2AAgentCardInvalidSchema(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".well-known/agent.json", `{"name":"broken-agent","capabilities":[],"auth_schemes":["oauth2"],"protocols":["http"]}`)

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect a2a agent cards: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected one parse_error finding, got %d", len(findings))
	}
	if findings[0].FindingType != "parse_error" {
		t.Fatalf("expected parse_error finding, got %q", findings[0].FindingType)
	}
	if findings[0].ParseError == nil || findings[0].ParseError.Kind != "schema_validation_error" {
		t.Fatalf("expected schema_validation_error parse error, got %#v", findings[0].ParseError)
	}
}

func TestDetectA2AGatewayCoverageSignal(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeFile(t, root, ".well-known/agent.json", `{"name":"support-agent","capabilities":["search"],"auth_schemes":["oauth2"],"protocols":["http"]}`)
	writeFile(t, root, "mcp-gateway.yaml", "gateway:\n  default_action: allow\n")

	findings, err := New().Detect(context.Background(), detect.Scope{Org: "local", Repo: "svc", Root: root}, detect.Options{})
	if err != nil {
		t.Fatalf("detect a2a agent cards: %v", err)
	}
	finding := mustFindA2AFinding(t, findings)
	if coverage := evidenceValue(finding, "coverage"); coverage != "unprotected" {
		t.Fatalf("expected unprotected coverage with default allow policy, got %q", coverage)
	}
	if finding.Severity != model.SeverityHigh {
		t.Fatalf("expected high severity for unprotected coverage, got %q", finding.Severity)
	}
}

func mustFindA2AFinding(t *testing.T, findings []model.Finding) model.Finding {
	t.Helper()
	for _, finding := range findings {
		if finding.FindingType == "a2a_agent_card" {
			return finding
		}
	}
	t.Fatalf("expected a2a_agent_card finding, got %#v", findings)
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
