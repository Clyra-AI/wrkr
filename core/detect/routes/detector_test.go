package routes

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clyra-AI/wrkr/core/model"
	detectortest "github.com/Clyra-AI/wrkr/internal/testutil/detectors"
)

func TestRouteTargetClassHintAddsCustomerDataSignal(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeRoutesTestFile(t, root, "api/routes.ts", `
import express from "express";
const router = express.Router();

router.delete("/prod/admin/users/:id", deleteUser);
router.get("/v1/health", health);
`)

	findings := detectortest.RunFixture(t, root, "local", "routes", New())
	if len(findings) == 0 {
		t.Fatal("expected route detector findings")
	}

	joined := strings.Join(routeMutableEndpointEvidence(findings), "\n")
	for _, want := range []string{
		"delete|medium|route|DELETE /prod/admin/users/:id",
		"user_admin|medium|route|DELETE /prod/admin/users/:id",
		"production_mutation|medium|route|DELETE /prod/admin/users/:id",
		"read|medium|route|GET /v1/health",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected mutable endpoint evidence %q in findings, got %q", want, joined)
		}
	}
	if !strings.Contains(strings.Join(routeTargetClassHints(findings), "\n"), "customer_data_adjacent") {
		t.Fatalf("expected route detector target class hint, got %+v", findings)
	}
}

func writeRoutesTestFile(t *testing.T, root, rel, content string) {
	t.Helper()

	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(strings.TrimSpace(content)+"\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func routeMutableEndpointEvidence(findings []model.Finding) []string {
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

func routeTargetClassHints(findings []model.Finding) []string {
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
