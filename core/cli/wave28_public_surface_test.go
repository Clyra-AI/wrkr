package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWave28PublicSurfaceAssessmentAppearsInReportJSONAndMarkdown(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	manifestPath := filepath.Join(tmp, "public-surface.yaml")
	if err := os.WriteFile(manifestPath, []byte(`schema_version: v1
name: acme-public
sources:
  - id: repo
    source_class: public_repo
    title: Acme public repo
    public_ref: https://github.com/acme/platform
    evidence_label: public_observed
    confidence: high
    claims:
      - Public repository is visible
  - id: workflow
    source_class: public_workflow
    title: Release workflow
    public_ref: https://github.com/acme/platform/actions/workflows/release.yml
    evidence_label: public_inferred
    confidence: medium
    inference_rationale: Workflow naming implies release automation, but private deployment evidence is still absent.
    claims:
      - Release automation likely exists
  - id: docs
    source_class: public_docs
    title: Security docs
    public_ref: https://docs.acme.example/security
    evidence_label: private_evidence_absent
    confidence: low
    claims:
      - No private approval export was provided
  - id: blog
    source_class: engineering_blog
    title: Engineering blog
    public_ref: https://blog.acme.example/post
    evidence_label: unsupported_public_claim
    confidence: low
    inference_rationale: The public post makes a strong deployment claim without technical public evidence.
    claims:
      - Autonomous deployment approvals are claimed
`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	statePath := filepath.Join(tmp, "state.json")
	var scanOut bytes.Buffer
	var scanErr bytes.Buffer
	code := Run([]string{
		"scan",
		"--target", "public-surface:" + manifestPath,
		"--state", statePath,
		"--json",
	}, &scanOut, &scanErr)
	if code != 0 {
		t.Fatalf("expected public-surface scan to succeed, got %d stderr=%s", code, scanErr.String())
	}

	var reportOut bytes.Buffer
	var reportErr bytes.Buffer
	mdPath := filepath.Join(tmp, "public-surface.md")
	code = Run([]string{
		"report",
		"--state", statePath,
		"--template", "public",
		"--md",
		"--md-path", mdPath,
		"--json",
	}, &reportOut, &reportErr)
	if code != 0 {
		t.Fatalf("expected public-surface report to succeed, got %d stderr=%s", code, reportErr.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(reportOut.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	summary, ok := payload["summary"].(map[string]any)
	if !ok {
		t.Fatalf("expected summary payload, got %T", payload["summary"])
	}
	assessment, ok := summary["public_surface_assessment"].(map[string]any)
	if !ok {
		t.Fatalf("expected public_surface_assessment, got %T", summary["public_surface_assessment"])
	}
	if assessment["total_sources"] != float64(4) {
		t.Fatalf("expected four public sources, got %v", assessment["total_sources"])
	}
	labelCounts, ok := assessment["label_counts"].(map[string]any)
	if !ok {
		t.Fatalf("expected label_counts object, got %T", assessment["label_counts"])
	}
	for key, want := range map[string]float64{
		"public_observed":          1,
		"public_inferred":          1,
		"unsupported_public_claim": 1,
		"private_evidence_absent":  1,
	} {
		if labelCounts[key] != want {
			t.Fatalf("expected label_counts[%s]=%v, got %v", key, want, labelCounts[key])
		}
	}

	markdown, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("read markdown: %v", err)
	}
	rendered := string(markdown)
	for _, needle := range []string{
		"## Public-Surface Assessment",
		"public observed fact",
		"public inferred context",
		"unsupported public claim",
		"private evidence absent",
		"does not verify private runtime, approval, credential, or control state",
	} {
		if !strings.Contains(rendered, needle) {
			t.Fatalf("expected markdown to contain %q, got:\n%s", needle, rendered)
		}
	}
}

func TestWave28PublicSurfaceScanRejectsUnsupportedSourceClass(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	manifestPath := filepath.Join(tmp, "public-surface.yaml")
	if err := os.WriteFile(manifestPath, []byte(`schema_version: v1
name: acme-public
sources:
  - id: bad
    source_class: unknown_surface
    public_ref: https://example.com
    evidence_label: public_observed
    confidence: high
    claims:
      - Unsupported source class
`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--target", "public-surface:" + manifestPath, "--json"}, &out, &errOut)
	if code != exitInvalidInput {
		t.Fatalf("expected exit %d, got %d stderr=%s", exitInvalidInput, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "invalid_input", exitInvalidInput)
}

func TestWave28PublicSurfaceScanRejectsUnsafeCapturePath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	manifestPath := filepath.Join(tmp, "public-surface.yaml")
	if err := os.WriteFile(manifestPath, []byte(`schema_version: v1
name: acme-public
sources:
  - id: bad
    source_class: public_docs
    public_ref: https://docs.acme.example/security
    evidence_label: public_observed
    confidence: high
    capture_path: ../private.json
    claims:
      - Unsafe local capture path
`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{"scan", "--target", "public-surface:" + manifestPath, "--json"}, &out, &errOut)
	if code != exitUnsafeBlocked {
		t.Fatalf("expected exit %d, got %d stderr=%s", exitUnsafeBlocked, code, errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "unsafe_operation_blocked", exitUnsafeBlocked)
}
