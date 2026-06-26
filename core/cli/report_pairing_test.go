package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	reportcore "github.com/Clyra-AI/wrkr/core/report"
)

func TestReportPairedShareProfileWritesExternalArtifactsAndPrivateJoinMap(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	mdPath := filepath.Join(tmp, "report.md")
	evidencePath := filepath.Join(tmp, "report-evidence.json")
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
		"--share-profile", "internal",
		"--md",
		"--md-path", mdPath,
		"--evidence-json",
		"--evidence-json-path", evidencePath,
		"--paired-share-profile", "customer-redacted",
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected paired report to succeed, got %d stderr=%s", code, errOut.String())
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	paths, ok := payload["artifact_paths"].(map[string]any)
	if !ok {
		t.Fatalf("expected artifact_paths map, got %T", payload["artifact_paths"])
	}
	required := []string{
		"markdown",
		"markdown_customer_redacted",
		"evidence_json",
		"evidence_json_customer_redacted",
		"private_join_map",
	}
	for _, key := range required {
		path, ok := paths[key].(string)
		if !ok || path == "" {
			t.Fatalf("expected artifact path for %s, got %v", key, paths[key])
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s at %s: %v", key, path, err)
		}
	}
}

func TestPairedArtifactsDoNotLeakOwnerLikeFields(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	evidencePath := filepath.Join(tmp, "report-evidence.json")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed to seed state: %d", code)
	}
	injectNestedOwnerLeakFixture(t, statePath)

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"report",
		"--state", statePath,
		"--share-profile", "internal",
		"--evidence-json",
		"--evidence-json-path", evidencePath,
		"--paired-share-profile", "customer-redacted",
		"--json",
	}, &out, &errOut)
	if code != 0 {
		t.Fatalf("expected paired report to succeed, got %d stderr=%s", code, errOut.String())
	}

	internalBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatalf("read internal evidence artifact: %v", err)
	}
	if !strings.Contains(string(internalBytes), "release-bot") {
		t.Fatalf("expected internal evidence artifact to retain cleartext owner context, got %q", string(internalBytes))
	}

	var payload map[string]any
	if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
		t.Fatalf("parse report payload: %v", err)
	}
	paths, ok := payload["artifact_paths"].(map[string]any)
	if !ok {
		t.Fatalf("expected artifact_paths map, got %T", payload["artifact_paths"])
	}
	externalPath, ok := paths["evidence_json_customer_redacted"].(string)
	if !ok || externalPath == "" {
		t.Fatalf("expected paired redacted evidence path, got %v", paths["evidence_json_customer_redacted"])
	}
	externalBytes, err := os.ReadFile(externalPath)
	if err != nil {
		t.Fatalf("read paired redacted evidence artifact: %v", err)
	}
	for _, forbidden := range []string{
		"release-bot",
		"triage-bot",
		"github.example.com/acme/enterprise-001/pull/108",
		"/Users/example/private/repo",
	} {
		if strings.Contains(string(externalBytes), forbidden) {
			t.Fatalf("expected paired redacted evidence artifact to redact %q, got %q", forbidden, string(externalBytes))
		}
	}
}

func TestReportPairedShareProfilePreflightsExternalArtifactPaths(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	statePath := filepath.Join(tmp, "state.json")
	mdPath := filepath.Join(tmp, "report.md")
	repoRoot := mustFindRepoRoot(t)
	scanPath := filepath.Join(repoRoot, "scenarios", "wrkr", "scan-mixed-org", "repos")
	if code := Run([]string{"scan", "--path", scanPath, "--state", statePath, "--json"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatalf("scan failed to seed state: %d", code)
	}

	externalPath := reportcore.PairedArtifactPath(mdPath, "customer-redacted")
	if err := os.MkdirAll(externalPath, 0o750); err != nil {
		t.Fatalf("mkdir paired artifact blocker: %v", err)
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	code := Run([]string{
		"report",
		"--state", statePath,
		"--share-profile", "internal",
		"--md",
		"--md-path", mdPath,
		"--paired-share-profile", "customer-redacted",
		"--json",
	}, &out, &errOut)
	if code != exitUnsafeBlocked {
		t.Fatalf("expected paired report to fail with exit %d, got %d stdout=%q stderr=%q", exitUnsafeBlocked, code, out.String(), errOut.String())
	}
	assertErrorEnvelopeCode(t, errOut.Bytes(), "unsafe_operation_blocked", exitUnsafeBlocked)
	if _, err := os.Stat(mdPath); !os.IsNotExist(err) {
		t.Fatalf("expected internal artifact write to be skipped on paired preflight failure, got err=%v", err)
	}
}
