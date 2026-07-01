package hygiene

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const docsSiteAuditPolicyFixtureToday = "2026-06-15"

func TestDocsSiteAuditPolicyAllowsCurrentModerateException(t *testing.T) {
	t.Parallel()

	repoRoot := writeDocsSiteAuditFixtureRepo(t, fixtureRepoOptions{})
	result := runDocsSiteAuditPolicy(t, repoRoot)

	if result.Status != "pass" {
		t.Fatalf("expected pass, failures=%v", result.Failures)
	}
	if len(result.ActionableAdvisories) != 1 {
		t.Fatalf("expected 1 actionable advisory, got %d", len(result.ActionableAdvisories))
	}
	if len(result.MatchedExceptions) != 1 {
		t.Fatalf("expected 1 matched exception, got %d", len(result.MatchedExceptions))
	}
}

func TestDocsSiteAuditPolicyWarnsBeforeExceptionExpiry(t *testing.T) {
	t.Parallel()

	repoRoot := writeDocsSiteAuditFixtureRepo(t, fixtureRepoOptions{})
	result := runDocsSiteAuditPolicyWithOptions(t, repoRoot, docsSiteAuditRunOptions{
		WarnExpiringWithinDays: 20,
	})

	if result.Status != "pass" {
		t.Fatalf("expected pass, failures=%v", result.Failures)
	}
	if len(result.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(result.Warnings), result.Warnings)
	}
	if !strings.Contains(result.Warnings[0], "expires on 2026-06-30") {
		t.Fatalf("expected expiry warning, got %q", result.Warnings[0])
	}
}

func TestDocsSiteAuditPolicyFailsExpiredException(t *testing.T) {
	t.Parallel()

	repoRoot := writeDocsSiteAuditFixtureRepo(t, fixtureRepoOptions{
		ExceptionExpiry: "2026-05-01",
	})
	_, stderr, err := runDocsSiteAuditPolicyRaw(t, repoRoot)
	if err == nil {
		t.Fatal("expected expired exception validation to fail")
	}
	if !strings.Contains(stderr, "expired on 2026-05-01") {
		t.Fatalf("expected expiry failure, got %s", stderr)
	}
}

func TestDocsSiteAuditPolicyFailsVersionDrift(t *testing.T) {
	t.Parallel()

	repoRoot := writeDocsSiteAuditFixtureRepo(t, fixtureRepoOptions{
		ExceptionCurrentVersion: "16.2.5",
	})
	_, stderr, err := runDocsSiteAuditPolicyRaw(t, repoRoot)
	if err == nil {
		t.Fatal("expected version drift validation to fail")
	}
	if !strings.Contains(stderr, "current_version=16.2.5") {
		t.Fatalf("expected version drift failure, got %s", stderr)
	}
}

func TestDocsSiteAuditPolicyFailsMissingOwnerAndRationale(t *testing.T) {
	t.Parallel()

	repoRoot := writeDocsSiteAuditFixtureRepo(t, fixtureRepoOptions{
		ForceBlankOwner:     true,
		ForceBlankRationale: true,
	})
	_, stderr, err := runDocsSiteAuditPolicyRaw(t, repoRoot)
	if err == nil {
		t.Fatal("expected missing owner/rationale validation to fail")
	}
	if !strings.Contains(stderr, "missing required field 'owner'") {
		t.Fatalf("expected owner validation failure, got %s", stderr)
	}
	if !strings.Contains(stderr, "missing required field 'rationale'") {
		t.Fatalf("expected rationale validation failure, got %s", stderr)
	}
}

func TestDocsSiteAuditPolicyFailsWhenAdvisoryDisappears(t *testing.T) {
	t.Parallel()

	repoRoot := writeDocsSiteAuditFixtureRepo(t, fixtureRepoOptions{
		AuditFixture: emptyDocsSiteAuditFixture(),
	})
	_, stderr, err := runDocsSiteAuditPolicyRaw(t, repoRoot)
	if err == nil {
		t.Fatal("expected stale exception validation to fail")
	}
	if !strings.Contains(stderr, "stale or mismatched docs-site advisory exception") {
		t.Fatalf("expected stale exception failure, got %s", stderr)
	}
}

func TestDocsSiteAuditPolicyAllowsEmptyExceptionsWhenAuditIsClean(t *testing.T) {
	t.Parallel()

	repoRoot := writeDocsSiteAuditFixtureRepo(t, fixtureRepoOptions{
		AuditFixture: emptyDocsSiteAuditFixture(),
		NoExceptions: true,
	})
	result := runDocsSiteAuditPolicy(t, repoRoot)

	if result.Status != "pass" {
		t.Fatalf("expected clean audit with no exceptions to pass, failures=%v", result.Failures)
	}
	if len(result.ActionableAdvisories) != 0 {
		t.Fatalf("expected 0 actionable advisories, got %d", len(result.ActionableAdvisories))
	}
	if len(result.MatchedExceptions) != 0 {
		t.Fatalf("expected 0 matched exceptions, got %d", len(result.MatchedExceptions))
	}
}

type docsSiteAuditPolicyResult struct {
	Status               string              `json:"status"`
	Warnings             []string            `json:"warnings"`
	Failures             []string            `json:"failures"`
	ActionableAdvisories []map[string]string `json:"actionable_advisories"`
	MatchedExceptions    []map[string]string `json:"matched_exceptions"`
}

type docsSiteAuditRunOptions struct {
	Today                  string
	WarnExpiringWithinDays int
}

type fixtureRepoOptions struct {
	AuditFixture            map[string]any
	ExceptionExpiry         string
	ExceptionCurrentVersion string
	ExceptionOwner          string
	ExceptionRationale      string
	ForceBlankOwner         bool
	ForceBlankRationale     bool
	NoExceptions            bool
}

func runDocsSiteAuditPolicy(t *testing.T, repoRoot string) docsSiteAuditPolicyResult {
	t.Helper()

	return runDocsSiteAuditPolicyWithOptions(t, repoRoot, docsSiteAuditRunOptions{})
}

func runDocsSiteAuditPolicyWithOptions(
	t *testing.T,
	repoRoot string,
	opts docsSiteAuditRunOptions,
) docsSiteAuditPolicyResult {
	t.Helper()

	stdout, stderr, err := runDocsSiteAuditPolicyRawWithOptions(t, repoRoot, opts)
	if err != nil {
		t.Fatalf("run docs-site audit policy: %v\nstderr=%s", err, stderr)
	}

	var result docsSiteAuditPolicyResult
	if err := json.Unmarshal([]byte(stdout), &result); err != nil {
		t.Fatalf("parse audit policy json: %v\nstdout=%s", err, stdout)
	}
	return result
}

func runDocsSiteAuditPolicyRaw(t *testing.T, repoRoot string) (string, string, error) {
	t.Helper()

	return runDocsSiteAuditPolicyRawWithOptions(t, repoRoot, docsSiteAuditRunOptions{})
}

func runDocsSiteAuditPolicyRawWithOptions(
	t *testing.T,
	repoRoot string,
	opts docsSiteAuditRunOptions,
) (string, string, error) {
	t.Helper()

	pythonPath, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available in test environment")
	}

	scriptPath := filepath.Join(mustFindRepoRoot(t), "scripts", "validate_docs_site_audit.py")
	auditPath := filepath.Join(repoRoot, "docs-site", "audit.json")
	exceptionsPath := filepath.Join(repoRoot, "docs-site", "security-advisory-exceptions.json")
	lockfilePath := filepath.Join(repoRoot, "docs-site", "package-lock.json")
	today := opts.Today
	if today == "" {
		today = docsSiteAuditPolicyFixtureToday
	}
	args := []string{
		scriptPath,
		"--repo-root", repoRoot,
		"--audit-report", auditPath,
		"--exceptions", exceptionsPath,
		"--lockfile", lockfilePath,
		"--today", today,
		"--json",
	}
	if opts.WarnExpiringWithinDays > 0 {
		args = append(args, "--warn-expiring-within-days", strconv.Itoa(opts.WarnExpiringWithinDays))
	}
	cmd := exec.Command(pythonPath, args...)
	output, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(output))
	if err != nil {
		return "", text, err
	}
	return text, "", nil
}

func writeDocsSiteAuditFixtureRepo(t *testing.T, opts fixtureRepoOptions) string {
	t.Helper()

	repoRoot := t.TempDir()
	docsSiteDir := filepath.Join(repoRoot, "docs-site")
	if err := os.MkdirAll(docsSiteDir, 0o755); err != nil {
		t.Fatalf("mkdir docs-site: %v", err)
	}

	auditFixture := opts.AuditFixture
	if auditFixture == nil {
		auditFixture = currentDocsSiteAuditFixture()
	}
	writeJSONFixture(t, filepath.Join(docsSiteDir, "audit.json"), auditFixture)
	writeJSONFixture(t, filepath.Join(docsSiteDir, "package-lock.json"), docsSiteLockfileFixture())
	writeJSONFixture(t, filepath.Join(docsSiteDir, "security-advisory-exceptions.json"), docsSiteExceptionFixture(opts))

	return repoRoot
}

func writeJSONFixture(t *testing.T, path string, payload any) {
	t.Helper()

	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture %s: %v", path, err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", path, err)
	}
}

func currentDocsSiteAuditFixture() map[string]any {
	return map[string]any{
		"auditReportVersion": 2,
		"vulnerabilities": map[string]any{
			"next": map[string]any{
				"name":     "next",
				"severity": "moderate",
				"isDirect": true,
				"via":      []any{"postcss"},
				"effects":  []any{},
				"range":    "9.3.4-canary.0 - 16.3.0-canary.5",
				"nodes":    []any{"node_modules/next"},
				"fixAvailable": map[string]any{
					"name":          "next",
					"version":       "9.3.3",
					"isSemVerMajor": true,
				},
			},
			"postcss": map[string]any{
				"name":     "postcss",
				"severity": "moderate",
				"isDirect": false,
				"via": []any{
					map[string]any{
						"source":     1117015,
						"name":       "postcss",
						"dependency": "postcss",
						"title":      "PostCSS has XSS via Unescaped </style> in its CSS Stringify Output",
						"url":        "https://github.com/advisories/GHSA-qx2v-qp2m-jg93",
						"severity":   "moderate",
						"range":      "<8.5.10",
					},
				},
				"effects": []any{"next"},
				"range":   "<8.5.10",
				"nodes":   []any{"node_modules/next/node_modules/postcss"},
				"fixAvailable": map[string]any{
					"name":          "next",
					"version":       "9.3.3",
					"isSemVerMajor": true,
				},
			},
		},
		"metadata": map[string]any{
			"vulnerabilities": map[string]any{
				"info":     0,
				"low":      0,
				"moderate": 2,
				"high":     0,
				"critical": 0,
				"total":    2,
			},
		},
	}
}

func emptyDocsSiteAuditFixture() map[string]any {
	return map[string]any{
		"auditReportVersion": 2,
		"vulnerabilities":    map[string]any{},
		"metadata": map[string]any{
			"vulnerabilities": map[string]any{
				"info":     0,
				"low":      0,
				"moderate": 0,
				"high":     0,
				"critical": 0,
				"total":    0,
			},
		},
	}
}

func docsSiteLockfileFixture() map[string]any {
	return map[string]any{
		"name":            "wrkr-docs-site",
		"lockfileVersion": 3,
		"packages": map[string]any{
			"": map[string]any{
				"name":    "wrkr-docs-site",
				"version": "1.0.0",
			},
			"node_modules/next": map[string]any{
				"version": "16.2.6",
			},
			"node_modules/next/node_modules/postcss": map[string]any{
				"version": "8.4.31",
			},
		},
	}
}

func docsSiteExceptionFixture(opts fixtureRepoOptions) map[string]any {
	expiry := opts.ExceptionExpiry
	if expiry == "" {
		expiry = "2026-06-30"
	}
	currentVersion := opts.ExceptionCurrentVersion
	if currentVersion == "" {
		currentVersion = "16.2.6"
	}
	owner := opts.ExceptionOwner
	if owner == "" && !opts.ForceBlankOwner {
		owner = "docs-platform"
	}
	rationale := opts.ExceptionRationale
	if rationale == "" && !opts.ForceBlankRationale {
		rationale = "Latest stable Next.js still resolves to 16.2.6 and npm audit only offers an unsafe semver-major downgrade."
	}
	payload := map[string]any{
		"schema_id":      "wrkr.docs_site.audit_exceptions",
		"schema_version": "1.0.0",
	}
	if opts.NoExceptions {
		payload["exceptions"] = []any{}
		return payload
	}
	payload["exceptions"] = []any{
		map[string]any{
			"package":           "postcss",
			"advisory":          "GHSA-qx2v-qp2m-jg93",
			"severity":          "moderate",
			"affected_node":     "node_modules/next/node_modules/postcss",
			"direct_dependency": "next",
			"current_version":   currentVersion,
			"owner":             owner,
			"scope":             "docs-site production dependencies",
			"rationale":         rationale,
			"expires_on":        expiry,
			"upgrade_trigger":   "Remove after a stable Next.js release ships with nested postcss >= 8.5.10.",
		},
	}
	return payload
}
