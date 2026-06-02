package enterprisepressure

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	VariantBaseline = "baseline"
	VariantCurrent  = "current"
	RepoCount       = 320
)

type externalControlEvidenceDocument struct {
	SchemaVersion string                          `json:"schema_version"`
	GeneratedAt   string                          `json:"generated_at"`
	Records       []externalControlEvidenceRecord `json:"records"`
}

type externalControlEvidenceRecord struct {
	RecordKind    string   `json:"record_kind"`
	SourceType    string   `json:"source_type"`
	Source        string   `json:"source"`
	Repo          string   `json:"repo"`
	Path          string   `json:"path"`
	ObservedAt    string   `json:"observed_at"`
	EvidenceClass string   `json:"evidence_class"`
	Status        string   `json:"status"`
	EvidenceRefs  []string `json:"evidence_refs,omitempty"`
}

func Materialize(root string, variant string) error {
	return MaterializeCount(root, variant, RepoCount)
}

func MaterializeCount(root string, variant string, repoCount int) error {
	root = strings.TrimSpace(root)
	if root == "" {
		return fmt.Errorf("root is required")
	}
	if repoCount <= 0 {
		return fmt.Errorf("repo count must be positive")
	}
	switch variant {
	case VariantBaseline, VariantCurrent:
	default:
		return fmt.Errorf("unsupported enterprise-pressure variant %q", variant)
	}

	for idx := 1; idx <= repoCount; idx++ {
		repoName := RepoName(idx)
		repoPath := filepath.Join(root, repoName)
		if err := os.MkdirAll(repoPath, 0o755); err != nil {
			return fmt.Errorf("mkdir repo %s: %w", repoName, err)
		}
		if err := writeBaselineRepo(repoPath, repoName, idx, repoCount); err != nil {
			return err
		}
	}
	if variant == VariantCurrent {
		if err := applyCurrentMutations(root, repoCount); err != nil {
			return err
		}
	}
	return nil
}

func RepoName(idx int) string {
	return fmt.Sprintf("enterprise-%03d", idx)
}

func writeBaselineRepo(repoPath, repoName string, idx, repoCount int) error {
	switch {
	case idx <= 120:
		if err := writeSimpleWorkflowRepo(repoPath, repoName, idx); err != nil {
			return err
		}
	case idx <= 140:
		if err := writeDeployAgentRepo(repoPath, repoName); err != nil {
			return err
		}
	case idx <= 150:
		if err := writeDependencyOnlyRepo(repoPath); err != nil {
			return err
		}
	case idx <= 160:
		if err := writeSourceOnlyRepo(repoPath, repoName); err != nil {
			return err
		}
	default:
		if err := writeFile(repoPath, "README.md", "# inert fixture\n"); err != nil {
			return err
		}
	}
	if idx == repoCount {
		if err := writeFile(repoPath, ".mcp.json", "{\n"); err != nil {
			return err
		}
	}
	return nil
}

func applyCurrentMutations(root string, repoCount int) error {
	if repoCount >= 1 {
		repo := filepath.Join(root, RepoName(1))
		if err := writeFile(repo, ".github/workflows/post-deploy.yml", workflowYAML("Post Deploy", true, true, false)); err != nil {
			return err
		}
	}
	if repoCount >= 2 {
		repo := filepath.Join(root, RepoName(2))
		if err := os.Remove(filepath.Join(repo, ".github", "workflows", "release.yml")); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove baseline workflow: %w", err)
		}
	}
	if repoCount >= 4 {
		repo := filepath.Join(root, RepoName(4))
		if err := writeApprovalSidecar(repo, RepoName(4), "evidence://public/change-calendar.yaml#resolved-gap"); err != nil {
			return err
		}
		if err := writeBranchProtectionSidecar(repo, RepoName(4)); err != nil {
			return err
		}
	}
	if repoCount >= 6 {
		repo := filepath.Join(root, RepoName(6))
		if err := writeFile(repo, ".github/workflows/release.yml", workflowYAML("Authority Drift", true, true, true)); err != nil {
			return err
		}
	}
	if repoCount >= 7 {
		repo := filepath.Join(root, RepoName(7))
		if err := writeTargetDeclaration(repo, RepoName(7), "developer_productivity", false); err != nil {
			return err
		}
	}
	if repoCount >= 8 {
		repo := filepath.Join(root, RepoName(8))
		if err := writeFile(repo, ".github/workflows/release.yml", contradictionWorkflowYAML("Late Contradiction")); err != nil {
			return err
		}
		if err := writeTargetDeclaration(repo, RepoName(8), "test_demo_sandbox", true); err != nil {
			return err
		}
	}
	if repoCount >= 12 {
		repo := filepath.Join(root, RepoName(12))
		if err := os.Remove(filepath.Join(repo, ".wrkr", "provenance", "external-control-evidence.json")); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove branch protection sidecar: %w", err)
		}
	}
	if repoCount >= 143 {
		repo := filepath.Join(root, RepoName(143))
		if err := writeFile(repo, ".github/workflows/release.yml", workflowYAML("Dependency Escalation", true, true, false)); err != nil {
			return err
		}
	}
	return nil
}

func writeSimpleWorkflowRepo(repoPath, repoName string, idx int) error {
	if err := writeFile(repoPath, ".github/workflows/release.yml", workflowYAML(fmt.Sprintf("Enterprise Release %03d", idx), idx%5 == 0, true, false)); err != nil {
		return err
	}
	if err := writeFile(repoPath, "AGENTS.md", "# Enterprise Agent\n\nCodex may review release automation in this repository.\n"); err != nil {
		return err
	}
	if err := writeFile(repoPath, ".codex/config.toml", "model = \"gpt-5\"\n"); err != nil {
		return err
	}
	if idx%4 == 0 {
		if err := writeFile(repoPath, "CODEOWNERS", fmt.Sprintf(".github/workflows/release.yml @acme/platform-%03d\n", idx)); err != nil {
			return err
		}
	}
	if idx%10 == 0 {
		if err := writeApprovalSidecar(repoPath, repoName, fmt.Sprintf("evidence://public/change-calendar.yaml#%s", repoName)); err != nil {
			return err
		}
	}
	if idx%12 == 0 {
		if err := writeBranchProtectionSidecar(repoPath, repoName); err != nil {
			return err
		}
	}
	return nil
}

func writeDeployAgentRepo(repoPath, repoName string) error {
	if err := writeFile(repoPath, ".github/workflows/release.yml", deployAgentWorkflowYAML("Deploy Agent")); err != nil {
		return err
	}
	if err := writeFile(repoPath, "AGENTS.md", "# Deploy Agent\n\nCodex is allowed to prepare release automation for this repo.\n"); err != nil {
		return err
	}
	if err := writeFile(repoPath, ".codex/config.toml", "model = \"gpt-5\"\n"); err != nil {
		return err
	}
	return writeFile(repoPath, ".wrkr/provenance/source-metadata.json", fmt.Sprintf(`{
  "source": "source_metadata",
  "pr_number": 108,
  "provider_url": "https://github.example.com/acme/%s/pull/108",
  "commit_sha": "deadbeef0108",
  "author": "release-bot",
  "timestamp": "2026-05-31T12:00:00Z",
  "changed_files": [
    ".github/workflows/release.yml",
    "AGENTS.md",
    ".codex/config.toml"
  ]
}
`, repoName))
}

func writeDependencyOnlyRepo(repoPath string) error {
	return writeFile(repoPath, "package.json", `{
  "name": "dependency-only-pressure",
  "private": true,
  "dependencies": {
    "crewai": "^0.8.0",
    "langchain": "^1.0.0"
  }
}
`)
}

func writeSourceOnlyRepo(repoPath, repoName string) error {
	if err := writeFile(repoPath, "agents/crew.py", "from crewai import Agent\n\n\ndef build_agent():\n    return Agent(role=\"triage\", goal=\"summarize posture\")\n"); err != nil {
		return err
	}
	return writeFile(repoPath, ".wrkr/provenance/source-metadata.json", fmt.Sprintf(`{
  "source": "source_metadata",
  "pr_number": 42,
  "provider_url": "https://github.example.com/acme/%s/pull/42",
  "commit_sha": "deadbeef0042",
  "author": "triage-bot",
  "timestamp": "2026-01-15T12:00:00Z",
  "changed_files": [
    "agents/crew.py"
  ]
}
`, repoName))
}

func writeApprovalSidecar(repoPath, repoName, evidenceRef string) error {
	return appendExternalControlEvidence(repoPath, "2026-05-31T16:30:00Z", externalControlEvidenceRecord{
		RecordKind:    "external_control",
		SourceType:    "ticket_export",
		Source:        "local_change_calendar",
		Repo:          repoName,
		Path:          ".github/workflows/release.yml",
		ObservedAt:    "2026-05-31T16:00:00Z",
		EvidenceClass: "deployment_approval",
		Status:        "matched",
		EvidenceRefs:  []string{evidenceRef},
	})
}

func writeBranchProtectionSidecar(repoPath, repoName string) error {
	return appendExternalControlEvidence(repoPath, "2026-05-31T16:40:00Z", externalControlEvidenceRecord{
		RecordKind:    "external_control",
		SourceType:    "provider_export",
		Source:        "github_branch_protection_export",
		Repo:          repoName,
		Path:          ".github/workflows/release.yml",
		ObservedAt:    "2026-05-31T16:10:00Z",
		EvidenceClass: "branch_protection",
		Status:        "matched",
		EvidenceRefs:  []string{fmt.Sprintf("evidence://public/provider-export.json#%s", repoName)},
	})
}

func writeTargetDeclaration(repoPath, repoName, targetClass string, nonProduction bool) error {
	return writeFile(repoPath, "wrkr-control-declarations.yaml", fmt.Sprintf(`schema_version: v1
issuer: demo-platform
targets:
  - repo: %s
    path: .github/workflows/release.yml
    target_class: %s
    non_production: %t
    observed_at: 2026-05-31T15:00:00Z
    evidence_refs:
      - evidence://public/targets.yaml#%s
`, repoName, targetClass, nonProduction, repoName))
}

func workflowYAML(name string, includeSecret bool, production bool, includeIDToken bool) string {
	permissions := "      contents: write\n      pull-requests: write\n"
	if includeIDToken {
		permissions += "      id-token: write\n"
	}
	environment := ""
	if production {
		environment = "    environment: production\n"
	}
	env := ""
	if includeSecret {
		env = "    env:\n      PROD_API_KEY: ${{ secrets.PROD_API_KEY }}\n"
	}
	return fmt.Sprintf(`name: %s
on:
  workflow_dispatch:
jobs:
  release:
%s    permissions:
%s%s    steps:
      - run: ./scripts/release.sh
`, name, environment, permissions, env)
}

func contradictionWorkflowYAML(name string) string {
	return fmt.Sprintf(`name: %s
on:
  workflow_dispatch:
jobs:
  release:
    permissions:
      contents: write
    env:
      PROD_API_KEY: ${{ secrets.PROD_API_KEY }}
    steps:
      - run: ./scripts/deploy.sh
`, name)
}

func deployAgentWorkflowYAML(name string) string {
	return fmt.Sprintf(`name: %s
on:
  workflow_dispatch:
jobs:
  release:
    permissions:
      contents: write
      pull-requests: write
      id-token: write
    environment: production
    steps:
      - run: codex exec release-plan
`, name)
}

func writeFile(root, rel, contents string) error {
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", rel, err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		return fmt.Errorf("write %s: %w", rel, err)
	}
	return nil
}

func appendExternalControlEvidence(repoPath, generatedAt string, record externalControlEvidenceRecord) error {
	rel := ".wrkr/provenance/external-control-evidence.json"
	path := filepath.Join(repoPath, filepath.FromSlash(rel))

	doc := externalControlEvidenceDocument{SchemaVersion: "v1"}
	payload, err := os.ReadFile(path) // #nosec G304 -- deterministic fixture-local sidecar path under the materialized repo.
	switch {
	case err == nil:
		if err := json.Unmarshal(payload, &doc); err != nil {
			return fmt.Errorf("parse %s: %w", rel, err)
		}
	case os.IsNotExist(err):
	default:
		return fmt.Errorf("read %s: %w", rel, err)
	}

	if strings.TrimSpace(doc.SchemaVersion) == "" {
		doc.SchemaVersion = "v1"
	}
	doc.GeneratedAt = generatedAt
	doc.Records = append(doc.Records, record)

	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", rel, err)
	}
	return writeFile(repoPath, rel, string(encoded)+"\n")
}
