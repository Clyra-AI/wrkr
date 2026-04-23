package cli

import (
	"fmt"
	"sort"
)

type nextStep struct {
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Command     string   `json:"command,omitempty"`
	Artifacts   []string `json:"artifacts,omitempty"`
}

func missingTargetNextSteps() []nextStep {
	return []nextStep{
		{
			ID:          "hosted_org_setup",
			Description: "Initialize a hosted org target when GitHub access is ready.",
			Command:     "wrkr init --non-interactive --org acme --github-api https://api.github.com --json",
		},
		{
			ID:          "evaluator_safe_fallback",
			Description: "Use the evaluator-safe scenario fallback when hosted setup is not ready yet.",
			Command:     "wrkr scan --path ./scenarios/wrkr/scan-mixed-org/repos --json",
		},
		{
			ID:          "local_machine_hygiene",
			Description: "Inspect the current machine for local AI tool and MCP posture.",
			Command:     "wrkr scan --my-setup --json",
		},
	}
}

func reportNextSteps(statePath string, artifacts reportArtifactResult) []nextStep {
	return []nextStep{
		{
			ID:          "review_report_artifacts",
			Description: "Review the generated report artifact fields before external handoff.",
			Artifacts:   reportArtifactReferences(artifacts),
		},
		{
			ID:          "generate_evidence_bundle",
			Description: "Generate a portable evidence bundle from the same saved scan state.",
			Command:     fmt.Sprintf("wrkr evidence --frameworks eu-ai-act,soc2,pci-dss --state %s --output ./wrkr-evidence --json", statePath),
		},
		{
			ID:          "verify_proof_chain",
			Description: "Verify the proof chain before sharing report or evidence artifacts externally.",
			Command:     fmt.Sprintf("wrkr verify --chain --state %s --json", statePath),
		},
	}
}

func evidenceNextSteps(statePath, outputDir, manifestPath string, reportArtifacts []string) []nextStep {
	bundleArtifacts := evidenceArtifactReferences(outputDir, manifestPath, reportArtifacts)
	return []nextStep{
		{
			ID:          "review_evidence_bundle",
			Description: "Review the generated evidence and report artifact fields before handoff.",
			Artifacts:   bundleArtifacts,
		},
		{
			ID:          "verify_proof_chain",
			Description: "Verify the proof chain before sharing evidence externally.",
			Command:     fmt.Sprintf("wrkr verify --chain --state %s --json", statePath),
		},
		{
			ID:          "render_audit_report",
			Description: "Render an audit-facing report packet from the same saved scan state.",
			Command:     fmt.Sprintf("wrkr report --state %s --template audit --md --md-path ./wrkr-audit-summary.md --json", statePath),
		},
	}
}

func reportArtifactReferences(artifacts reportArtifactResult) []string {
	refs := []string{}
	if artifacts.MarkdownPath != "" {
		refs = append(refs, "artifact_paths.markdown")
	}
	if artifacts.PDFPath != "" {
		refs = append(refs, "artifact_paths.pdf")
	}
	if artifacts.EvidenceJSONPath != "" {
		refs = append(refs, "artifact_paths.evidence_json")
	}
	if artifacts.BacklogCSVPath != "" {
		refs = append(refs, "artifact_paths.backlog_csv")
	}
	return uniqueSortedStrings(refs)
}

func evidenceArtifactReferences(outputDir, manifestPath string, reportArtifacts []string) []string {
	refs := []string{}
	if outputDir != "" {
		refs = append(refs, "output_dir")
	}
	if manifestPath != "" {
		refs = append(refs, "manifest_path")
	}
	if len(reportArtifacts) > 0 {
		refs = append(refs, "report_artifacts")
	}
	return uniqueSortedStrings(refs)
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}
