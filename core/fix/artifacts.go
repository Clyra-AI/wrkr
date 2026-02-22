package fix

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

const remediationArtifactsRoot = ".wrkr/remediations"

type PRArtifact struct {
	Path          string
	Content       []byte
	CommitMessage string
}

// BuildPRArtifacts renders deterministic repository files that document and apply
// remediation intent so --open-pr produces code changes instead of metadata-only PRs.
func BuildPRArtifacts(plan Plan) ([]PRArtifact, error) {
	root := filepath.Join(remediationArtifactsRoot, strings.TrimSpace(plan.Fingerprint))
	artifacts := make([]PRArtifact, 0, len(plan.Remediations)+1)

	planPayload := map[string]any{
		"fingerprint":    strings.TrimSpace(plan.Fingerprint),
		"requested_top":  plan.RequestedTop,
		"remediations":   plan.Remediations,
		"non_fixable":    plan.Skipped,
		"artifact_style": "deterministic_patch_preview",
	}
	encodedPlan, err := json.MarshalIndent(planPayload, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal remediation artifact plan: %w", err)
	}
	encodedPlan = append(encodedPlan, '\n')
	artifacts = append(artifacts, PRArtifact{
		Path:          filepath.Join(root, "plan.json"),
		Content:       encodedPlan,
		CommitMessage: fmt.Sprintf("chore(remediation): update plan %s", shortFingerprint(plan.Fingerprint)),
	})

	for idx, item := range plan.Remediations {
		path := filepath.Join(root, fmt.Sprintf("%02d-%s-%s.patch", idx+1, strings.ToLower(strings.TrimSpace(item.TemplateID)), shortRemediationID(item.ID)))
		content := remediationPatchContent(item)
		artifacts = append(artifacts, PRArtifact{
			Path:          path,
			Content:       []byte(content),
			CommitMessage: item.CommitMessage,
		})
	}

	return artifacts, nil
}

func remediationPatchContent(item Remediation) string {
	lines := []string{
		"# Wrkr Remediation Patch Preview",
		"",
		"- Remediation ID: `" + strings.TrimSpace(item.ID) + "`",
		"- Template: `" + strings.TrimSpace(item.TemplateID) + "`",
		"- Category: `" + strings.TrimSpace(item.Category) + "`",
		"- Target: `" + strings.TrimSpace(item.Finding.Location) + "`",
		"- Rule ID: `" + strings.TrimSpace(item.RuleID) + "`",
		"",
		"## Rationale",
		"",
		strings.TrimSpace(item.Rationale),
		"",
		"## Patch Preview",
		"",
		"```diff",
		strings.TrimSpace(item.PatchPreview),
		"```",
		"",
	}
	return strings.Join(lines, "\n")
}

func shortFingerprint(fingerprint string) string {
	trimmed := strings.TrimSpace(fingerprint)
	if len(trimmed) <= 12 {
		return trimmed
	}
	return trimmed[:12]
}

func shortRemediationID(id string) string {
	trimmed := strings.TrimSpace(id)
	if len(trimmed) <= 12 {
		return trimmed
	}
	return trimmed[:12]
}
