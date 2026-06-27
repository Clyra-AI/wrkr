package report

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/risk"
)

var unsupportedBuyerArtifactPhrases = []string{
	"approval missing",
	"owner missing",
	"proof missing",
	"no approval",
	"uncontrolled",
	"not governed",
}

var buyerPrimaryInternalTokens = []string{
	"approval_evidence_unknown",
	"proof_evidence_unknown",
	"control_first",
	"prod_or_customer_impacting",
	"production_impacting",
	"report_only",
	"recommended_control",
	"not_collected",
}

const buyerPrimaryMaxLineLength = 520

type BuyerArtifactQAInput struct {
	ActionPathTypes []string
	PathEvidence    []BuyerArtifactPathEvidence
	Texts           map[string]string
}

type BuyerArtifactPathEvidence struct {
	ActionPathType string
	Repo           string
	Location       string
}

func ValidateBuyerArtifactTexts(input BuyerArtifactQAInput) error {
	if len(input.Texts) == 0 {
		return nil
	}

	issues := make([]string, 0)
	artifactNames := make([]string, 0, len(input.Texts))
	for name := range input.Texts {
		artifactNames = append(artifactNames, name)
	}
	sort.Strings(artifactNames)

	for _, name := range artifactNames {
		text := strings.TrimSpace(input.Texts[name])
		if text == "" {
			continue
		}
		lower := strings.ToLower(text)
		for _, phrase := range unsupportedBuyerArtifactPhrases {
			if strings.Contains(lower, phrase) {
				issues = append(issues, fmt.Sprintf("%s contains unsupported buyer phrase %q", name, phrase))
			}
		}
		issues = append(issues, validateBuyerPrimaryText(name, text)...)
		if strings.Contains(lower, "agent framework") {
			if !hasAgentFrameworkEvidence(input) {
				issues = append(issues, fmt.Sprintf("%s contains agent-framework wording without action_path_type=%q evidence", name, risk.ActionPathTypeAgentFramework))
				continue
			}
			if !agentFrameworkWordingBackedByPath(text, input.PathEvidence) {
				issues = append(issues, fmt.Sprintf("%s contains agent-framework wording that is not backed by the specific path evidence", name))
			}
		}
	}

	if len(issues) == 0 {
		return nil
	}
	slices.Sort(issues)
	issues = slices.Compact(issues)
	return errors.New(strings.Join(issues, "; "))
}

func validateBuyerPrimaryText(name string, text string) []string {
	primary := buyerPrimarySection(text)
	if primary == "" {
		return nil
	}
	issues := make([]string, 0)
	lower := strings.ToLower(primary)
	for _, token := range buyerPrimaryInternalTokens {
		if strings.Contains(lower, token) {
			issues = append(issues, fmt.Sprintf("%s primary lead contains internal token %q", name, token))
		}
	}
	for idx, line := range strings.Split(primary, "\n") {
		if len(line) > buyerPrimaryMaxLineLength {
			issues = append(issues, fmt.Sprintf("%s primary lead line %d exceeds %d characters", name, idx+1, buyerPrimaryMaxLineLength))
		}
	}
	if strings.Count(lower, "approval evidence not found") > 1 {
		issues = append(issues, fmt.Sprintf("%s primary lead repeats raw approval evidence gap wording", name))
	}
	if strings.Count(lower, "path-specific proof not found") > 1 {
		issues = append(issues, fmt.Sprintf("%s primary lead repeats raw proof evidence gap wording", name))
	}
	if weakBlockedCredentialLead(lower) {
		issues = append(issues, fmt.Sprintf("%s primary lead starts blocked standing-credential guidance with accept-risk before reduction", name))
	}
	return issues
}

func buyerPrimarySection(text string) string {
	normalized := strings.ReplaceAll(text, "\r\n", "\n")
	start := strings.Index(normalized, "## What To Look At First")
	if start < 0 {
		return ""
	}
	end := strings.Index(normalized[start:], "## Report Context Appendix")
	if end < 0 {
		return strings.TrimSpace(normalized[start:])
	}
	return strings.TrimSpace(normalized[start : start+end])
}

func weakBlockedCredentialLead(lower string) bool {
	if !strings.Contains(lower, "blocked") {
		return false
	}
	if !strings.Contains(lower, "standing credential") && !strings.Contains(lower, "standing") {
		return false
	}
	acceptIdx := strings.Index(lower, "accept risk")
	if acceptIdx < 0 {
		return false
	}
	strongIdx := firstStrongCredentialVerbIndex(lower)
	return strongIdx < 0 || acceptIdx < strongIdx
}

func firstStrongCredentialVerbIndex(lower string) int {
	strongTerms := []string{"replace standing credential", "reduce standing credential", "revoke", "rotate", "jit", "brokered"}
	best := -1
	for _, term := range strongTerms {
		idx := strings.Index(lower, term)
		if idx < 0 {
			continue
		}
		if best < 0 || idx < best {
			best = idx
		}
	}
	return best
}

func hasActionPathType(actionPathTypes []string, want string) bool {
	for _, actionPathType := range actionPathTypes {
		if strings.TrimSpace(actionPathType) == want {
			return true
		}
	}
	return false
}

func hasAgentFrameworkEvidence(input BuyerArtifactQAInput) bool {
	if hasActionPathType(input.ActionPathTypes, risk.ActionPathTypeAgentFramework) {
		return true
	}
	for _, evidence := range input.PathEvidence {
		if strings.TrimSpace(evidence.ActionPathType) == risk.ActionPathTypeAgentFramework {
			return true
		}
	}
	return false
}

func agentFrameworkWordingBackedByPath(text string, pathEvidence []BuyerArtifactPathEvidence) bool {
	if len(pathEvidence) == 0 {
		return false
	}

	blocks := splitArtifactBlocks(text)
	for _, block := range blocks {
		blockLower := strings.ToLower(block)
		if !strings.Contains(blockLower, "agent framework") {
			continue
		}
		if !blockHasAgentFrameworkEvidence(blockLower, pathEvidence) {
			return false
		}
	}
	return true
}

func splitArtifactBlocks(text string) []string {
	rawBlocks := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n\n")
	blocks := make([]string, 0, len(rawBlocks))
	for _, block := range rawBlocks {
		trimmed := strings.TrimSpace(block)
		if trimmed == "" {
			continue
		}
		blocks = append(blocks, trimmed)
	}
	return blocks
}

func blockHasAgentFrameworkEvidence(block string, pathEvidence []BuyerArtifactPathEvidence) bool {
	for _, evidence := range pathEvidence {
		if strings.TrimSpace(evidence.ActionPathType) != risk.ActionPathTypeAgentFramework {
			continue
		}
		repo := strings.ToLower(strings.TrimSpace(evidence.Repo))
		location := strings.ToLower(strings.TrimSpace(evidence.Location))
		switch {
		case repo != "" && location != "":
			if strings.Contains(block, repo) && strings.Contains(block, location) {
				return true
			}
		case repo != "":
			if strings.Contains(block, repo) {
				return true
			}
		case location != "":
			if strings.Contains(block, location) {
				return true
			}
		}
	}
	return false
}
