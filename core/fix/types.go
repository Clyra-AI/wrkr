package fix

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/Clyra-AI/wrkr/core/model"
	"github.com/Clyra-AI/wrkr/core/risk"
)

const (
	ReasonUnsupportedFindingType = "unsupported_finding_type"
	ReasonMissingLocation        = "missing_location"
	ReasonAmbiguousPatchTarget   = "ambiguous_patch_target"
	ReasonMissingRuleTemplate    = "missing_rule_template"
)

// Plan is a deterministic remediation output for ranked findings.
type Plan struct {
	RequestedTop int           `json:"requested_top"`
	Fingerprint  string        `json:"fingerprint"`
	Remediations []Remediation `json:"remediations"`
	Skipped      []Skipped     `json:"skipped"`
}

// Remediation describes one deterministic patch preview and commit intent.
type Remediation struct {
	ID            string        `json:"id"`
	TemplateID    string        `json:"template_id"`
	Category      string        `json:"category"`
	RuleID        string        `json:"rule_id,omitempty"`
	Title         string        `json:"title"`
	Rationale     string        `json:"rationale"`
	CommitMessage string        `json:"commit_message"`
	PatchPreview  string        `json:"patch_preview"`
	Finding       model.Finding `json:"finding"`
}

// Skipped is emitted for non-fixable findings with explicit reason codes.
type Skipped struct {
	CanonicalKey string `json:"canonical_key"`
	FindingType  string `json:"finding_type"`
	RuleID       string `json:"rule_id,omitempty"`
	Location     string `json:"location,omitempty"`
	ReasonCode   string `json:"reason_code"`
	Message      string `json:"message"`
}

func canonicalFindingKey(f model.Finding) string {
	parts := []string{
		strings.TrimSpace(f.FindingType),
		strings.TrimSpace(f.RuleID),
		strings.TrimSpace(f.ToolType),
		strings.TrimSpace(f.Location),
		strings.TrimSpace(f.Repo),
		strings.TrimSpace(f.Org),
	}
	return strings.Join(parts, "|")
}

func planFingerprint(remediations []Remediation, skipped []Skipped) string {
	parts := make([]string, 0, len(remediations)+len(skipped))
	for _, item := range remediations {
		parts = append(parts, "fix:"+item.ID)
	}
	for _, item := range skipped {
		parts = append(parts, "skip:"+item.CanonicalKey+":"+item.ReasonCode)
	}
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}

func remediationID(candidate risk.ScoredFinding, templateID string) string {
	sum := sha256.Sum256([]byte(canonicalFindingKey(candidate.Finding) + "|" + templateID))
	return hex.EncodeToString(sum[:])
}
