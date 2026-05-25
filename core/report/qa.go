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

type BuyerArtifactQAInput struct {
	ActionPathTypes []string
	Texts           map[string]string
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
		if strings.Contains(lower, "agent framework") && !hasActionPathType(input.ActionPathTypes, risk.ActionPathTypeAgentFramework) {
			issues = append(issues, fmt.Sprintf("%s contains agent-framework wording without action_path_type=%q evidence", name, risk.ActionPathTypeAgentFramework))
		}
	}

	if len(issues) == 0 {
		return nil
	}
	slices.Sort(issues)
	issues = slices.Compact(issues)
	return errors.New(strings.Join(issues, "; "))
}

func hasActionPathType(actionPathTypes []string, want string) bool {
	for _, actionPathType := range actionPathTypes {
		if strings.TrimSpace(actionPathType) == want {
			return true
		}
	}
	return false
}
