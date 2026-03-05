package policy

import (
	"fmt"
	"regexp"
	"strings"
)

var ruleIDPattern = regexp.MustCompile(`^WRKR-(A)?[0-9]{3}$`)

// NormalizeRuleID trims and uppercases a rule ID and validates namespace shape.
func NormalizeRuleID(id string) (string, error) {
	normalized := strings.ToUpper(strings.TrimSpace(id))
	if !ruleIDPattern.MatchString(normalized) {
		return "", fmt.Errorf("invalid rule id %q: expected WRKR-### or WRKR-A###", id)
	}
	return normalized, nil
}

// RuleIDAliases returns deterministic namespace aliases for a rule ID.
func RuleIDAliases(id string) []string {
	normalized, err := NormalizeRuleID(id)
	if err != nil {
		trimmed := strings.ToUpper(strings.TrimSpace(id))
		if trimmed == "" {
			return nil
		}
		return []string{trimmed}
	}

	suffix := strings.TrimPrefix(normalized, "WRKR-")
	if strings.HasPrefix(suffix, "A") {
		return []string{
			normalized,
			"WRKR-" + strings.TrimPrefix(suffix, "A"),
		}
	}
	return []string{
		normalized,
		"WRKR-A" + suffix,
	}
}
