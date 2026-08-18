package compliance

var frameworkControlRuleMap = map[string]map[string][]string{
	"eu-ai-act": {
		"article-9":  {"WRKR-A001", "WRKR-A002", "WRKR-A005", "WRKR-A006", "WRKR-A009", "WRKR-A010"},
		"article-12": {"WRKR-A001", "WRKR-A003", "WRKR-A004", "WRKR-A008"},
		"article-14": {"WRKR-A001", "WRKR-A002", "WRKR-A007", "WRKR-A009", "WRKR-A010"},
	},
	"soc2": {
		"cc6": {"WRKR-A001", "WRKR-A002", "WRKR-A003", "WRKR-A005", "WRKR-A007", "WRKR-A009"},
		"cc7": {"WRKR-A004", "WRKR-A006", "WRKR-A007", "WRKR-A010"},
		"cc8": {"WRKR-A001", "WRKR-A002", "WRKR-A009", "WRKR-A010"},
	},
	"pci-dss": {
		"req-10": {"WRKR-A001", "WRKR-A003", "WRKR-A004", "WRKR-A006", "WRKR-A009", "WRKR-A010"},
	},
}

// frameworkControlCompatibilityAliases preserves the one-to-one SOC 2 control
// identities that Proof made more precise in v0.5.0. It is intentionally
// explicit: controls without an established predecessor must not inherit a
// mapping through prefix or fuzzy matching.
var frameworkControlCompatibilityAliases = map[string]map[string]string{
	"soc2": {
		"cc6.1": "cc6",
		"cc7.1": "cc7",
		"cc8.1": "cc8",
	},
}

func configuredControlRuleIDs(frameworkID, controlID string) []string {
	controls := frameworkControlRuleMap[frameworkID]
	if len(controls) == 0 {
		return nil
	}
	if ruleIDs := controls[controlID]; len(ruleIDs) > 0 {
		return append([]string(nil), ruleIDs...)
	}
	alias := frameworkControlCompatibilityAliases[frameworkID][controlID]
	if alias == "" {
		return nil
	}
	return append([]string(nil), controls[alias]...)
}
