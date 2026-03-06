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
