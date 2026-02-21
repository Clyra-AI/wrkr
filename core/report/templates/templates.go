package templates

type Pack struct {
	HeadlineTitle  string
	TopRisksTitle  string
	ChangesTitle   string
	LifecycleTitle string
	ProofTitle     string
	ActionsTitle   string
}

var packs = map[string]Pack{
	"exec": {
		HeadlineTitle:  "Executive posture summary",
		TopRisksTitle:  "Top prioritized risks",
		ChangesTitle:   "What changed",
		LifecycleTitle: "Governance actions",
		ProofTitle:     "Proof verification",
		ActionsTitle:   "Next executive actions",
	},
	"operator": {
		HeadlineTitle:  "Operator posture summary",
		TopRisksTitle:  "Top prioritized risks",
		ChangesTitle:   "What changed since previous scan",
		LifecycleTitle: "Lifecycle approvals and reviews",
		ProofTitle:     "Proof verification footer",
		ActionsTitle:   "Next operator actions",
	},
	"audit": {
		HeadlineTitle:  "Audit posture summary",
		TopRisksTitle:  "Top prioritized risk findings",
		ChangesTitle:   "Deterministic change deltas",
		LifecycleTitle: "Lifecycle control actions",
		ProofTitle:     "Evidence and proof verification",
		ActionsTitle:   "Next audit actions",
	},
	"public": {
		HeadlineTitle:  "Public posture summary",
		TopRisksTitle:  "Top prioritized risks",
		ChangesTitle:   "What changed",
		LifecycleTitle: "Governance actions",
		ProofTitle:     "Proof verification",
		ActionsTitle:   "Next actions",
	},
}

func Resolve(name string) Pack {
	if pack, ok := packs[name]; ok {
		return pack
	}
	return packs["operator"]
}
