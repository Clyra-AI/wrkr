package templates

type Pack struct {
	HeadlineTitle        string
	ExecutiveRollupTitle string
	TopRisksTitle        string
	ChangesTitle         string
	LifecycleTitle       string
	ProofTitle           string
	ActionsTitle         string
}

var packs = map[string]Pack{
	"exec": {
		HeadlineTitle:        "Executive posture summary",
		ExecutiveRollupTitle: "Executive Rollup",
		TopRisksTitle:        "Top prioritized risks",
		ChangesTitle:         "What changed",
		LifecycleTitle:       "Governance actions",
		ProofTitle:           "Proof verification",
		ActionsTitle:         "Next executive actions",
	},
	"operator": {
		HeadlineTitle:        "Operator posture summary",
		ExecutiveRollupTitle: "Executive Rollup",
		TopRisksTitle:        "Top prioritized risks",
		ChangesTitle:         "What changed since previous scan",
		LifecycleTitle:       "Lifecycle approvals and reviews",
		ProofTitle:           "Proof verification footer",
		ActionsTitle:         "Next operator actions",
	},
	"audit": {
		HeadlineTitle:        "Audit posture summary",
		ExecutiveRollupTitle: "Executive Rollup",
		TopRisksTitle:        "Top prioritized risk findings",
		ChangesTitle:         "Deterministic change deltas",
		LifecycleTitle:       "Lifecycle control actions",
		ProofTitle:           "Evidence and proof verification",
		ActionsTitle:         "Next audit actions",
	},
	"public": {
		HeadlineTitle:        "Public posture summary",
		ExecutiveRollupTitle: "Executive Rollup",
		TopRisksTitle:        "Top prioritized risks",
		ChangesTitle:         "What changed",
		LifecycleTitle:       "Governance actions",
		ProofTitle:           "Proof verification",
		ActionsTitle:         "Next actions",
	},
	"ciso": {
		HeadlineTitle:        "CISO control backlog summary",
		ExecutiveRollupTitle: "Executive Rollup",
		TopRisksTitle:        "Top governance control backlog items",
		ChangesTitle:         "Risk and approval movement",
		LifecycleTitle:       "Executive ownership and approval actions",
		ProofTitle:           "Evidence and proof verification",
		ActionsTitle:         "Next executive control actions",
	},
	"appsec": {
		HeadlineTitle:        "AppSec control backlog summary",
		ExecutiveRollupTitle: "Executive Rollup",
		TopRisksTitle:        "Top AppSec control paths",
		ChangesTitle:         "Control-path changes",
		LifecycleTitle:       "Approval and remediation workflow",
		ProofTitle:           "Evidence and proof verification",
		ActionsTitle:         "Next AppSec actions",
	},
	"platform": {
		HeadlineTitle:        "Platform control backlog summary",
		ExecutiveRollupTitle: "Executive Rollup",
		TopRisksTitle:        "Top platform-owned control paths",
		ChangesTitle:         "Platform posture changes",
		LifecycleTitle:       "Ownership and lifecycle queue",
		ProofTitle:           "Evidence and proof verification",
		ActionsTitle:         "Next platform actions",
	},
	"customer-draft": {
		HeadlineTitle:        "Customer draft posture summary",
		ExecutiveRollupTitle: "Executive Rollup",
		TopRisksTitle:        "Shareable control backlog highlights",
		ChangesTitle:         "Shareable changes",
		LifecycleTitle:       "Governance actions",
		ProofTitle:           "Proof verification",
		ActionsTitle:         "Next customer-facing actions",
	},
	"agent-action-bom": {
		HeadlineTitle:        "Agent Action BOM summary",
		ExecutiveRollupTitle: "Executive Rollup",
		TopRisksTitle:        "Top risky agent action BOM items",
		ChangesTitle:         "Control and evidence changes",
		LifecycleTitle:       "Ownership and approval actions",
		ProofTitle:           "Proof and runtime evidence",
		ActionsTitle:         "Next control actions",
	},
	"design-partner-summary": {
		HeadlineTitle:        "Design partner static action summary",
		ExecutiveRollupTitle: "Executive Rollup",
		TopRisksTitle:        "Top validated action paths",
		ChangesTitle:         "What changed since the previous scan",
		LifecycleTitle:       "Ownership and approval gaps",
		ProofTitle:           "Proof and evidence gaps",
		ActionsTitle:         "Recommended controls",
	},
}

func Resolve(name string) Pack {
	if pack, ok := packs[name]; ok {
		return pack
	}
	return packs["operator"]
}
